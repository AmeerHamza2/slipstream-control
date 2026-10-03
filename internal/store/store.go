// Package store is the Postgres persistence layer (database/sql + lib/pq).
package store

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/netip"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/lib/pq"

	"github.com/ameerhamza2/slipstream-control/internal/ipam"
	"github.com/ameerhamza2/slipstream-control/migrations"
)

var (
	ErrNotFound       = errors.New("store: not found")
	ErrEmailTaken     = errors.New("store: email already registered")
	ErrDeviceKeyTaken = errors.New("store: wireguard public key already registered")
	ErrDeviceLimit    = errors.New("store: device limit reached")
	ErrServerName     = errors.New("store: server name already exists")
	ErrTokenInvalid   = errors.New("store: refresh token invalid or expired")
	ErrTokenReused    = errors.New("store: refresh token reuse detected")
	ErrPoolExhausted  = errors.New("store: tunnel address pool exhausted")
	// ErrAllocContention means every allocation attempt lost a race to a
	// concurrent allocator; the caller should retry.
	ErrAllocContention = errors.New("store: tunnel address allocation contention")
)

// Store wraps a *sql.DB.
type Store struct {
	db     *sql.DB
	tunnel ipam.Range
}

// Pool sizes the connection pool. Zero fields keep DefaultPool's value.
type Pool struct {
	MaxOpen     int
	MaxIdle     int
	MaxLifetime time.Duration
	MaxIdleTime time.Duration
}

// DefaultPool suits one replica of a small deployment; production sets the
// DB_* environment variables (see docs/SCALABILITY.md).
var DefaultPool = Pool{MaxOpen: 20, MaxIdle: 20, MaxLifetime: 30 * time.Minute, MaxIdleTime: 5 * time.Minute}

// Open connects to Postgres with DefaultPool.
func Open(ctx context.Context, dsn string) (*Store, error) { return OpenPool(ctx, dsn, DefaultPool) }

// OpenPool connects to Postgres and configures the pool.
func OpenPool(ctx context.Context, dsn string, p Pool) (*Store, error) {
	if p.MaxOpen <= 0 {
		p.MaxOpen = DefaultPool.MaxOpen
	}
	if p.MaxIdle <= 0 || p.MaxIdle > p.MaxOpen {
		p.MaxIdle = p.MaxOpen
	}
	if p.MaxLifetime <= 0 {
		p.MaxLifetime = DefaultPool.MaxLifetime
	}
	if p.MaxIdleTime <= 0 {
		p.MaxIdleTime = DefaultPool.MaxIdleTime
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(p.MaxOpen)
	db.SetMaxIdleConns(p.MaxIdle)
	db.SetConnMaxIdleTime(p.MaxIdleTime)
	// A bounded lifetime lets connections rebalance after a failover or a
	// PgBouncer/replica change instead of pinning to the old backend forever.
	db.SetConnMaxLifetime(p.MaxLifetime)
	pctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := db.PingContext(pctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("store: ping: %w", err)
	}
	return New(db), nil
}

// New wraps an existing *sql.DB.
func New(db *sql.DB) *Store { return &Store{db: db, tunnel: ipam.Default} }

// SetTunnelRange restricts address allocation to [first, last] (tests use a
// tiny range to exercise exhaustion; it could also carve the pool by region).
func (s *Store) SetTunnelRange(first, last netip.Addr) error {
	r, err := ipam.NewRange(first, last)
	if err != nil {
		return err
	}
	s.tunnel = r
	return nil
}

// IsUnavailable reports whether err means the database could not be reached
// or could not serve the request right now (connection refused or dropped,
// timeout, server shutting down or out of connections). Callers answer such
// errors with 503 + Retry-After rather than a 500: the request was fine and
// a retry, possibly on another replica, can succeed.
func IsUnavailable(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, driver.ErrBadConn) || errors.Is(err, sql.ErrConnDone) ||
		errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) || errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.ECONNRESET) {
		return true
	}
	var pe *pq.Error
	if errors.As(err, &pe) {
		switch pe.Code.Class() {
		case "08", // connection exception
			"53", // insufficient resources (too many connections, out of memory)
			"57": // operator intervention: admin shutdown, cannot connect now, query canceled (statement_timeout)
			return true
		}
		return false
	}
	var ne net.Error
	return errors.As(err, &ne)
}

// DB exposes the handle (tests, readiness).
func (s *Store) DB() *sql.DB { return s.db }

// Close closes the pool.
func (s *Store) Close() error { return s.db.Close() }

// Ping checks connectivity.
func (s *Store) Ping(ctx context.Context) error { return s.db.PingContext(ctx) }

// migrationLockKey is an arbitrary constant for pg_advisory_xact_lock.
const migrationLockKey int64 = 0x5_11F_57EA

// Migrate applies pending embedded migrations. Everything runs in a single
// transaction holding a transaction-scoped advisory lock, so concurrent
// replicas starting at once serialise, and a failed migration leaves the
// schema untouched (Postgres DDL is transactional).
func (s *Store) Migrate(ctx context.Context) (applied []string, err error) {
	names, err := fs.Glob(migrations.FS, "*.sql")
	if err != nil {
		return nil, err
	}
	sort.Strings(names)
	err = s.inTx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1)`, migrationLockKey); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
			version text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())`); err != nil {
			return err
		}
		done := map[string]bool{}
		rows, err := tx.QueryContext(ctx, `SELECT version FROM schema_migrations`)
		if err != nil {
			return err
		}
		for rows.Next() {
			var v string
			if err := rows.Scan(&v); err != nil {
				rows.Close()
				return err
			}
			done[v] = true
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		for _, name := range names {
			version := strings.TrimSuffix(name, ".sql")
			if done[version] {
				continue
			}
			body, err := migrations.FS.ReadFile(name)
			if err != nil {
				return err
			}
			// No bind args: lib/pq uses the simple protocol, which allows
			// multiple statements per Exec.
			if _, err := tx.ExecContext(ctx, string(body)); err != nil {
				return fmt.Errorf("migration %s: %w", name, err)
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations (version) VALUES ($1)`, version); err != nil {
				return err
			}
			applied = append(applied, version)
		}
		return nil
	})
	return applied, err
}

func (s *Store) inTx(ctx context.Context, fn func(*sql.Tx) error) (err error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() {
		if p := recover(); p != nil {
			_ = tx.Rollback()
			panic(p)
		}
		if err != nil {
			_ = tx.Rollback()
		}
	}()
	if err = fn(tx); err != nil {
		return err
	}
	return tx.Commit()
}

// uniqueViolation returns the constraint name if err is a unique violation.
func uniqueViolation(err error) (string, bool) {
	var pe *pq.Error
	if errors.As(err, &pe) && pe.Code == "23505" {
		return pe.Constraint, true
	}
	return "", false
}

func nullTime(t sql.NullTime) *time.Time {
	if !t.Valid {
		return nil
	}
	v := t.Time.UTC()
	return &v
}

func nullFloat(f sql.NullFloat64) *float64 {
	if !f.Valid {
		return nil
	}
	v := f.Float64
	return &v
}
