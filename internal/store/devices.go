package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	mrand "math/rand/v2"
	"net/netip"
	"sort"
	"time"

	"github.com/lib/pq"
)

// Device is a registered WireGuard client.
type Device struct {
	ID          string
	UserID      string
	Name        string
	Platform    string
	WGPublicKey string
	TunnelIP    netip.Addr
	CreatedAt   time.Time
}

const maxAllocAttempts = 16

// CreateDevice registers a device and allocates its tunnel address.
//
// The user row is locked (FOR NO KEY UPDATE) so concurrent requests cannot both pass
// the device-limit check. Address allocation relies on UNIQUE(tunnel_ip): we
// insert a candidate, and if another transaction took it, roll back to a
// savepoint and retry with a fresh candidate (see nextCandidate). It returns
// ErrPoolExhausted only when an exhaustive gap search found no free address,
// and ErrAllocContention when every attempt lost a race (retryable).
func (s *Store) CreateDevice(ctx context.Context, d Device, limit int) (Device, error) {
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		var one int
		// NO KEY UPDATE still serialises concurrent registrations for this
		// user, without blocking FK inserts that reference the user (login
		// creating a refresh token, a billing event) the way FOR UPDATE does.
		if err := tx.QueryRowContext(ctx, `SELECT 1 FROM users WHERE id = $1 FOR NO KEY UPDATE`, d.UserID).Scan(&one); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrNotFound
			}
			return err
		}
		var n int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM devices WHERE user_id = $1`, d.UserID).Scan(&n); err != nil {
			return err
		}
		if n >= limit {
			return ErrDeviceLimit
		}
		for attempt := 0; attempt < maxAllocAttempts; attempt++ {
			cand, err := s.nextCandidate(ctx, tx, attempt)
			if err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `SAVEPOINT alloc`); err != nil {
				return err
			}
			err = tx.QueryRowContext(ctx, `INSERT INTO devices (id, user_id, name, platform, wg_public_key, tunnel_ip)
				VALUES ($1, $2, $3, $4, $5, $6) RETURNING created_at`,
				d.ID, d.UserID, d.Name, d.Platform, d.WGPublicKey, cand.String()).Scan(&d.CreatedAt)
			if err == nil {
				d.TunnelIP = cand
				return nil
			}
			c, uv := uniqueViolation(err)
			if !uv {
				return err
			}
			if _, rerr := tx.ExecContext(ctx, `ROLLBACK TO SAVEPOINT alloc`); rerr != nil {
				return rerr
			}
			if c == "devices_wg_public_key_key" {
				return ErrDeviceKeyTaken
			}
			// Address collision: a concurrent allocator won. Loop and re-read.
		}
		return ErrAllocContention
	})
	return d, err
}

// nextCandidate proposes an address in s.tunnel.
//
//   - Early attempts use max(tunnel_ip)+1 (an Index Only Scan Backward on
//     devices_tunnel_ip_key: O(log n)). It is re-read on every attempt: under
//     READ COMMITTED each statement sees the row committed by the
//     transaction that beat us, so the retry moves just past the winner and
//     the pool stays dense. Retries add a small random skip so a herd of
//     concurrent allocators that all read the same maximum spreads out
//     instead of colliding on one address after another.
//   - When the cursor has reached the end of the range (or after several
//     collisions) addresses freed by deleted devices are reused: a gap search
//     from a random point walks devices_tunnel_ip_key until the first
//     address whose successor is free, wrapping around once. Its cost is the
//     length of the occupied run it lands in (expected 1/free-fraction), so
//     it stays cheap until the pool is nearly full, and it is exact: it only
//     reports exhaustion when no address in the range is free.
func (s *Store) nextCandidate(ctx context.Context, tx *sql.Tx, attempt int) (netip.Addr, error) {
	r := s.tunnel
	if attempt < maxAllocAttempts/4 {
		var highest sql.NullString
		if err := tx.QueryRowContext(ctx, `SELECT host(max(tunnel_ip)) FROM devices WHERE tunnel_ip BETWEEN $1::inet AND $2::inet`,
			r.First().String(), r.Last().String()).Scan(&highest); err != nil {
			return netip.Addr{}, err
		}
		var h netip.Addr
		if highest.Valid {
			var err error
			if h, err = netip.ParseAddr(highest.String); err != nil {
				return netip.Addr{}, fmt.Errorf("store: bad tunnel ip %q: %w", highest.String, err)
			}
		}
		var skip uint32
		if attempt > 0 {
			skip = uint32(mrand.IntN(4 * attempt))
		}
		if a, ok := r.Next(h, highest.Valid, skip); ok {
			return a, nil
		}
	}
	start := r.Random()
	if a, ok, err := findGap(ctx, tx, start, r.Last()); err != nil || ok {
		return a, err
	}
	if start != r.First() {
		if a, ok, err := findGap(ctx, tx, r.First(), start); err != nil || ok {
			return a, err
		}
	}
	return netip.Addr{}, ErrPoolExhausted
}

// findGap returns the lowest free address in [lo, hi], if any.
func findGap(ctx context.Context, tx *sql.Tx, lo, hi netip.Addr) (netip.Addr, bool, error) {
	var free string
	err := tx.QueryRowContext(ctx, `
		SELECT host(c) FROM (
			(SELECT $1::inet AS c WHERE NOT EXISTS (SELECT 1 FROM devices WHERE tunnel_ip = $1::inet))
			UNION ALL
			(SELECT d.tunnel_ip + 1 FROM devices d
			 WHERE d.tunnel_ip >= $1::inet AND d.tunnel_ip < $2::inet
			   AND NOT EXISTS (SELECT 1 FROM devices x WHERE x.tunnel_ip = d.tunnel_ip + 1)
			 ORDER BY d.tunnel_ip LIMIT 1)
		) q LIMIT 1`, lo.String(), hi.String()).Scan(&free)
	if errors.Is(err, sql.ErrNoRows) {
		return netip.Addr{}, false, nil
	}
	if err != nil {
		return netip.Addr{}, false, err
	}
	a, err := netip.ParseAddr(free)
	return a, err == nil, err
}

func scanDevice(sc interface{ Scan(...any) error }) (Device, error) {
	var d Device
	var ip string
	if err := sc.Scan(&d.ID, &d.UserID, &d.Name, &d.Platform, &d.WGPublicKey, &ip, &d.CreatedAt); err != nil {
		return d, err
	}
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return d, fmt.Errorf("store: bad tunnel ip %q: %w", ip, err)
	}
	d.TunnelIP = a
	return d, nil
}

const deviceCols = `id, user_id, name, platform, wg_public_key, host(tunnel_ip), created_at`

// ListDevices returns a user's devices, oldest first.
func (s *Store) ListDevices(ctx context.Context, userID string) ([]Device, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+deviceCols+` FROM devices WHERE user_id = $1 ORDER BY created_at, id`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Device{}
	for rows.Next() {
		d, err := scanDevice(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// CountDevices returns how many devices a user has.
func (s *Store) CountDevices(ctx context.Context, userID string) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM devices WHERE user_id = $1`, userID).Scan(&n)
	return n, err
}

// GetDevice returns a device owned by userID (ErrNotFound otherwise, so a
// device id belonging to someone else is indistinguishable from a missing one).
func (s *Store) GetDevice(ctx context.Context, userID, id string) (Device, error) {
	d, err := scanDevice(s.db.QueryRowContext(ctx, `SELECT `+deviceCols+` FROM devices WHERE id = $1 AND user_id = $2`, id, userID))
	if errors.Is(err, sql.ErrNoRows) {
		return d, ErrNotFound
	}
	return d, err
}

// DeleteDevice removes a device; its address and preshared keys go with it.
func (s *Store) DeleteDevice(ctx context.Context, userID, id string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM devices WHERE id = $1 AND user_id = $2`, id, userID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// EnsurePresharedKeys returns the encrypted PSK for each (device, server),
// creating missing ones with gen. The steady state (every key exists, i.e.
// any config fetch after the first) is a single indexed read. Missing keys
// are inserted in one statement with ON CONFLICT DO NOTHING, so concurrent
// first issuances converge on a single key, and then read back.
func (s *Store) EnsurePresharedKeys(ctx context.Context, deviceID string, serverIDs []string, gen func(serverID string) (string, error)) (map[string]string, error) {
	out := make(map[string]string, len(serverIDs))
	read := func(ids []string) error {
		rows, err := s.db.QueryContext(ctx, `SELECT server_id, psk_enc FROM device_server_keys WHERE device_id = $1 AND server_id = ANY($2::uuid[])`,
			deviceID, pq.Array(ids))
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var sid, enc string
			if err := rows.Scan(&sid, &enc); err != nil {
				return err
			}
			out[sid] = enc
		}
		return rows.Err()
	}
	if err := read(serverIDs); err != nil {
		return nil, err
	}
	var missing, encs []string
	// Insert in id order: the FK checks share-lock the server rows, and a
	// consistent order rules out lock-order inversions between issuances.
	sorted := append([]string(nil), serverIDs...)
	sort.Strings(sorted)
	for _, sid := range sorted {
		if _, ok := out[sid]; ok {
			continue
		}
		enc, err := gen(sid)
		if err != nil {
			return nil, err
		}
		missing, encs = append(missing, sid), append(encs, enc)
	}
	if len(missing) == 0 {
		return out, nil
	}
	if _, err := s.db.ExecContext(ctx, `INSERT INTO device_server_keys (device_id, server_id, psk_enc)
		SELECT $1, sid, enc FROM unnest($2::uuid[], $3::text[]) AS t(sid, enc)
		ON CONFLICT (device_id, server_id) DO NOTHING`, deviceID, pq.Array(missing), pq.Array(encs)); err != nil {
		return nil, err
	}
	if err := read(missing); err != nil {
		return nil, err
	}
	for _, sid := range serverIDs {
		if _, ok := out[sid]; !ok {
			return nil, fmt.Errorf("store: preshared key for server %s missing after insert", sid)
		}
	}
	return out, nil
}
