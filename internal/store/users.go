package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/ameerhamza2/slipstream-control/internal/auth"
)

// User is an account.
type User struct {
	ID           string
	Email        string
	PasswordHash string
	CreatedAt    time.Time
}

// CreateUser inserts a user; email must already be normalised.
func (s *Store) CreateUser(ctx context.Context, id, email, passwordHash string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO users (id, email, password_hash) VALUES ($1, $2, $3)`, id, email, passwordHash)
	if c, ok := uniqueViolation(err); ok && c == "users_email_key" {
		return ErrEmailTaken
	}
	return err
}

func (s *Store) userBy(ctx context.Context, col, v string) (User, error) {
	var u User
	err := s.db.QueryRowContext(ctx, `SELECT id, email, password_hash, created_at FROM users WHERE `+col+` = $1`, v).
		Scan(&u.ID, &u.Email, &u.PasswordHash, &u.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return u, ErrNotFound
	}
	return u, err
}

// UserByEmail looks a user up by normalised email.
func (s *Store) UserByEmail(ctx context.Context, email string) (User, error) {
	return s.userBy(ctx, "email", email)
}

// UserByID looks a user up by id.
func (s *Store) UserByID(ctx context.Context, id string) (User, error) {
	return s.userBy(ctx, "id", id)
}

// UpdatePasswordHash replaces a user's hash (transparent rehash on login).
func (s *Store) UpdatePasswordHash(ctx context.Context, id, hash string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE users SET password_hash = $2 WHERE id = $1`, id, hash)
	return err
}

// CreateRefreshToken stores a new token (the first of a family on login).
func (s *Store) CreateRefreshToken(ctx context.Context, id, userID, familyID string, hash []byte, expiresAt time.Time) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO refresh_tokens (id, user_id, family_id, token_hash, expires_at) VALUES ($1, $2, $3, $4, $5)`,
		id, userID, familyID, hash, expiresAt)
	return err
}

// RotateRefreshToken atomically exchanges oldHash for newHash in the same
// family. Reuse of an already-rotated token revokes the entire family and
// returns ErrTokenReused (the revocation is committed).
func (s *Store) RotateRefreshToken(ctx context.Context, oldHash, newHash []byte, newID string, now time.Time) (userID, familyID string, err error) {
	var reused bool
	err = s.inTx(ctx, func(tx *sql.Tx) error {
		var rec auth.RefreshRecord
		var rotated, revoked sql.NullTime
		err := tx.QueryRowContext(ctx, `SELECT id, user_id, family_id, expires_at, rotated_at, revoked_at
			FROM refresh_tokens WHERE token_hash = $1 FOR UPDATE`, oldHash).
			Scan(&rec.ID, &rec.UserID, &rec.FamilyID, &rec.ExpiresAt, &rotated, &revoked)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrTokenInvalid
		}
		if err != nil {
			return err
		}
		rec.RotatedAt, rec.RevokedAt = nullTime(rotated), nullTime(revoked)
		switch auth.DecideRotation(rec, now) {
		case auth.RotateExpired:
			return ErrTokenInvalid
		case auth.RotateReuse:
			if _, err := tx.ExecContext(ctx, `UPDATE refresh_tokens SET revoked_at = $2 WHERE family_id = $1 AND revoked_at IS NULL`, rec.FamilyID, now); err != nil {
				return err
			}
			reused, userID, familyID = true, rec.UserID, rec.FamilyID
			return nil // commit the revocation
		}
		if _, err := tx.ExecContext(ctx, `UPDATE refresh_tokens SET rotated_at = $2 WHERE id = $1`, rec.ID, now); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO refresh_tokens (id, user_id, family_id, token_hash, expires_at) VALUES ($1, $2, $3, $4, $5)`,
			newID, rec.UserID, rec.FamilyID, newHash, now.Add(auth.RefreshTokenTTL)); err != nil {
			return err
		}
		userID, familyID = rec.UserID, rec.FamilyID
		return nil
	})
	if err == nil && reused {
		return userID, familyID, ErrTokenReused
	}
	return userID, familyID, err
}

// RevokeFamily revokes every token in a user's refresh family.
func (s *Store) RevokeFamily(ctx context.Context, userID, familyID string, now time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, `UPDATE refresh_tokens SET revoked_at = $3 WHERE user_id = $1 AND family_id = $2 AND revoked_at IS NULL`, userID, familyID, now)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// cleanupBatch bounds each janitor DELETE so it never holds locks on, or
// generates WAL for, millions of rows in one statement.
const cleanupBatch = 5000

// deleteBatched runs a "DELETE ... WHERE id IN (SELECT ... LIMIT $2)"
// statement until it deletes fewer than a batch, pausing briefly between
// batches so replication and foreground traffic keep up.
func (s *Store) deleteBatched(ctx context.Context, q string, arg any) (int64, error) {
	var total int64
	for {
		res, err := s.db.ExecContext(ctx, q, arg, cleanupBatch)
		if err != nil {
			return total, err
		}
		n, _ := res.RowsAffected()
		total += n
		if n < cleanupBatch {
			return total, nil
		}
		select {
		case <-ctx.Done():
			return total, ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}
}

// DeleteExpiredRefreshTokens garbage-collects tokens that expired before
// `before`, in index-backed batches (refresh_tokens_expires_idx).
func (s *Store) DeleteExpiredRefreshTokens(ctx context.Context, before time.Time) (int64, error) {
	return s.deleteBatched(ctx, `DELETE FROM refresh_tokens WHERE id IN
		(SELECT id FROM refresh_tokens WHERE expires_at < $1 LIMIT $2)`, before)
}

// DeleteRevokedRefreshTokens removes tokens revoked before `before`. A
// revoked token is rejected whether or not its row still exists (reuse of a
// revoked token only re-revokes an already revoked family), so the rows are
// dead weight once revocation is a day old.
func (s *Store) DeleteRevokedRefreshTokens(ctx context.Context, before time.Time) (int64, error) {
	return s.deleteBatched(ctx, `DELETE FROM refresh_tokens WHERE id IN
		(SELECT id FROM refresh_tokens WHERE revoked_at < $1 LIMIT $2)`, before)
}

// DeletePeerTombstones removes peer removals older than `before`.
func (s *Store) DeletePeerTombstones(ctx context.Context, before time.Time) (int64, error) {
	return s.deleteBatched(ctx, `DELETE FROM peer_tombstones WHERE ctid IN
		(SELECT ctid FROM peer_tombstones WHERE deleted_at < $1 LIMIT $2)`, before)
}

// CleanupStats reports one janitor pass.
type CleanupStats struct {
	ExpiredTokens, RevokedTokens, Tombstones int64
}

// AcquireLease takes the named lease for `ttl` if it is free or expired, on
// the database clock. It is a single upsert, so it works through any
// connection pooler, and a crashed holder simply lets the lease expire.
func (s *Store) AcquireLease(ctx context.Context, name, holder string, ttl time.Duration) (bool, error) {
	var got string
	err := s.db.QueryRowContext(ctx, `INSERT INTO maintenance_leases (name, holder, expires_at)
		VALUES ($1, $2, now() + $3 * interval '1 millisecond')
		ON CONFLICT (name) DO UPDATE SET holder = EXCLUDED.holder, expires_at = EXCLUDED.expires_at
		WHERE maintenance_leases.expires_at <= now()
		RETURNING holder`, name, holder, ttl.Milliseconds()).Scan(&got)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}

// ReleaseLease gives the lease up early (only if holder still has it).
func (s *Store) ReleaseLease(ctx context.Context, name, holder string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE maintenance_leases SET expires_at = now() WHERE name = $1 AND holder = $2`, name, holder)
	return err
}

// JanitorLease names the janitor's lease.
const JanitorLease = "janitor"

// Cleanup runs one janitor pass if this replica wins the janitor lease for
// the next `every`. Every replica calls it periodically; the lease makes the
// work happen once per interval across the fleet. If the pass fails the
// lease is released so another replica retries on its next tick.
func (s *Store) Cleanup(ctx context.Context, now time.Time, holder string, every time.Duration) (stats CleanupStats, ran bool, err error) {
	if ran, err = s.AcquireLease(ctx, JanitorLease, holder, every); err != nil || !ran {
		return stats, false, err
	}
	defer func() {
		if err != nil {
			rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			defer cancel()
			_ = s.ReleaseLease(rctx, JanitorLease, holder)
		}
	}()
	// Tokens are kept a day past expiry/revocation so a late replay of a
	// rotated token is still recognised as reuse.
	grace := now.Add(-24 * time.Hour)
	if stats.ExpiredTokens, err = s.DeleteExpiredRefreshTokens(ctx, grace); err != nil {
		return stats, true, err
	}
	if stats.RevokedTokens, err = s.DeleteRevokedRefreshTokens(ctx, grace); err != nil {
		return stats, true, err
	}
	stats.Tombstones, err = s.DeletePeerTombstones(ctx, now.Add(-PeerTombstoneRetention))
	return stats, true, err
}
