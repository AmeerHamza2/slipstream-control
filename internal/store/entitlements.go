package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/ameerhamza2/slipstream-control/internal/entitlements"
)

// Outcome reasons for an entitlement event that was not applied.
const (
	ReasonDuplicate = "duplicate"
	ReasonStale     = "stale"
)

// ApplyEntitlementEvent records and applies a billing event.
//
//   - Idempotency: the event row is inserted with ON CONFLICT DO NOTHING on
//     event_id; zero rows inserted means we have seen it -> "duplicate".
//   - Ordering: the subscription upsert only overwrites when the incoming
//     occurred_at is >= the stored last_event_at. That comparison happens
//     inside the INSERT ... ON CONFLICT DO UPDATE ... WHERE, so it is atomic
//     even when two events for the same subscription race; zero rows
//     affected means a newer event already won -> "stale".
//
// Returns ErrNotFound if the user does not exist.
func (s *Store) ApplyEntitlementEvent(ctx context.Context, e entitlements.Event) (applied bool, reason string, err error) {
	err = s.inTx(ctx, func(tx *sql.Tx) error {
		var one int
		if err := tx.QueryRowContext(ctx, `SELECT 1 FROM users WHERE id = $1`, e.UserID).Scan(&one); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrNotFound
			}
			return err
		}
		res, err := tx.ExecContext(ctx, `INSERT INTO entitlement_events
			(event_id, source, user_id, product_id, status, expires_at, original_transaction_id, occurred_at, applied)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, false) ON CONFLICT (event_id) DO NOTHING`,
			e.EventID, e.Source, e.UserID, e.ProductID, e.Status, e.ExpiresAt, e.OriginalTransactionID, e.OccurredAt)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			applied, reason = false, ReasonDuplicate
			return nil
		}
		res, err = tx.ExecContext(ctx, `INSERT INTO subscriptions
			(source, original_transaction_id, user_id, product_id, status, expires_at, last_event_id, last_event_at, updated_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, now())
			ON CONFLICT (source, original_transaction_id) DO UPDATE SET
				user_id = EXCLUDED.user_id, product_id = EXCLUDED.product_id, status = EXCLUDED.status,
				expires_at = EXCLUDED.expires_at, last_event_id = EXCLUDED.last_event_id,
				last_event_at = EXCLUDED.last_event_at, updated_at = now()
			WHERE subscriptions.last_event_at <= EXCLUDED.last_event_at`,
			e.Source, e.OriginalTransactionID, e.UserID, e.ProductID, e.Status, e.ExpiresAt, e.EventID, e.OccurredAt)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			applied, reason = false, ReasonStale
		} else {
			applied = true
		}
		var r any
		if reason != "" {
			r = reason
		}
		_, err = tx.ExecContext(ctx, `UPDATE entitlement_events SET applied = $2, reason = $3 WHERE event_id = $1`, e.EventID, applied, r)
		return err
	})
	return applied, reason, err
}

// Subscriptions returns all subscriptions of a user.
func (s *Store) Subscriptions(ctx context.Context, userID string) ([]entitlements.Subscription, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT source, status, expires_at, last_event_at FROM subscriptions WHERE user_id = $1`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []entitlements.Subscription
	for rows.Next() {
		var sub entitlements.Subscription
		var exp sql.NullTime
		if err := rows.Scan(&sub.Source, &sub.Status, &exp, &sub.LastEventAt); err != nil {
			return nil, err
		}
		sub.ExpiresAt = nullTime(exp)
		out = append(out, sub)
	}
	return out, rows.Err()
}

// Entitlement summarises a user's current entitlement.
func (s *Store) Entitlement(ctx context.Context, userID string, now time.Time) (entitlements.Summary, error) {
	subs, err := s.Subscriptions(ctx, userID)
	if err != nil {
		return entitlements.Summary{}, err
	}
	return entitlements.Summarize(subs, now), nil
}
