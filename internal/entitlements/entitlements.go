// Package entitlements holds the pure rules for store-agnostic subscription
// events: validation, what "active" means, and plan derivation.
package entitlements

import (
	"errors"
	"fmt"
	"time"
	"unicode/utf8"

	"github.com/ameerhamza2/slipstream-control/internal/ids"
)

const (
	PlanFree    = "free"
	PlanPremium = "premium"
)

// DeviceLimit returns the maximum number of devices for a plan.
func DeviceLimit(plan string) int {
	if plan == PlanPremium {
		return 5
	}
	return 0
}

var (
	validSources  = map[string]bool{"stripe": true, "app_store": true, "google_play": true}
	validStatuses = map[string]bool{"active": true, "grace": true, "expired": true, "revoked": true, "refunded": true}
)

// Event is the payload of POST /internal/v1/entitlements.
type Event struct {
	EventID               string     `json:"event_id"`
	Source                string     `json:"source"`
	UserID                string     `json:"user_id"`
	ProductID             string     `json:"product_id"`
	Status                string     `json:"status"`
	ExpiresAt             *time.Time `json:"expires_at"`
	OriginalTransactionID string     `json:"original_transaction_id"`
	OccurredAt            time.Time  `json:"occurred_at"`
}

// printableID reports whether s is a non-empty identifier of at most 255
// bytes without control characters. Postgres text cannot hold NUL, so a NUL
// byte that got this far would fail the insert with a 500; other control
// characters have no business in store identifiers either.
func printableID(s string) bool {
	if s == "" || len(s) > 255 || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

// Validate checks the event's shape.
func (e Event) Validate() error {
	switch {
	case !printableID(e.EventID):
		return errors.New("event_id is required (max 255 chars, no control characters)")
	case !validSources[e.Source]:
		return fmt.Errorf("source must be one of stripe, app_store, google_play")
	case !ids.Valid(e.UserID):
		return errors.New("user_id must be a UUID")
	case !printableID(e.ProductID):
		return errors.New("product_id is required (max 255 chars, no control characters)")
	case !validStatuses[e.Status]:
		return errors.New("status must be one of active, grace, expired, revoked, refunded")
	case !printableID(e.OriginalTransactionID):
		return errors.New("original_transaction_id is required (max 255 chars, no control characters)")
	case e.OccurredAt.IsZero():
		return errors.New("occurred_at is required")
	case (e.Status == "active" || e.Status == "grace") && e.ExpiresAt == nil:
		return errors.New("expires_at is required for active and grace events")
	}
	return nil
}

// IsActive: status active or grace, with expires_at in the future.
func IsActive(status string, expiresAt *time.Time, now time.Time) bool {
	return (status == "active" || status == "grace") && expiresAt != nil && expiresAt.After(now)
}

// Subscription is the latest applied state of one (source, original_transaction_id).
type Subscription struct {
	Source      string
	Status      string
	ExpiresAt   *time.Time
	LastEventAt time.Time
}

// Summary is the /v1/me entitlement view.
type Summary struct {
	Active    bool       `json:"active"`
	ExpiresAt *time.Time `json:"expires_at"`
	Source    *string    `json:"source"`
}

// Plan returns the plan implied by the summary.
func (s Summary) Plan() string {
	if s.Active {
		return PlanPremium
	}
	return PlanFree
}

// Summarize derives the user's entitlement from all their subscriptions.
// Activity is evaluated at read time, so a subscription lapses at
// expires_at even if the store never sends an "expired" event.
// If several are active, the one expiring last wins; if none is, the most
// recently updated one is reported (so the app can show "expired on ...").
func Summarize(subs []Subscription, now time.Time) Summary {
	var best *Subscription
	bestActive := false
	for i := range subs {
		s := &subs[i]
		active := IsActive(s.Status, s.ExpiresAt, now)
		switch {
		case best == nil:
		case active && !bestActive:
		case active && bestActive && s.ExpiresAt.After(*best.ExpiresAt):
		case !active && !bestActive && s.LastEventAt.After(best.LastEventAt):
		default:
			continue
		}
		best, bestActive = s, active
	}
	if best == nil {
		return Summary{}
	}
	src := best.Source
	return Summary{Active: bestActive, ExpiresAt: best.ExpiresAt, Source: &src}
}
