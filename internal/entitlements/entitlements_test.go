package entitlements

import (
	"testing"
	"time"
)

func tp(t time.Time) *time.Time { return &t }

func TestIsActive(t *testing.T) {
	now := time.Now()
	future, past := now.Add(time.Hour), now.Add(-time.Hour)
	cases := []struct {
		status string
		exp    *time.Time
		want   bool
	}{
		{"active", &future, true},
		{"grace", &future, true},
		{"active", &past, false},
		{"active", nil, false},
		{"expired", &future, false},
		{"revoked", &future, false},
		{"refunded", &future, false},
	}
	for _, c := range cases {
		if got := IsActive(c.status, c.exp, now); got != c.want {
			t.Errorf("IsActive(%s,%v)=%v", c.status, c.exp, got)
		}
	}
}

func TestSummarize(t *testing.T) {
	now := time.Now()
	if s := Summarize(nil, now); s.Active || s.Source != nil || s.Plan() != PlanFree {
		t.Fatalf("empty: %+v", s)
	}
	subs := []Subscription{
		{Source: "stripe", Status: "expired", ExpiresAt: tp(now.Add(-time.Hour)), LastEventAt: now.Add(-time.Minute)},
		{Source: "app_store", Status: "active", ExpiresAt: tp(now.Add(time.Hour)), LastEventAt: now.Add(-time.Hour)},
		{Source: "google_play", Status: "grace", ExpiresAt: tp(now.Add(2 * time.Hour)), LastEventAt: now.Add(-2 * time.Hour)},
	}
	s := Summarize(subs, now)
	if !s.Active || *s.Source != "google_play" || s.Plan() != PlanPremium {
		t.Fatalf("active: %+v", s)
	}
	// Everything lapsed: report the most recently updated.
	s = Summarize(subs, now.Add(3*time.Hour))
	if s.Active || *s.Source != "stripe" || s.Plan() != PlanFree {
		t.Fatalf("lapsed: %+v", s)
	}
}

func TestValidate(t *testing.T) {
	good := Event{EventID: "evt_1", Source: "stripe", UserID: "123e4567-e89b-42d3-a456-426614174000", ProductID: "premium_monthly",
		Status: "active", ExpiresAt: tp(time.Now()), OriginalTransactionID: "sub_1", OccurredAt: time.Now()}
	if err := good.Validate(); err != nil {
		t.Fatal(err)
	}
	mut := []func(*Event){
		func(e *Event) { e.EventID = "" },
		func(e *Event) { e.Source = "paypal" },
		func(e *Event) { e.UserID = "nope" },
		func(e *Event) { e.Status = "paused" },
		func(e *Event) { e.ExpiresAt = nil },
		func(e *Event) { e.OriginalTransactionID = "" },
		func(e *Event) { e.OccurredAt = time.Time{} },
		func(e *Event) { e.ProductID = "" },
		// Postgres text cannot store NUL: these used to reach the INSERT and 500.
		func(e *Event) { e.EventID = "evt\x00" },
		func(e *Event) { e.ProductID = "a\x00b" },
		func(e *Event) { e.OriginalTransactionID = "\x00" },
		func(e *Event) { e.OriginalTransactionID = "sub\n1" },
		func(e *Event) { e.EventID = "evt\xff" },
	}
	for i, m := range mut {
		e := good
		m(&e)
		if e.Validate() == nil {
			t.Errorf("mutation %d accepted", i)
		}
	}
	e := good
	e.Status, e.ExpiresAt = "expired", nil
	if err := e.Validate(); err != nil {
		t.Errorf("expired without expires_at rejected: %v", err)
	}
	if DeviceLimit(PlanFree) != 0 || DeviceLimit(PlanPremium) != 5 {
		t.Fatal("device limits")
	}
}
