package health

import (
	"testing"
	"time"
)

func fp(v float64) *float64 { return &v }

func TestStateMachine(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	up := Result{Reachable: true, RTTp50: fp(40), Load: fp(0.3)}
	down := Result{Reachable: false}
	var s State

	if Effective(s, now) {
		t.Fatal("new server must start unhealthy")
	}
	s = Apply(s, up, now)
	if Effective(s, now) {
		t.Fatal("healthy after a single reachable result")
	}
	now = now.Add(15 * time.Second)
	s = Apply(s, up, now)
	if !Effective(s, now) {
		t.Fatal("not healthy after 2 reachable results")
	}
	for i := 1; i <= 2; i++ {
		now = now.Add(15 * time.Second)
		s = Apply(s, down, now)
		if !Effective(s, now) {
			t.Fatalf("unhealthy after only %d unreachable results", i)
		}
	}
	now = now.Add(15 * time.Second)
	s = Apply(s, down, now)
	if Effective(s, now) {
		t.Fatal("still healthy after 3 unreachable results")
	}
	// One reachable in between resets the unreachable streak.
	now = now.Add(15 * time.Second)
	s = Apply(s, up, now)
	if Effective(s, now) {
		t.Fatal("recovered after only one reachable")
	}
	now = now.Add(15 * time.Second)
	s = Apply(s, up, now)
	if !Effective(s, now) {
		t.Fatal("did not recover after 2 reachable")
	}
	if *s.Load != 0.3 || *s.RTTp50 != 40 {
		t.Fatalf("metrics not stored: %+v", s)
	}
	// Unknown load keeps the last value.
	s = Apply(s, Result{Reachable: true, Load: nil, RTTp50: fp(50)}, now)
	if *s.Load != 0.3 || *s.RTTp50 != 50 {
		t.Fatalf("load not kept: %v", *s.Load)
	}
}

func TestSilence(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	up := Result{Reachable: true}
	s := Apply(Apply(State{}, up, now), up, now)
	if !Effective(s, now.Add(90*time.Second)) {
		t.Fatal("unhealthy at exactly 90s")
	}
	if Effective(s, now.Add(91*time.Second)) {
		t.Fatal("healthy after 91s of silence")
	}
	// After silence, one reachable result is not enough.
	later := now.Add(5 * time.Minute)
	s = Apply(s, up, later)
	if Effective(s, later) {
		t.Fatal("silence did not reset the healthy streak")
	}
	s = Apply(s, up, later.Add(time.Second))
	if !Effective(s, later.Add(time.Second)) {
		t.Fatal("did not recover after silence")
	}
}
