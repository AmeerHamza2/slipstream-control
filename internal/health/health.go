// Package health is the server health state machine fed by prober heartbeats.
//
//   - A server becomes unhealthy after 3 consecutive unreachable results.
//   - It becomes healthy after 2 consecutive reachable results.
//   - It is unhealthy whenever no heartbeat has arrived for 90 s. This rule
//     is evaluated at read time (Effective), so it holds even if every
//     prober dies and nothing is left to run a state transition.
//
// New servers start unhealthy and must earn two reachable results.
package health

import "time"

const (
	UnhealthyAfter = 3
	HealthyAfter   = 2
	SilenceTimeout = 90 * time.Second
)

// State is the persisted per-server health state.
type State struct {
	Healthy                bool
	ConsecutiveReachable   int
	ConsecutiveUnreachable int
	LastHeartbeatAt        *time.Time
	RTTp50, RTTp95, Loss   *float64
	Load                   *float64
}

// Result is one prober observation of one server.
type Result struct {
	Reachable bool
	RTTp50    *float64
	RTTp95    *float64
	Loss      *float64
	Load      *float64 // nil = unknown: keep the previous value
}

// Silent reports whether the server has gone SilenceTimeout without a heartbeat.
func Silent(s State, now time.Time) bool {
	return s.LastHeartbeatAt == nil || now.Sub(*s.LastHeartbeatAt) > SilenceTimeout
}

// Effective is the health callers should act on.
func Effective(s State, now time.Time) bool { return s.Healthy && !Silent(s, now) }

// Apply folds a result into the state. If the server had gone silent it is
// first reset to unhealthy, so recovering from silence also requires two
// consecutive reachable results (no stale "healthy" flag survives an outage).
func Apply(s State, r Result, now time.Time) State {
	if Silent(s, now) {
		s.Healthy = false
		s.ConsecutiveReachable = 0
		s.ConsecutiveUnreachable = 0
	}
	if r.Reachable {
		s.ConsecutiveReachable++
		s.ConsecutiveUnreachable = 0
		if s.ConsecutiveReachable >= HealthyAfter {
			s.Healthy = true
		}
	} else {
		s.ConsecutiveUnreachable++
		s.ConsecutiveReachable = 0
		if s.ConsecutiveUnreachable >= UnhealthyAfter {
			s.Healthy = false
		}
	}
	// Saturate counters; they only matter up to their thresholds.
	s.ConsecutiveReachable = min(s.ConsecutiveReachable, 1000)
	s.ConsecutiveUnreachable = min(s.ConsecutiveUnreachable, 1000)
	if r.RTTp50 != nil {
		s.RTTp50 = r.RTTp50
	}
	if r.RTTp95 != nil {
		s.RTTp95 = r.RTTp95
	}
	if r.Loss != nil {
		s.Loss = r.Loss
	}
	if r.Load != nil {
		s.Load = r.Load
	}
	t := now
	s.LastHeartbeatAt = &t
	return s
}
