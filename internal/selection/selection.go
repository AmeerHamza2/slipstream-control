// Package selection ranks VPN servers for config issuance.
package selection

import (
	"math"
	"sort"
	"strings"
)

// Candidate is the subset of server state that ranking needs.
type Candidate struct {
	ID      string
	Name    string
	Country string
	Healthy bool
	// Metrics are pointers because the prober may not have reported them yet.
	RTTp50 *float64
	Load   *float64
	Loss   *float64
}

// Defaults applied when a metric is unknown. They are deliberately
// pessimistic so a server with real, good numbers outranks an unknown one.
const (
	UnknownRTTms = 1000.0
	UnknownLoad  = 0.5
	UnknownLoss  = 0.0
)

// Score is rtt_ms_p50 + 400*load + 200*loss (lower is better).
func Score(c Candidate) float64 {
	rtt, load, loss := UnknownRTTms, UnknownLoad, UnknownLoss
	if c.RTTp50 != nil && !math.IsNaN(*c.RTTp50) {
		rtt = *c.RTTp50
	}
	if c.Load != nil && !math.IsNaN(*c.Load) {
		load = *c.Load
	}
	if c.Loss != nil && !math.IsNaN(*c.Loss) {
		loss = *c.Loss
	}
	return rtt + 400*load + 200*loss
}

// Rank returns up to n healthy candidates, best first. If country is set,
// only servers in that country are considered unless none of them is healthy,
// in which case all countries are used. Ties break by name for determinism.
func Rank(all []Candidate, country string, n int) []Candidate {
	var healthy, inCountry []Candidate
	for _, c := range all {
		if !c.Healthy {
			continue
		}
		healthy = append(healthy, c)
		if country != "" && strings.EqualFold(c.Country, country) {
			inCountry = append(inCountry, c)
		}
	}
	pool := healthy
	if country != "" && len(inCountry) > 0 {
		pool = inCountry
	}
	sort.SliceStable(pool, func(i, j int) bool {
		si, sj := Score(pool[i]), Score(pool[j])
		if si != sj {
			return si < sj
		}
		return pool[i].Name < pool[j].Name
	})
	if len(pool) > n {
		pool = pool[:n]
	}
	return pool
}

// Ranking is a candidate list pre-sorted by (Score, Name). Scores do not
// depend on health, so a fleet snapshot is sorted once and each config
// request only walks it, applying health at read time: O(k) for the usual
// case instead of filtering and sorting the whole fleet per request.
type Ranking struct{ sorted []Candidate }

// NewRanking sorts a copy of all (the Healthy field is ignored).
func NewRanking(all []Candidate) *Ranking {
	s := append([]Candidate(nil), all...)
	sort.SliceStable(s, func(i, j int) bool {
		si, sj := Score(s[i]), Score(s[j])
		if si != sj {
			return si < sj
		}
		return s[i].Name < s[j].Name
	})
	return &Ranking{sorted: s}
}

// Top returns exactly what Rank would for the same candidates when healthy
// reports each candidate's health: up to n healthy servers best first,
// restricted to country when any server there is healthy.
func (r *Ranking) Top(country string, n int, healthy func(Candidate) bool) []Candidate {
	var out []Candidate
	if country != "" {
		for _, c := range r.sorted {
			if len(out) == n {
				break
			}
			if strings.EqualFold(c.Country, country) && healthy(c) {
				c.Healthy = true
				out = append(out, c)
			}
		}
		if len(out) > 0 {
			return out
		}
	}
	for _, c := range r.sorted {
		if len(out) == n {
			break
		}
		if healthy(c) {
			c.Healthy = true
			out = append(out, c)
		}
	}
	return out
}
