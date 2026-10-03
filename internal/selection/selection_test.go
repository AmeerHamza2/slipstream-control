package selection

import (
	"fmt"
	"math/rand/v2"
	"reflect"
	"testing"
)

func f(v float64) *float64 { return &v }

func names(cs []Candidate) []string {
	out := []string{}
	for _, c := range cs {
		out = append(out, c.Name)
	}
	return out
}

func TestScore(t *testing.T) {
	c := Candidate{RTTp50: f(40), Load: f(0.5), Loss: f(0.1)}
	if s := Score(c); s != 40+200+20 {
		t.Fatalf("score %v", s)
	}
	if s := Score(Candidate{}); s != UnknownRTTms+400*UnknownLoad {
		t.Fatalf("unknown score %v", s)
	}
}

func TestRank(t *testing.T) {
	servers := []Candidate{
		{Name: "fra-01", Country: "DE", Healthy: true, RTTp50: f(40), Load: f(0.9), Loss: f(0)}, // 400
		{Name: "fra-02", Country: "DE", Healthy: true, RTTp50: f(45), Load: f(0.1), Loss: f(0)}, // 85
		{Name: "ams-01", Country: "NL", Healthy: true, RTTp50: f(30), Load: f(0.1), Loss: f(0)}, // 70
		{Name: "lon-01", Country: "GB", Healthy: true, RTTp50: f(20), Load: f(0), Loss: f(0.5)}, // 120
		{Name: "par-01", Country: "FR", Healthy: false, RTTp50: f(1), Load: f(0), Loss: f(0)},   // unhealthy
		{Name: "ber-01", Country: "DE", Healthy: true, RTTp50: f(45), Load: f(0.1), Loss: f(0)}, // 85, tie with fra-02
		{Name: "nyc-01", Country: "US", Healthy: true, RTTp50: nil, Load: nil, Loss: nil},       // 1200
	}
	if got := names(Rank(servers, "", 3)); !reflect.DeepEqual(got, []string{"ams-01", "ber-01", "fra-02"}) {
		t.Fatalf("global ranking %v", got)
	}
	if got := names(Rank(servers, "de", 3)); !reflect.DeepEqual(got, []string{"ber-01", "fra-02", "fra-01"}) {
		t.Fatalf("country ranking %v", got)
	}
	// No healthy server in FR: fall back to all countries.
	if got := names(Rank(servers, "FR", 2)); !reflect.DeepEqual(got, []string{"ams-01", "ber-01"}) {
		t.Fatalf("fallback ranking %v", got)
	}
	if got := Rank([]Candidate{{Name: "x", Healthy: false}}, "", 3); len(got) != 0 {
		t.Fatalf("expected none, got %v", got)
	}
	if got := Rank(servers, "", 100); len(got) != 6 {
		t.Fatalf("expected all 6 healthy, got %d", len(got))
	}
}

// TestRankingMatchesRank checks the precomputed ranking against the
// reference implementation on random fleets.
func TestRankingMatchesRank(t *testing.T) {
	rng := rand.New(rand.NewPCG(7, 9))
	countries := []string{"DE", "NL", "US", "JP"}
	for iter := 0; iter < 2000; iter++ {
		var all []Candidate
		for i := 0; i < rng.IntN(40); i++ {
			c := Candidate{ID: fmt.Sprint(i), Name: fmt.Sprintf("s%02d", rng.IntN(30)), Country: countries[rng.IntN(4)], Healthy: rng.IntN(3) > 0}
			if rng.IntN(5) > 0 {
				c.RTTp50 = f(float64(rng.IntN(5)) * 10)
			}
			if rng.IntN(5) > 0 {
				c.Load = f(float64(rng.IntN(4)) / 4)
			}
			if rng.IntN(5) > 0 {
				c.Loss = f(float64(rng.IntN(3)) / 10)
			}
			all = append(all, c)
		}
		health := map[string]bool{}
		for _, c := range all {
			health[c.ID] = c.Healthy
		}
		country := []string{"", "de", "US", "FR"}[rng.IntN(4)]
		n := 1 + rng.IntN(4)
		want := Rank(append([]Candidate(nil), all...), country, n)
		got := NewRanking(all).Top(country, n, func(c Candidate) bool { return health[c.ID] })
		if fmt.Sprint(ids(want)) != fmt.Sprint(ids(got)) {
			t.Fatalf("iter %d country %q n %d: Rank %v, Top %v", iter, country, n, ids(want), ids(got))
		}
	}
}

func ids(cs []Candidate) []string {
	out := make([]string, len(cs))
	for i, c := range cs {
		out[i] = c.ID
	}
	return out
}
