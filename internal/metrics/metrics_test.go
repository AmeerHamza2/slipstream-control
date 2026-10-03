package metrics

import (
	"strings"
	"sync"
	"testing"
)

func TestExposition(t *testing.T) {
	r := NewRegistry()
	c := r.NewCounterVec("reqs_total", "Requests.", "route", "status")
	h := r.NewHistogramVec("lat_seconds", "Latency.", []float64{0.1, 1}, "route")
	plain := r.NewCounterVec("plain_total", "No labels.")

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); c.Inc("GET /v1/me", "200") }()
	}
	wg.Wait()
	c.Inc(`we"ird`, "500")
	h.Observe(0.05, "r")
	h.Observe(0.5, "r")
	h.Observe(5, "r")

	var b strings.Builder
	r.Render(&b)
	out := b.String()
	for _, want := range []string{
		"# TYPE reqs_total counter",
		`reqs_total{route="GET /v1/me",status="200"} 100`,
		`reqs_total{route="we\"ird",status="500"} 1`,
		"# TYPE lat_seconds histogram",
		`lat_seconds_bucket{route="r",le="0.1"} 1`,
		`lat_seconds_bucket{route="r",le="1"} 2`,
		`lat_seconds_bucket{route="r",le="+Inf"} 3`,
		`lat_seconds_sum{route="r"} 5.55`,
		`lat_seconds_count{route="r"} 3`,
		"plain_total 0",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Index(out, "lat_seconds") > strings.Index(out, "reqs_total") {
		t.Error("collectors not sorted")
	}
	_ = plain
}
