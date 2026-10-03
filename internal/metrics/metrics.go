// Package metrics is a minimal, dependency-free Prometheus text-format
// (version 0.0.4) exposition: labelled counters, gauges and histograms.
package metrics

import (
	"fmt"
	"io"
	"math"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
)

type collector interface {
	write(w io.Writer)
	name() string
}

// Registry holds collectors and renders them.
type Registry struct {
	mu         sync.Mutex
	collectors []collector
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry { return &Registry{} }

func (r *Registry) register(c collector) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.collectors = append(r.collectors, c)
}

// Render renders every collector, sorted by name.
func (r *Registry) Render(w io.Writer) {
	r.mu.Lock()
	cs := append([]collector(nil), r.collectors...)
	r.mu.Unlock()
	sort.Slice(cs, func(i, j int) bool { return cs[i].name() < cs[j].name() })
	for _, c := range cs {
		c.write(w)
	}
}

// Handler serves the registry.
func (r *Registry) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		r.Render(w)
	})
}

func escape(v string) string {
	return strings.NewReplacer(`\`, `\\`, "\n", `\n`, `"`, `\"`).Replace(v)
}

func labelString(names, values []string, extra ...string) string {
	if len(names) == 0 && len(extra) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteByte('{')
	for i, n := range names {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `%s="%s"`, n, escape(values[i]))
	}
	for i := 0; i+1 < len(extra); i += 2 {
		if b.Len() > 1 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `%s="%s"`, extra[i], escape(extra[i+1]))
	}
	b.WriteByte('}')
	return b.String()
}

func formatFloat(f float64) string {
	switch {
	case math.IsInf(f, 1):
		return "+Inf"
	case math.IsInf(f, -1):
		return "-Inf"
	}
	return strconv.FormatFloat(f, 'g', -1, 64)
}

type series[T any] struct {
	mu     sync.RWMutex
	byKey  map[string]*T
	values map[string][]string
}

func (s *series[T]) get(labels []string, want int, mk func() *T) *T {
	if len(labels) != want {
		panic(fmt.Sprintf("metrics: expected %d label values, got %d", want, len(labels)))
	}
	key := strings.Join(labels, "\xff")
	s.mu.RLock()
	v, ok := s.byKey[key]
	s.mu.RUnlock()
	if ok {
		return v
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if v, ok = s.byKey[key]; ok {
		return v
	}
	if s.byKey == nil {
		s.byKey, s.values = map[string]*T{}, map[string][]string{}
	}
	v = mk()
	s.byKey[key] = v
	s.values[key] = append([]string(nil), labels...)
	return v
}

func (s *series[T]) sortedKeys() []string {
	keys := make([]string, 0, len(s.byKey))
	for k := range s.byKey {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// atomicFloat is a float64 updated with CAS.
type atomicFloat struct{ bits atomic.Uint64 }

func (a *atomicFloat) Add(d float64) {
	for {
		old := a.bits.Load()
		if a.bits.CompareAndSwap(old, math.Float64bits(math.Float64frombits(old)+d)) {
			return
		}
	}
}
func (a *atomicFloat) Set(v float64) { a.bits.Store(math.Float64bits(v)) }
func (a *atomicFloat) Load() float64 { return math.Float64frombits(a.bits.Load()) }

// CounterVec is a monotonically increasing counter with labels.
type CounterVec struct {
	n, help, typ string
	labels       []string
	s            series[atomicFloat]
}

// NewCounterVec registers a counter.
func (r *Registry) NewCounterVec(name, help string, labels ...string) *CounterVec {
	c := &CounterVec{n: name, help: help, typ: "counter", labels: labels}
	r.register(c)
	return c
}

// NewGaugeVec registers a gauge (same storage, settable).
func (r *Registry) NewGaugeVec(name, help string, labels ...string) *CounterVec {
	c := &CounterVec{n: name, help: help, typ: "gauge", labels: labels}
	r.register(c)
	return c
}

func (c *CounterVec) name() string { return c.n }

// Inc adds 1.
func (c *CounterVec) Inc(labels ...string) { c.Add(1, labels...) }

// Add adds d (must be >= 0 for counters).
func (c *CounterVec) Add(d float64, labels ...string) {
	c.s.get(labels, len(c.labels), func() *atomicFloat { return &atomicFloat{} }).Add(d)
}

// Set sets a gauge value.
func (c *CounterVec) Set(v float64, labels ...string) {
	c.s.get(labels, len(c.labels), func() *atomicFloat { return &atomicFloat{} }).Set(v)
}

// Value returns the current value (tests).
func (c *CounterVec) Value(labels ...string) float64 {
	return c.s.get(labels, len(c.labels), func() *atomicFloat { return &atomicFloat{} }).Load()
}

func (c *CounterVec) write(w io.Writer) {
	fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s %s\n", c.n, c.help, c.n, c.typ)
	c.s.mu.RLock()
	defer c.s.mu.RUnlock()
	if len(c.labels) == 0 && len(c.s.byKey) == 0 {
		fmt.Fprintf(w, "%s 0\n", c.n)
	}
	for _, k := range c.s.sortedKeys() {
		fmt.Fprintf(w, "%s%s %s\n", c.n, labelString(c.labels, c.s.values[k]), formatFloat(c.s.byKey[k].Load()))
	}
}

// DefaultBuckets are latency buckets in seconds.
var DefaultBuckets = []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10}

type histogram struct {
	counts []atomic.Uint64 // per bucket (non-cumulative), +Inf last
	sum    atomicFloat
	count  atomic.Uint64
}

// HistogramVec is a labelled histogram.
type HistogramVec struct {
	n, help string
	labels  []string
	buckets []float64
	s       series[histogram]
}

// NewHistogramVec registers a histogram with the given upper bounds.
func (r *Registry) NewHistogramVec(name, help string, buckets []float64, labels ...string) *HistogramVec {
	h := &HistogramVec{n: name, help: help, labels: labels, buckets: append([]float64(nil), buckets...)}
	sort.Float64s(h.buckets)
	r.register(h)
	return h
}

func (h *HistogramVec) name() string { return h.n }

// Observe records v.
func (h *HistogramVec) Observe(v float64, labels ...string) {
	hs := h.s.get(labels, len(h.labels), func() *histogram {
		return &histogram{counts: make([]atomic.Uint64, len(h.buckets)+1)}
	})
	i := sort.SearchFloat64s(h.buckets, v) // first bucket with bound >= v
	hs.counts[i].Add(1)
	hs.sum.Add(v)
	hs.count.Add(1)
}

func (h *HistogramVec) write(w io.Writer) {
	fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s histogram\n", h.n, h.help, h.n)
	h.s.mu.RLock()
	defer h.s.mu.RUnlock()
	for _, k := range h.s.sortedKeys() {
		hs, lv := h.s.byKey[k], h.s.values[k]
		var cum uint64
		for i, b := range h.buckets {
			cum += hs.counts[i].Load()
			fmt.Fprintf(w, "%s_bucket%s %d\n", h.n, labelString(h.labels, lv, "le", formatFloat(b)), cum)
		}
		cum += hs.counts[len(h.buckets)].Load()
		fmt.Fprintf(w, "%s_bucket%s %d\n", h.n, labelString(h.labels, lv, "le", "+Inf"), cum)
		fmt.Fprintf(w, "%s_sum%s %s\n", h.n, labelString(h.labels, lv), formatFloat(hs.sum.Load()))
		fmt.Fprintf(w, "%s_count%s %d\n", h.n, labelString(h.labels, lv), hs.count.Load())
	}
}

// App bundles the service's metrics.
type App struct {
	Registry          *Registry
	HTTPRequests      *CounterVec
	HTTPDuration      *HistogramVec
	RateLimitRejected *CounterVec
	RateLimitFailOpen *CounterVec
	RateLimitFailShut *CounterVec
	Heartbeats        *CounterVec
	EntitlementEvents *CounterVec
	Shed              *CounterVec
	ServerSnapshots   *CounterVec
	SecretDecryptFail *CounterVec
}

// NewApp registers all application metrics on a fresh registry.
func NewApp() *App {
	r := NewRegistry()
	return &App{
		Registry:          r,
		HTTPRequests:      r.NewCounterVec("slipstream_http_requests_total", "HTTP requests by route pattern, method and status.", "route", "method", "status"),
		HTTPDuration:      r.NewHistogramVec("slipstream_http_request_duration_seconds", "HTTP request latency by route pattern and method.", DefaultBuckets, "route", "method"),
		RateLimitRejected: r.NewCounterVec("slipstream_ratelimit_rejected_total", "Requests rejected with 429 by limit scope.", "scope"),
		RateLimitFailOpen: r.NewCounterVec("slipstream_ratelimit_fail_open_total", "Requests allowed because the rate limiter (Redis) was unavailable.", "scope"),
		RateLimitFailShut: r.NewCounterVec("slipstream_ratelimit_fail_closed_total", "Auth requests refused because the rate limiter (Redis) was unavailable.", "scope"),
		Heartbeats:        r.NewCounterVec("slipstream_heartbeat_results_total", "Prober heartbeat results ingested.", "reachable"),
		EntitlementEvents: r.NewCounterVec("slipstream_entitlement_events_total", "Entitlement events by outcome.", "source", "result"),
		Shed:              r.NewCounterVec("slipstream_requests_shed_total", "Requests answered 503 + Retry-After instead of being queued or failed, by reason.", "reason"),
		ServerSnapshots:   r.NewCounterVec("slipstream_server_snapshot_loads_total", "Server list snapshot loads from Postgres, by result.", "result"),
		SecretDecryptFail: r.NewCounterVec("slipstream_secret_decrypt_failures_total", "Servers skipped during config issuance because a stored secret failed to decrypt (wrong DATA_ENCRYPTION_KEY or corrupted row). Should always be 0: alert on any increase.", "kind"),
	}
}
