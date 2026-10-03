// Command loadtest drives a running Slipstream api with a realistic mix of
// app traffic and reports throughput, latency percentiles and errors per
// endpoint. It uses only the standard library (plus the repo's own
// stdlib-only svcauth package for request signing).
//
// Setup phase (skipped when -state names an existing file):
//   - signs up -users accounts (argon2id on the server, so this is slow by design),
//   - grants each an active entitlement via the signed internal endpoint,
//   - logs each in and registers one WireGuard device.
//
// The state (emails, passwords, current tokens, device ids) is written to
// -state so later runs at other concurrency levels skip setup.
//
// Run phase: -concurrency closed-loop workers for -duration. Each worker owns
// a disjoint slice of the users, so a user's refresh token is never used by
// two goroutines at once (that would correctly trip reuse detection). A
// background goroutine plays the fleet prober and posts signed heartbeats
// for every server every 15 s so servers stay healthy past the 90 s silence
// rule.
//
// Rate limits: the api must run with TRUSTED_PROXY_CIDRS covering this
// process's address (e.g. 127.0.0.1/32). Every request then carries a random
// X-Forwarded-For from 100.64.0.0/10, so per-IP limits behave as they would
// for a population of real clients. Per-user (120/min) and per-email (5/min)
// limits are respected by giving the run enough users and pacing logins; any
// 429 that still happens is reported as an error. No production code path is
// changed or disabled for load testing.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math"
	mrand "math/rand/v2"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"text/tabwriter"
	"time"

	"github.com/ameerhamza2/slipstream-control/internal/svcauth"
)

type user struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	ID       string `json:"id"`
	Access   string `json:"access"`
	Refresh  string `json:"refresh"`
	DeviceID string `json:"device_id"`

	logins []time.Time // per-email limit pacing (5/min on the server)
}

type state struct {
	Users []*user `json:"users"`
}

type cfg struct {
	base, billingSecret, proberSecret string
	client                            *http.Client
	heartbeats                        bool
}

func main() {
	var c cfg
	flag.StringVar(&c.base, "url", "http://127.0.0.1:8080", "api base URL")
	nUsers := flag.Int("users", 3000, "users to create in setup")
	setupConc := flag.Int("setup-concurrency", 8, "concurrency of the setup phase")
	statePath := flag.String("state", "", "state file: reused if it exists, written after setup and after the run")
	conc := flag.Int("concurrency", 32, "closed-loop workers")
	dur := flag.Duration("duration", 60*time.Second, "run duration")
	mixFlag := flag.String("mix", "servers=30,me=25,config=25,refresh=15,login=5", "weighted operation mix")
	countryP := flag.Float64("country-share", 0.5, "share of config requests that ask for a specific country")
	flag.BoolVar(&c.heartbeats, "heartbeats", true, "post prober heartbeats for every server every 15 s")
	jsonOut := flag.String("json", "", "also write the report as JSON to this file")
	flag.BoolVar(&honorRetryAfter, "honor-retry-after", true, "on 429/503 with Retry-After, the worker waits that long (max 5 s) like a well-behaved app")
	label := flag.String("label", "", "label printed with the report")
	procs := flag.String("procs", "api,postgres,redis-server", "comma-separated process-name prefixes to account CPU for (Linux /proc)")
	flag.Parse()
	c.billingSecret = os.Getenv("BILLING_SERVICE_SECRET")
	c.proberSecret = os.Getenv("PROBER_SERVICE_SECRET")
	if c.billingSecret == "" || c.proberSecret == "" {
		log.Fatal("BILLING_SERVICE_SECRET and PROBER_SERVICE_SECRET must be set (same values as the api)")
	}
	mix, err := parseMix(*mixFlag)
	if err != nil {
		log.Fatal(err)
	}
	c.client = &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{
		MaxIdleConns: *conc * 2, MaxIdleConnsPerHost: *conc * 2, IdleConnTimeout: 90 * time.Second,
	}}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	var st state
	if *statePath != "" {
		if b, err := os.ReadFile(*statePath); err == nil {
			if err := json.Unmarshal(b, &st); err != nil {
				log.Fatalf("state: %v", err)
			}
			log.Printf("loaded %d users from %s", len(st.Users), *statePath)
		}
	}
	if c.heartbeats {
		hbCtx, hbStop := context.WithCancel(ctx)
		defer hbStop()
		if err := c.heartbeatOnce(hbCtx); err != nil {
			log.Fatalf("heartbeat: %v", err)
		}
		go c.heartbeatLoop(hbCtx)
	}
	if len(st.Users) == 0 {
		st.Users = c.setup(ctx, *nUsers, *setupConc)
		save(*statePath, &st)
	} else {
		c.revive(ctx, st.Users, *setupConc)
	}
	if len(st.Users) < *conc {
		log.Fatalf("need at least as many users (%d) as workers (%d)", len(st.Users), *conc)
	}

	log.Printf("run: %d workers for %s, mix %s", *conc, *dur, *mixFlag)
	groups := strings.Split(*procs, ",")
	before := sampleCPU(groups)
	rep := c.run(ctx, st.Users, *conc, *dur, mix, *countryP)
	rep.CPU = cpuDelta(before, sampleCPU(groups))
	save(*statePath, &st)
	rep.Label, rep.Concurrency, rep.Mix = *label, *conc, *mixFlag
	rep.print(os.Stdout)
	if *jsonOut != "" {
		b, _ := json.MarshalIndent(rep, "", "  ")
		if err := os.WriteFile(*jsonOut, b, 0o644); err != nil {
			log.Fatal(err)
		}
	}
}

func save(path string, st *state) {
	if path == "" {
		return
	}
	b, _ := json.Marshal(st)
	if err := os.WriteFile(path, b, 0o600); err != nil {
		log.Printf("save state: %v", err)
	}
}

// ---- HTTP helpers ---------------------------------------------------------

type result struct {
	status     int
	body       []byte
	dur        time.Duration
	err        error
	retryAfter time.Duration
}

// randomIP is a client address from the CGNAT range, presented through the
// (trusted) X-Forwarded-For header.
func randomIP() string {
	n := mrand.Uint32()
	return fmt.Sprintf("100.%d.%d.%d", 64+(n>>16)&63, (n>>8)&255, n&255)
}

func (c *cfg) do(ctx context.Context, method, path string, body []byte, hdr map[string]string) result {
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, rdr)
	if err != nil {
		return result{err: err}
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("X-Forwarded-For", randomIP())
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	start := time.Now()
	res, err := c.client.Do(req)
	if err != nil {
		return result{err: err, dur: time.Since(start)}
	}
	b, err := io.ReadAll(res.Body)
	res.Body.Close()
	r := result{status: res.StatusCode, body: b, dur: time.Since(start), err: err}
	if n, err := strconv.Atoi(res.Header.Get("Retry-After")); err == nil && n > 0 {
		r.retryAfter = time.Duration(n) * time.Second
	}
	return r
}

func (c *cfg) doJSON(ctx context.Context, method, path string, v any, hdr map[string]string) result {
	var b []byte
	if v != nil {
		b, _ = json.Marshal(v)
	}
	return c.do(ctx, method, path, b, hdr)
}

func (c *cfg) signed(ctx context.Context, service, secret, method, path string, v any) result {
	var b []byte
	if v != nil {
		b, _ = json.Marshal(v)
	}
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	return c.do(ctx, method, path, b, map[string]string{
		svcauth.HeaderService: service, svcauth.HeaderTimestamp: ts,
		svcauth.HeaderSignature: svcauth.Sign([]byte(secret), ts, method, path, b),
	})
}

func bearer(tok string) map[string]string { return map[string]string{"Authorization": "Bearer " + tok} }

func randKey() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}

// ---- prober simulation ----------------------------------------------------

func (c *cfg) heartbeatOnce(ctx context.Context) error {
	r := c.signed(ctx, svcauth.ServiceProber, c.proberSecret, "GET", "/internal/v1/servers", nil)
	if r.err != nil || r.status != 200 {
		return fmt.Errorf("list servers: %v %d %s", r.err, r.status, trunc(r.body))
	}
	var servers []struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(r.body, &servers); err != nil {
		return err
	}
	results := make([]map[string]any, 0, len(servers))
	for _, s := range servers {
		rtt := 10 + mrand.Float64()*150
		results = append(results, map[string]any{"server_id": s.ID, "reachable": true, "rtt_ms_p50": rtt,
			"rtt_ms_p95": rtt * 1.4, "loss": mrand.Float64() * 0.01, "load": mrand.Float64()})
	}
	// Two batches so new servers pass the "2 consecutive reachable" rule.
	for i := 0; i < 2; i++ {
		for off := 0; off < len(results); off += 5000 {
			end := min(off+5000, len(results))
			h := c.signed(ctx, svcauth.ServiceProber, c.proberSecret, "POST", "/internal/v1/servers/heartbeats",
				map[string]any{"prober_id": "loadtest", "observed_at": time.Now().UTC().Format(time.RFC3339), "results": results[off:end]})
			if h.err != nil || h.status != 202 {
				return fmt.Errorf("heartbeats: %v %d %s", h.err, h.status, trunc(h.body))
			}
			hbLatency.add(h.dur)
		}
	}
	return nil
}

var hbLatency latencies

func (c *cfg) heartbeatLoop(ctx context.Context) {
	t := time.NewTicker(15 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := c.heartbeatOnce(ctx); err != nil && ctx.Err() == nil {
				log.Printf("heartbeat: %v", err)
			}
		}
	}
}

// ---- setup ----------------------------------------------------------------

func (c *cfg) setup(ctx context.Context, n, conc int) []*user {
	log.Printf("setup: creating %d users (signup, entitlement, login, device) with %d workers", n, conc)
	runID := strconv.FormatInt(time.Now().UnixNano(), 36)
	users := make([]*user, n)
	var next, done, failed atomic.Int64
	var wg sync.WaitGroup
	start := time.Now()
	for w := 0; w < conc; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				i := int(next.Add(1) - 1)
				if i >= n || ctx.Err() != nil {
					return
				}
				u := &user{Email: fmt.Sprintf("lt-%s-%d@example.com", runID, i), Password: "loadtest-password-" + runID}
				if err := c.provision(ctx, u); err != nil {
					failed.Add(1)
					log.Printf("setup user %d: %v", i, err)
					continue
				}
				users[i] = u
				if d := done.Add(1); d%500 == 0 {
					log.Printf("setup: %d/%d users (%.0f/s)", d, n, float64(d)/time.Since(start).Seconds())
				}
			}
		}()
	}
	wg.Wait()
	out := users[:0]
	for _, u := range users {
		if u != nil {
			out = append(out, u)
		}
	}
	log.Printf("setup: %d users ready, %d failed, in %s", len(out), failed.Load(), time.Since(start).Round(time.Second))
	return out
}

// retry repeats op on 429/503 (setup only; the run phase records them).
func retry(ctx context.Context, op func() result) result {
	var r result
	for attempt := 0; attempt < 30; attempt++ {
		r = op()
		if r.err == nil && r.status != 429 && r.status != 503 {
			return r
		}
		select {
		case <-ctx.Done():
			return r
		case <-time.After(time.Duration(200+mrand.IntN(800)) * time.Millisecond):
		}
	}
	return r
}

func (c *cfg) provision(ctx context.Context, u *user) error {
	cred := map[string]string{"email": u.Email, "password": u.Password}
	r := retry(ctx, func() result { return c.doJSON(ctx, "POST", "/v1/auth/signup", cred, nil) })
	if r.err != nil || r.status != 201 {
		return fmt.Errorf("signup: %v %d %s", r.err, r.status, trunc(r.body))
	}
	var s struct {
		UserID string `json:"user_id"`
	}
	_ = json.Unmarshal(r.body, &s)
	u.ID = s.UserID
	now := time.Now().UTC()
	ev := map[string]any{"event_id": "lt_" + u.ID, "source": "stripe", "user_id": u.ID, "product_id": "premium_monthly",
		"status": "active", "expires_at": now.Add(30 * 24 * time.Hour).Format(time.RFC3339),
		"original_transaction_id": "lt_sub_" + u.ID, "occurred_at": now.Format(time.RFC3339)}
	r = retry(ctx, func() result {
		return c.signed(ctx, svcauth.ServiceBilling, c.billingSecret, "POST", "/internal/v1/entitlements", ev)
	})
	if r.err != nil || r.status != 200 {
		return fmt.Errorf("entitle: %v %d %s", r.err, r.status, trunc(r.body))
	}
	if err := c.login(ctx, u, true); err != nil {
		return err
	}
	r = retry(ctx, func() result {
		return c.doJSON(ctx, "POST", "/v1/devices", map[string]string{"name": "loadtest", "platform": "android", "wg_public_key": randKey()}, bearer(u.Access))
	})
	if r.err != nil || r.status != 201 {
		return fmt.Errorf("device: %v %d %s", r.err, r.status, trunc(r.body))
	}
	var d struct {
		DeviceID string `json:"device_id"`
	}
	_ = json.Unmarshal(r.body, &d)
	u.DeviceID = d.DeviceID
	return nil
}

func (c *cfg) login(ctx context.Context, u *user, withRetry bool) error {
	op := func() result {
		return c.doJSON(ctx, "POST", "/v1/auth/login", map[string]string{"email": u.Email, "password": u.Password}, nil)
	}
	var r result
	if withRetry {
		r = retry(ctx, op)
	} else {
		r = op()
	}
	if r.err != nil || r.status != 200 {
		return fmt.Errorf("login: %v %d %s", r.err, r.status, trunc(r.body))
	}
	return u.takeTokens(r.body)
}

func (u *user) takeTokens(b []byte) error {
	var t struct {
		Access  string `json:"access_token"`
		Refresh string `json:"refresh_token"`
	}
	if err := json.Unmarshal(b, &t); err != nil || t.Access == "" {
		return errors.New("bad token response")
	}
	u.Access, u.Refresh = t.Access, t.Refresh
	return nil
}

// revive refreshes every stored session (access tokens from an earlier run
// have probably expired); users whose refresh fails log in again.
func (c *cfg) revive(ctx context.Context, users []*user, conc int) {
	start := time.Now()
	var next, relogged atomic.Int64
	var wg sync.WaitGroup
	for w := 0; w < conc*4; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				i := int(next.Add(1) - 1)
				if i >= len(users) || ctx.Err() != nil {
					return
				}
				u := users[i]
				r := retry(ctx, func() result {
					return c.doJSON(ctx, "POST", "/v1/auth/refresh", map[string]string{"refresh_token": u.Refresh}, nil)
				})
				if r.status == 200 && u.takeTokens(r.body) == nil {
					continue
				}
				relogged.Add(1)
				if err := c.login(ctx, u, true); err != nil {
					log.Printf("revive %s: %v", u.Email, err)
				}
			}
		}()
	}
	wg.Wait()
	log.Printf("revived %d sessions (%d re-logins) in %s", len(users), relogged.Load(), time.Since(start).Round(time.Millisecond))
}

// ---- run ------------------------------------------------------------------

type op struct {
	name   string
	weight int
}

func parseMix(s string) ([]op, error) {
	var out []op
	known := map[string]bool{"servers": true, "me": true, "config": true, "refresh": true, "login": true, "devices": true}
	for _, part := range strings.Split(s, ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		w, err := strconv.Atoi(v)
		if !ok || err != nil || w < 0 || !known[k] {
			return nil, fmt.Errorf("bad -mix entry %q (ops: servers, me, config, refresh, login, devices)", part)
		}
		if w > 0 {
			out = append(out, op{k, w})
		}
	}
	if len(out) == 0 {
		return nil, errors.New("empty -mix")
	}
	return out, nil
}

func pick(mix []op, total int) string {
	n := mrand.IntN(total)
	for _, o := range mix {
		if n < o.weight {
			return o.name
		}
		n -= o.weight
	}
	return mix[len(mix)-1].name
}

var countries = strings.Fields("US DE GB FR NL JP SG CA AU BR IN ES IT SE CH")

var honorRetryAfter bool

// backoff makes a worker behave like a real client after being shed.
func backoff(ctx context.Context, r result) {
	if !honorRetryAfter || (r.status != 503 && r.status != 429) || r.retryAfter <= 0 {
		return
	}
	select {
	case <-ctx.Done():
	case <-time.After(min(r.retryAfter, 5*time.Second)):
	}
}

type latencies struct {
	mu sync.Mutex
	ds []time.Duration
}

func (l *latencies) add(d time.Duration) {
	l.mu.Lock()
	l.ds = append(l.ds, d)
	l.mu.Unlock()
}

type stats struct {
	ok   map[string][]time.Duration
	errs map[string]map[string]int
}

func newStats() *stats {
	return &stats{ok: map[string][]time.Duration{}, errs: map[string]map[string]int{}}
}

func (s *stats) record(name string, r result, want int) {
	if r.err == nil && r.status == want {
		s.ok[name] = append(s.ok[name], r.dur)
		return
	}
	k := strconv.Itoa(r.status)
	if r.err != nil {
		k = "neterr"
		if errors.Is(r.err, context.DeadlineExceeded) || errors.Is(r.err, context.Canceled) {
			k = "canceled"
		}
	}
	if s.errs[name] == nil {
		s.errs[name] = map[string]int{}
	}
	s.errs[name][k]++
}

func (c *cfg) run(ctx context.Context, users []*user, conc int, dur time.Duration, mix []op, countryShare float64) report {
	total := 0
	for _, o := range mix {
		total += o.weight
	}
	runCtx, cancel := context.WithTimeout(ctx, dur)
	defer cancel()
	all := make([]*stats, conc)
	var wg sync.WaitGroup
	start := time.Now()
	for w := 0; w < conc; w++ {
		var mine []*user
		for i := w; i < len(users); i += conc {
			mine = append(mine, users[i])
		}
		st := newStats()
		all[w] = st
		wg.Add(1)
		go func() {
			defer wg.Done()
			for runCtx.Err() == nil {
				u := mine[mrand.IntN(len(mine))]
				name := pick(mix, total)
				c.step(runCtx, st, u, name, countryShare)
			}
		}()
	}
	wg.Wait()
	elapsed := time.Since(start)
	merged := newStats()
	for _, s := range all {
		for k, v := range s.ok {
			merged.ok[k] = append(merged.ok[k], v...)
		}
		for k, m := range s.errs {
			if merged.errs[k] == nil {
				merged.errs[k] = map[string]int{}
			}
			for code, n := range m {
				merged.errs[k][code] += n
			}
		}
	}
	return buildReport(merged, elapsed)
}

func (c *cfg) step(ctx context.Context, st *stats, u *user, name string, countryShare float64) {
	switch name {
	case "login":
		// The server allows 5 logins per email per minute; stay under it.
		now := time.Now()
		recent := u.logins[:0]
		for _, t := range u.logins {
			if now.Sub(t) < time.Minute {
				recent = append(recent, t)
			}
		}
		u.logins = recent
		if len(recent) >= 4 {
			name = "me"
			break
		}
		u.logins = append(u.logins, now)
		r := c.doJSON(ctx, "POST", "/v1/auth/login", map[string]string{"email": u.Email, "password": u.Password}, nil)
		if ctx.Err() != nil {
			return
		}
		st.record("login", r, 200)
		if r.status == 200 {
			_ = u.takeTokens(r.body)
		}
		backoff(ctx, r)
		return
	case "refresh":
		r := c.doJSON(ctx, "POST", "/v1/auth/refresh", map[string]string{"refresh_token": u.Refresh}, nil)
		if ctx.Err() != nil {
			return
		}
		st.record("refresh", r, 200)
		backoff(ctx, r)
		if r.status == 200 {
			_ = u.takeTokens(r.body)
		} else if r.status == 401 {
			_ = c.login(ctx, u, true)
		}
		return
	}
	var r result
	want := 200
	switch name {
	case "me":
		r = c.do(ctx, "GET", "/v1/me", nil, bearer(u.Access))
	case "servers":
		r = c.do(ctx, "GET", "/v1/servers", nil, bearer(u.Access))
	case "devices":
		r = c.do(ctx, "GET", "/v1/devices", nil, bearer(u.Access))
	case "config":
		body := map[string]string{}
		if mrand.Float64() < countryShare {
			body["country"] = countries[mrand.IntN(len(countries))]
		}
		r = c.doJSON(ctx, "POST", "/v1/devices/"+u.DeviceID+"/config", body, bearer(u.Access))
	}
	if ctx.Err() != nil {
		return // the run ended mid-request; do not count it
	}
	st.record(name, r, want)
	backoff(ctx, r)
}

// ---- report ---------------------------------------------------------------

type endpointReport struct {
	Endpoint string         `json:"endpoint"`
	OK       int            `json:"ok"`
	Errors   map[string]int `json:"errors,omitempty"`
	RPS      float64        `json:"rps"`
	P50ms    float64        `json:"p50_ms"`
	P95ms    float64        `json:"p95_ms"`
	P99ms    float64        `json:"p99_ms"`
	MaxMs    float64        `json:"max_ms"`
}

type report struct {
	Label       string             `json:"label,omitempty"`
	Concurrency int                `json:"concurrency"`
	Mix         string             `json:"mix"`
	Seconds     float64            `json:"seconds"`
	TotalRPS    float64            `json:"total_rps"`
	ErrorRate   float64            `json:"error_rate"`
	Endpoints   []endpointReport   `json:"endpoints"`
	Heartbeat   *endpointReport    `json:"heartbeat_batch,omitempty"`
	CPU         map[string]float64 `json:"cpu_seconds,omitempty"`
}

func pct(ds []time.Duration, p float64) float64 {
	if len(ds) == 0 {
		return 0
	}
	i := int(math.Ceil(p*float64(len(ds)))) - 1
	i = max(0, min(i, len(ds)-1))
	return float64(ds[i].Microseconds()) / 1000
}

func summarize(name string, ds []time.Duration, secs float64) endpointReport {
	sort.Slice(ds, func(i, j int) bool { return ds[i] < ds[j] })
	return endpointReport{Endpoint: name, OK: len(ds), RPS: float64(len(ds)) / secs,
		P50ms: pct(ds, .50), P95ms: pct(ds, .95), P99ms: pct(ds, .99), MaxMs: pct(ds, 1)}
}

func buildReport(s *stats, elapsed time.Duration) report {
	secs := elapsed.Seconds()
	rep := report{Seconds: math.Round(secs*10) / 10}
	names := map[string]bool{}
	for k := range s.ok {
		names[k] = true
	}
	for k := range s.errs {
		names[k] = true
	}
	var okTotal, errTotal int
	for name := range names {
		e := summarize(name, s.ok[name], secs)
		e.Errors = s.errs[name]
		for _, n := range e.Errors {
			errTotal += n
		}
		okTotal += e.OK
		rep.Endpoints = append(rep.Endpoints, e)
	}
	sort.Slice(rep.Endpoints, func(i, j int) bool { return rep.Endpoints[i].Endpoint < rep.Endpoints[j].Endpoint })
	rep.TotalRPS = float64(okTotal+errTotal) / secs
	if okTotal+errTotal > 0 {
		rep.ErrorRate = float64(errTotal) / float64(okTotal+errTotal)
	}
	hbLatency.mu.Lock()
	if len(hbLatency.ds) > 0 {
		h := summarize("heartbeat_batch", append([]time.Duration(nil), hbLatency.ds...), secs)
		h.RPS = 0
		rep.Heartbeat = &h
	}
	hbLatency.mu.Unlock()
	return rep
}

func (r report) print(w io.Writer) {
	fmt.Fprintf(w, "\n== %s concurrency=%d duration=%.1fs total=%.1f req/s errors=%.2f%%  mix=%s\n",
		r.Label, r.Concurrency, r.Seconds, r.TotalRPS, 100*r.ErrorRate, r.Mix)
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', tabwriter.AlignRight)
	fmt.Fprintln(tw, "endpoint\tok\treq/s\tp50 ms\tp95 ms\tp99 ms\tmax ms\terrors\t")
	for _, e := range r.Endpoints {
		var errs []string
		for k, n := range e.Errors {
			errs = append(errs, fmt.Sprintf("%s:%d", k, n))
		}
		sort.Strings(errs)
		fmt.Fprintf(tw, "%s\t%d\t%.1f\t%.1f\t%.1f\t%.1f\t%.1f\t%s\t\n", e.Endpoint, e.OK, e.RPS, e.P50ms, e.P95ms, e.P99ms, e.MaxMs, strings.Join(errs, " "))
	}
	if r.Heartbeat != nil {
		h := r.Heartbeat
		fmt.Fprintf(tw, "%s\t%d\t-\t%.1f\t%.1f\t%.1f\t%.1f\t\t\n", h.Endpoint, h.OK, h.P50ms, h.P95ms, h.P99ms, h.MaxMs)
	}
	tw.Flush()
	if len(r.CPU) > 0 && r.TotalRPS > 0 {
		reqs := r.TotalRPS * r.Seconds
		var keys []string
		for k := range r.CPU {
			if k != "_busy" {
				keys = append(keys, k)
			}
		}
		sort.Strings(keys)
		fmt.Fprintf(w, "cpu (cores avg over run): machine busy %.2f", r.CPU["_busy"]/r.Seconds)
		for _, k := range keys {
			fmt.Fprintf(w, "  %s %.2f", k, r.CPU[k]/r.Seconds)
		}
		fmt.Fprintf(w, "\ncpu ms per request:")
		for _, k := range keys {
			if k != "other" && k != "loadtest" {
				fmt.Fprintf(w, "  %s %.2f", k, 1000*r.CPU[k]/reqs)
			}
		}
		fmt.Fprintln(w)
	}
}

func trunc(b []byte) string {
	if len(b) > 200 {
		return string(b[:200]) + "..."
	}
	return string(b)
}
