package httpapi_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/ameerhamza2/slipstream-control/internal/auth"
	"github.com/ameerhamza2/slipstream-control/internal/httpapi"
	"github.com/ameerhamza2/slipstream-control/internal/ids"
	"github.com/ameerhamza2/slipstream-control/internal/ratelimit"
	"github.com/ameerhamza2/slipstream-control/internal/store"
	"github.com/ameerhamza2/slipstream-control/internal/svcauth"
)

// generousLimits keeps rate limits out of the way of tests that are about
// something else.
func generousLimits(d *httpapi.Deps) {
	d.Limits = httpapi.Limits{AuthPerIP: 10000, AuthPerEmail: 1000, RefreshPerIP: 10000, PerUser: 10000, Window: time.Minute}
}

// premium creates an entitled user (directly in the store: no argon2) and
// returns its id and an access token.
func (e *env) premium(expires time.Time) (userID, token string) {
	e.t.Helper()
	userID = ids.New()
	if err := testStore.CreateUser(context.Background(), userID, randEmail(), "x"); err != nil {
		e.t.Fatal(err)
	}
	expect(e.t, e.entitle(userID, "active", expires, e.clock.Now(), "sub_"+userID), 200)
	token, _, err := e.tokens.Issue(userID, ids.New())
	if err != nil {
		e.t.Fatal(err)
	}
	return userID, token
}

func (e *env) newDevice(token string) string {
	e.t.Helper()
	r := e.do("POST", "/v1/devices", map[string]string{"name": "d", "platform": "ios", "wg_public_key": wgKey()}, bearerHdr(token))
	expect(e.t, r, http.StatusCreated)
	return r.json(e.t)["device_id"].(string)
}

func (e *env) healthyServer(name, country, ip string) string {
	e.t.Helper()
	id := e.createServer(name, country, ip, "")["id"].(string)
	for i := 0; i < 2; i++ {
		expect(e.t, e.heartbeat(up(id, 30, 0.2)), http.StatusAccepted)
	}
	return id
}

// ---- peers: pagination and incremental sync --------------------------------

type peerAgent struct {
	peers map[string]map[string]any
	token string
}

func peerIDs(m map[string]map[string]any) string {
	out := make([]string, 0, len(m))
	for id := range m {
		out = append(out, id)
	}
	sort.Strings(out)
	return strings.Join(out, ",")
}

func (e *env) peersPath(serverID, query string) string {
	p := "/admin/v1/servers/" + serverID + "/peers"
	if query != "" {
		p += "?" + query
	}
	return p
}

// fullSync pages through the list the way a node agent would.
func (e *env) fullSync(serverID string, limit int) peerAgent {
	e.t.Helper()
	a := peerAgent{peers: map[string]map[string]any{}}
	cursor := ""
	for pages := 0; ; pages++ {
		if pages > 100 {
			e.t.Fatal("pagination does not terminate")
		}
		q := "limit=" + strconv.Itoa(limit)
		if cursor != "" {
			q += "&cursor=" + url.QueryEscape(cursor)
		}
		r := e.admin("GET", e.peersPath(serverID, q), nil)
		expect(e.t, r, 200)
		tok := r.header.Get("X-Sync-Token")
		if tok == "" || (a.token != "" && tok != a.token) {
			e.t.Fatalf("sync token %q changed mid-walk (first %q)", tok, a.token)
		}
		a.token = tok
		page := r.list(e.t)
		if len(page) > limit {
			e.t.Fatalf("page of %d > limit %d", len(page), limit)
		}
		for _, p := range page {
			id := p["device_id"].(string)
			if _, dup := a.peers[id]; dup {
				e.t.Fatalf("peer %s returned twice", id)
			}
			a.peers[id] = p
		}
		cursor = r.header.Get("X-Next-Cursor")
		if cursor == "" {
			if r.header.Get("Link") != "" {
				e.t.Fatal("Link without cursor")
			}
			return a
		}
		if !strings.Contains(r.header.Get("Link"), `rel="next"`) {
			e.t.Fatalf("Link: %q", r.header.Get("Link"))
		}
	}
}

func (e *env) legacyPeers(serverID string) map[string]map[string]any {
	e.t.Helper()
	r := e.admin("GET", e.peersPath(serverID, ""), nil)
	expect(e.t, r, 200)
	if r.header.Get("X-Sync-Token") == "" {
		e.t.Fatal("legacy listing lacks X-Sync-Token")
	}
	out := map[string]map[string]any{}
	for _, p := range r.list(e.t) {
		out[p["device_id"].(string)] = p
	}
	return out
}

// sync applies one incremental sync: upserts first, then removals.
func (e *env) sync(serverID string, a *peerAgent) (ups, rems int) {
	e.t.Helper()
	r := e.admin("GET", e.peersPath(serverID, "since="+url.QueryEscape(a.token)), nil)
	expect(e.t, r, 200)
	var ch struct {
		Upserts   []map[string]any `json:"upserts"`
		Removals  []string         `json:"removals"`
		SyncToken string           `json:"sync_token"`
	}
	if err := json.Unmarshal(r.body, &ch); err != nil || ch.Upserts == nil || ch.Removals == nil || ch.SyncToken == "" {
		e.t.Fatalf("delta: %v %s", err, r.body)
	}
	if r.header.Get("X-Sync-Token") != ch.SyncToken {
		e.t.Fatal("header and body sync tokens differ")
	}
	for _, p := range ch.Upserts {
		sameKeys(e.t, "upsert", p, "device_id", "wg_public_key", "tunnel_address", "preshared_key")
		a.peers[p["device_id"].(string)] = p
	}
	for _, id := range ch.Removals {
		delete(a.peers, id)
	}
	a.token = ch.SyncToken
	return len(ch.Upserts), len(ch.Removals)
}

func TestPeersPaginationAndIncrementalSync(t *testing.T) {
	e := newEnv(t, generousLimits)
	resetServers(t)
	srv := e.healthyServer("pag-01", "SE", "203.0.113.50")
	now := e.clock.Now()
	type acct struct{ user, token, device string }
	var accts []acct
	for i := 0; i < 7; i++ {
		exp := now.Add(30 * 24 * time.Hour)
		if i == 0 {
			exp = now.Add(time.Hour) // lapses by time later in the test
		}
		u, tok := e.premium(exp)
		d := e.newDevice(tok)
		expect(t, e.do("POST", "/v1/devices/"+d+"/config", nil, bearerHdr(tok)), 200)
		accts = append(accts, acct{u, tok, d})
	}
	legacy := e.legacyPeers(srv)
	if len(legacy) != 7 {
		t.Fatalf("legacy: %d peers", len(legacy))
	}
	for _, limit := range []int{1, 2, 3, 7, 1000} {
		a := e.fullSync(srv, limit)
		if peerIDs(a.peers) != peerIDs(legacy) {
			t.Fatalf("limit %d: paged %v != legacy %v", limit, peerIDs(a.peers), peerIDs(legacy))
		}
		for id, p := range legacy {
			if fmt.Sprint(a.peers[id]) != fmt.Sprint(p) {
				t.Fatalf("peer differs: %v vs %v", a.peers[id], p)
			}
		}
	}
	// cursor alone uses the default page size.
	a := e.fullSync(srv, 2)
	first := e.admin("GET", e.peersPath(srv, "limit=2"), nil)
	r := e.admin("GET", e.peersPath(srv, "cursor="+url.QueryEscape(first.header.Get("X-Next-Cursor"))), nil)
	expect(t, r, 200)
	if n := len(r.list(t)); n != 5 {
		t.Fatalf("cursor without limit returned %d", n)
	}

	for _, q := range []string{"limit=0", "limit=10001", "limit=x", "cursor=nope", "cursor=c1.!!", "since=nope", "since=v1.zz&limit=5", "since=v1.-5"} {
		r := e.admin("GET", e.peersPath(srv, q), nil)
		expect(t, r, 400)
		if r.errCode(t) != "invalid_request" {
			t.Fatal(q)
		}
	}
	expect(t, e.admin("GET", e.peersPath(srv, "since="+"v1."+strconv.FormatInt(time.Now().Add(-25*time.Hour).UnixMicro(), 36)), nil), http.StatusGone)
	expect(t, e.admin("GET", e.peersPath(srv, "since="+"v1."+strconv.FormatInt(time.Now().Add(time.Hour).UnixMicro(), 36)), nil), 400)
	expect(t, e.admin("GET", e.peersPath(ids.New(), "since="+url.QueryEscape(a.token)), nil), 404)

	check := func(step string) {
		t.Helper()
		ups, rems := e.sync(srv, &a)
		if got, want := peerIDs(a.peers), peerIDs(e.legacyPeers(srv)); got != want {
			t.Fatalf("%s: agent state %v != server list %v (upserts %d, removals %d)", step, got, want, ups, rems)
		}
	}
	check("no change")

	// New peer.
	u, tok := e.premium(now.Add(30 * 24 * time.Hour))
	d := e.newDevice(tok)
	expect(t, e.do("POST", "/v1/devices/"+d+"/config", nil, bearerHdr(tok)), 200)
	check("new peer")
	if _, ok := a.peers[d]; !ok {
		t.Fatal("new peer not synced")
	}
	// Device removed by its owner.
	expect(t, e.do("DELETE", "/v1/devices/"+accts[1].device, nil, bearerHdr(accts[1].token)), 204)
	check("device deleted")
	if _, ok := a.peers[accts[1].device]; ok {
		t.Fatal("deleted device still synced")
	}
	// Account deleted (cascade through devices to keys: the trigger still fires).
	if _, err := testStore.DB().Exec(`DELETE FROM users WHERE id = $1`, accts[2].user); err != nil {
		t.Fatal(err)
	}
	check("user deleted")
	// Subscription expired by an event.
	expect(t, e.entitle(accts[3].user, "expired", now.Add(-time.Second), e.clock.Now().Add(time.Second), "sub_"+accts[3].user), 200)
	check("expired event")
	if _, ok := a.peers[accts[3].device]; ok {
		t.Fatal("expired user still synced")
	}
	// Renewed again.
	expect(t, e.entitle(accts[3].user, "active", now.Add(60*24*time.Hour), e.clock.Now().Add(2*time.Second), "sub_"+accts[3].user), 200)
	check("renewed")
	if _, ok := a.peers[accts[3].device]; !ok {
		t.Fatal("renewed user not synced")
	}
	// Lapse by time alone: no event arrives, expires_at simply passes.
	e.clock.Advance(2 * time.Hour)
	check("lapsed by time")
	if _, ok := a.peers[accts[0].device]; ok {
		t.Fatal("time-lapsed user still synced")
	}
	_ = u
	if len(a.peers) != 5 {
		t.Fatalf("final peers %d: %v", len(a.peers), peerIDs(a.peers))
	}
}

// ---- IPAM -------------------------------------------------------------------

func TestIPAMExhaustionAndGapReuse(t *testing.T) {
	e := newEnv(t, generousLimits)
	lo, hi := netip.MustParseAddr("10.100.0.2"), netip.MustParseAddr("10.100.0.5")
	clean := func() {
		if _, err := testStore.DB().Exec(`DELETE FROM devices WHERE tunnel_ip << inet '10.100.0.0/24'`); err != nil {
			t.Fatal(err)
		}
	}
	clean()
	if err := testStore.SetTunnelRange(lo, hi); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = testStore.SetTunnelRange(netip.MustParseAddr("10.64.0.2"), netip.MustParseAddr("10.127.255.254"))
		clean()
	})
	_, tok := e.premium(e.clock.Now().Add(time.Hour))
	_, tok2 := e.premium(e.clock.Now().Add(time.Hour))
	addrs := map[string]string{} // address -> device
	for i := 0; i < 4; i++ {
		r := e.do("POST", "/v1/devices", map[string]string{"name": "d", "platform": "ios", "wg_public_key": wgKey()}, bearerHdr(tok))
		expect(t, r, 201)
		m := r.json(t)
		addrs[m["tunnel_address"].(string)] = m["device_id"].(string)
	}
	if len(addrs) != 4 || addrs["10.100.0.2/32"] == "" || addrs["10.100.0.5/32"] == "" {
		t.Fatalf("allocation: %v", addrs)
	}
	// Pool exhausted: a clean, retryable 503 (not a 500).
	r := e.do("POST", "/v1/devices", map[string]string{"name": "d", "platform": "ios", "wg_public_key": wgKey()}, bearerHdr(tok2))
	expect(t, r, http.StatusServiceUnavailable)
	if r.header.Get("Retry-After") == "" || r.errCode(t) != "internal" {
		t.Fatalf("exhaustion response: %v %s", r.header, r.body)
	}
	// A freed address in the middle is found by the gap search...
	expect(t, e.do("DELETE", "/v1/devices/"+addrs["10.100.0.3/32"], nil, bearerHdr(tok)), 204)
	r = e.do("POST", "/v1/devices", map[string]string{"name": "d", "platform": "ios", "wg_public_key": wgKey()}, bearerHdr(tok2))
	expect(t, r, 201)
	if got := r.json(t)["tunnel_address"]; got != "10.100.0.3/32" {
		t.Fatalf("gap reuse got %v", got)
	}
	// ...and so is one at the very start of the range.
	expect(t, e.do("DELETE", "/v1/devices/"+addrs["10.100.0.2/32"], nil, bearerHdr(tok)), 204)
	r = e.do("POST", "/v1/devices", map[string]string{"name": "d", "platform": "ios", "wg_public_key": wgKey()}, bearerHdr(tok2))
	expect(t, r, 201)
	if got := r.json(t)["tunnel_address"]; got != "10.100.0.2/32" {
		t.Fatalf("gap reuse at range start got %v", got)
	}
	expect(t, e.do("POST", "/v1/devices", map[string]string{"name": "d", "platform": "ios", "wg_public_key": wgKey()}, bearerHdr(tok2)), 503)
}

// TestIPAMConcurrentHerd: many allocators racing for max+1 must all succeed
// with unique addresses (retries with skip, then gap search).
func TestIPAMConcurrentHerd(t *testing.T) {
	e := newEnv(t, generousLimits)
	const n = 48
	tokens := make([]string, n)
	for i := range tokens {
		_, tokens[i] = e.premium(e.clock.Now().Add(time.Hour))
	}
	var mu sync.Mutex
	addrs := map[string]bool{}
	var wg sync.WaitGroup
	start := make(chan struct{})
	for _, tok := range tokens {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			buf, _ := json.Marshal(map[string]string{"name": "d", "platform": "android", "wg_public_key": wgKey()})
			req, _ := http.NewRequest("POST", e.srv.URL+"/v1/devices", bytes.NewReader(buf))
			req.Header.Set("Authorization", "Bearer "+tok)
			res, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Error(err)
				return
			}
			defer res.Body.Close()
			var m map[string]any
			_ = json.NewDecoder(res.Body).Decode(&m)
			if res.StatusCode != 201 {
				t.Errorf("status %d: %v", res.StatusCode, m)
				return
			}
			mu.Lock()
			addrs[m["tunnel_address"].(string)] = true
			mu.Unlock()
		}()
	}
	close(start)
	wg.Wait()
	if len(addrs) != n {
		t.Fatalf("%d unique addresses for %d devices", len(addrs), n)
	}
}

// ---- dependency outages -----------------------------------------------------

// flakyProxy is a TCP proxy to Postgres that can be cut, which is how a
// failover, network partition or restart looks to the api.
type flakyProxy struct {
	ln     net.Listener
	target string
	mu     sync.Mutex
	down   bool
	conns  map[net.Conn]bool
}

func newFlakyProxy(t *testing.T, target string) *flakyProxy {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &flakyProxy{ln: ln, target: target, conns: map[net.Conn]bool{}}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			p.mu.Lock()
			down := p.down
			if !down {
				p.conns[c] = true
			}
			p.mu.Unlock()
			if down {
				c.Close() // accepted then dropped: the nastier failure mode
				continue
			}
			go p.pipe(c)
		}
	}()
	t.Cleanup(func() { ln.Close(); p.setDown(true) })
	return p
}

func (p *flakyProxy) pipe(c net.Conn) {
	u, err := net.Dial("tcp", p.target)
	if err != nil {
		c.Close()
		return
	}
	p.mu.Lock()
	p.conns[u] = true
	p.mu.Unlock()
	go func() { _, _ = io.Copy(u, c); u.Close() }()
	_, _ = io.Copy(c, u)
	c.Close()
}

func (p *flakyProxy) setDown(down bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.down = down
	if down {
		for c := range p.conns {
			c.Close()
		}
		p.conns = map[net.Conn]bool{}
	}
}

func TestPostgresOutageReturns503(t *testing.T) {
	if testStore == nil {
		t.Skip("TEST_DATABASE_URL not set")
	}
	dsn, _ := url.Parse(os.Getenv("TEST_DATABASE_URL"))
	proxy := newFlakyProxy(t, dsn.Host)
	dsn.Host = proxy.ln.Addr().String()
	flaky, err := store.OpenPool(context.Background(), dsn.String(), store.Pool{MaxOpen: 4})
	if err != nil {
		t.Fatal(err)
	}
	defer flaky.Close()

	healthy := newEnv(t, generousLimits)
	resetServers(t)
	srv := healthy.healthyServer("pg-out-01", "FI", "203.0.113.60")
	_, tok := healthy.premium(healthy.clock.Now().Add(time.Hour))
	dev := healthy.newDevice(tok)
	acct := healthy.signupLogin()

	e := newEnv(t, generousLimits, func(d *httpapi.Deps) { d.Store = flaky; d.ServerCacheTTL = -1; d.RequestTimeout = 3 * time.Second })
	tok2, _, _ := e.tokens.Issue(acct.id, ids.New())
	_ = tok
	userTok := tok2
	expect(t, e.do("GET", "/v1/me", nil, bearerHdr(userTok)), 200)
	expect(t, e.do("GET", "/readyz", nil, nil), 200)

	proxy.setDown(true)
	start := time.Now()
	calls := []struct {
		method, path string
		body         any
		hdr          map[string]string
	}{
		{"GET", "/v1/me", nil, bearerHdr(userTok)},
		{"GET", "/v1/servers", nil, bearerHdr(userTok)},
		{"GET", "/v1/devices", nil, bearerHdr(userTok)},
		{"POST", "/v1/auth/login", map[string]string{"email": acct.email, "password": acct.password}, nil},
		{"POST", "/v1/auth/refresh", map[string]string{"refresh_token": acct.refresh}, nil},
		{"POST", "/v1/auth/signup", map[string]string{"email": randEmail(), "password": "correct horse battery staple"}, nil},
		{"GET", "/admin/v1/servers/" + srv + "/peers", nil, bearerHdr(adminToken)},
	}
	for _, c := range calls {
		r := e.do(c.method, c.path, c.body, c.hdr)
		if r.status != http.StatusServiceUnavailable || r.header.Get("Retry-After") == "" || r.errCode(t) != "internal" {
			t.Fatalf("%s %s during outage: %d %v %s", c.method, c.path, r.status, r.header.Get("Retry-After"), r.body)
		}
	}
	r := e.prober("POST", "/internal/v1/servers/heartbeats", map[string]any{"prober_id": "p", "observed_at": time.Now().UTC().Format(time.RFC3339),
		"results": []map[string]any{up(srv, 10, 0.1)}})
	expect(t, r, 503)
	r = e.do("GET", "/readyz", nil, nil)
	expect(t, r, 503)
	if r.json(t)["checks"].(map[string]any)["postgres"] != "unavailable" {
		t.Fatalf("readyz: %s", r.body)
	}
	if time.Since(start) > 30*time.Second {
		t.Fatalf("outage responses took %s", time.Since(start))
	}
	if e.metrics.Shed.Value("db_unavailable") == 0 {
		t.Fatal("shed metric not counted")
	}

	// Recovery needs no restart: the pool reconnects.
	proxy.setDown(false)
	deadline := time.Now().Add(10 * time.Second)
	for {
		r := e.do("GET", "/v1/me", nil, bearerHdr(userTok))
		if r.status == 200 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no recovery: %d %s", r.status, r.body)
		}
		time.Sleep(100 * time.Millisecond)
	}
	expect(t, e.do("GET", "/readyz", nil, nil), 200)
	_ = dev
}

func TestRedisDownPerContract(t *testing.T) {
	healthy := newEnv(t)
	a := healthy.signupLogin()
	dead := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1", DialTimeout: 200 * time.Millisecond,
		ReadTimeout: 200 * time.Millisecond, PoolTimeout: 200 * time.Millisecond, ContextTimeoutEnabled: true, MaxRetries: -1})
	defer dead.Close()
	e := newEnv(t, func(d *httpapi.Deps) { d.Redis = dead; d.Limiter = ratelimit.NewRedis(dead, "x:") })
	start := time.Now()
	r := e.do("POST", "/v1/auth/login", map[string]string{"email": a.email, "password": a.password}, nil)
	expect(t, r, 503) // auth fails closed
	if r.header.Get("Retry-After") == "" {
		t.Fatal("no Retry-After")
	}
	expect(t, e.do("GET", "/v1/me", nil, bearerHdr(a.access)), 200) // the rest fails open
	r = e.do("GET", "/readyz", nil, nil)
	expect(t, r, 503)
	if r.json(t)["checks"].(map[string]any)["redis"] != "unavailable" {
		t.Fatalf("readyz: %s", r.body)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("a dead Redis must degrade quickly, took %s", d)
	}
}

// TestPasswordHashingSaturationSheds: beyond the argon2 admission limits a
// login gets 503 + Retry-After at once instead of queueing without bound.
func TestPasswordHashingSaturationSheds(t *testing.T) {
	heavy := auth.NewHasherWithLimits(auth.Argon2Params{MemoryKiB: 16 * 1024, Iterations: 3, Parallelism: 1, SaltLen: 16, KeyLen: 32},
		auth.HashLimits{Concurrency: 1, Queue: 1, QueueTimeout: time.Millisecond})
	e := newEnv(t, generousLimits, func(d *httpapi.Deps) { d.Hasher = heavy })
	const n = 10
	accts := make([]account, n)
	for i := range accts {
		accts[i] = account{email: randEmail(), password: "correct horse battery staple"}
		expect(t, e.do("POST", "/v1/auth/signup", map[string]string{"email": accts[i].email, "password": accts[i].password}, nil), 201)
	}
	var mu sync.Mutex
	codes := map[int]int{}
	var wg sync.WaitGroup
	for _, a := range accts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			buf, _ := json.Marshal(map[string]string{"email": a.email, "password": a.password})
			res, err := http.Post(e.srv.URL+"/v1/auth/login", "application/json", bytes.NewReader(buf))
			if err != nil {
				t.Error(err)
				return
			}
			res.Body.Close()
			if res.StatusCode == 503 && res.Header.Get("Retry-After") != "1" {
				t.Error("503 without Retry-After")
			}
			mu.Lock()
			codes[res.StatusCode]++
			mu.Unlock()
		}()
	}
	wg.Wait()
	if codes[200] == 0 || codes[503] == 0 || codes[200]+codes[503] != n {
		t.Fatalf("status mix %v: want some 200 and some 503, nothing else", codes)
	}
	if e.metrics.Shed.Value("argon2_saturated") != float64(codes[503]) {
		t.Fatalf("shed metric %v != %d", e.metrics.Shed.Value("argon2_saturated"), codes[503])
	}
}

// ---- server list snapshot -----------------------------------------------------

func TestServerListCache(t *testing.T) {
	e := newEnv(t)
	resetServers(t)
	_, tok := e.premium(e.clock.Now().Add(time.Hour))
	h := bearerHdr(tok)
	expect(t, e.do("GET", "/v1/servers", nil, h), 200) // warm an empty snapshot
	id := e.healthyServer("cache-01", "NO", "203.0.113.70")
	// Writes through this replica invalidate at once.
	r := e.do("GET", "/v1/servers", nil, h)
	expect(t, r, 200)
	if l := r.list(t); len(l) != 1 || l[0]["healthy"] != true {
		t.Fatalf("after heartbeat: %s", r.body)
	}
	etag := r.header.Get("ETag")
	if etag == "" {
		t.Fatal("no ETag")
	}
	h304 := map[string]string{"Authorization": "Bearer " + tok, "If-None-Match": etag}
	expect(t, e.do("GET", "/v1/servers", nil, h304), http.StatusNotModified)

	// gzip, byte-identical once decompressed.
	req, _ := http.NewRequest("GET", e.srv.URL+"/v1/servers", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Accept-Encoding", "gzip")
	res, err := (&http.Transport{DisableCompression: true}).RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	zr, err := gzip.NewReader(res.Body)
	if err != nil || res.Header.Get("Content-Encoding") != "gzip" {
		t.Fatalf("gzip: %v %v", err, res.Header)
	}
	unz, _ := io.ReadAll(zr)
	res.Body.Close()
	if !bytes.Equal(unz, r.body) {
		t.Fatal("gzip body differs")
	}

	// The 90 s silence rule still holds with a cached snapshot.
	e.clock.Advance(91 * time.Second)
	if l := e.do("GET", "/v1/servers", nil, h).list(t); l[0]["healthy"] != false {
		t.Fatalf("silent server still healthy: %v", l)
	}
	e.clock.Advance(-91 * time.Second)
	// Unreachable x3 through the API flips it immediately.
	for i := 0; i < 3; i++ {
		expect(t, e.heartbeat(map[string]any{"server_id": id, "reachable": false}), 202)
	}
	if l := e.do("GET", "/v1/servers", nil, h).list(t); l[0]["healthy"] != false {
		t.Fatalf("unreachable server still healthy: %v", l)
	}

	// A write on another replica (here: straight to the DB) shows up within
	// one TTL.
	short := newEnv(t, func(d *httpapi.Deps) { d.ServerCacheTTL = 50 * time.Millisecond })
	tokS, _, _ := short.tokens.Issue(ids.New(), ids.New())
	expect(t, short.do("GET", "/v1/servers", nil, bearerHdr(tokS)), 200)
	if _, err := testStore.DB().Exec(`UPDATE servers SET city = 'Elsewhere' WHERE id = $1`, id); err != nil {
		t.Fatal(err)
	}
	time.Sleep(80 * time.Millisecond)
	if l := short.do("GET", "/v1/servers", nil, bearerHdr(tokS)).list(t); l[0]["city"] != "Elsewhere" {
		t.Fatalf("snapshot not refreshed after TTL: %v", l)
	}
}

// ---- janitor ------------------------------------------------------------------

func TestCleanupIsSingletonAndBatched(t *testing.T) {
	if testStore == nil {
		t.Skip("TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	uid := ids.New()
	if err := testStore.CreateUser(ctx, uid, randEmail(), "x"); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	fam := ids.New()
	for i := 0; i < 12; i++ {
		_, h := auth.NewRefreshToken()
		exp := now.Add(-48 * time.Hour) // long expired
		if i >= 10 {
			exp = now.Add(time.Hour) // live
		}
		if err := testStore.CreateRefreshToken(ctx, ids.New(), uid, fam, h, exp); err != nil {
			t.Fatal(err)
		}
	}
	count := func() (n int) {
		_ = testStore.DB().QueryRow(`SELECT count(*) FROM refresh_tokens WHERE user_id = $1`, uid).Scan(&n)
		return n
	}
	if _, err := testStore.DB().Exec(`DELETE FROM maintenance_leases`); err != nil {
		t.Fatal(err)
	}
	// Another replica holds the lease: this one skips.
	if ok, err := testStore.AcquireLease(ctx, store.JanitorLease, "replica-b", time.Hour); err != nil || !ok {
		t.Fatalf("acquire: %v %v", ok, err)
	}
	if _, ran, err := testStore.Cleanup(ctx, now, "replica-a", time.Hour); err != nil || ran {
		t.Fatalf("ran while leased elsewhere: %v %v", ran, err)
	}
	if count() != 12 {
		t.Fatal("deleted while not holding the lease")
	}
	if err := testStore.ReleaseLease(ctx, store.JanitorLease, "replica-b"); err != nil {
		t.Fatal(err)
	}
	st, ran, err := testStore.Cleanup(ctx, now, "replica-a", time.Hour)
	if err != nil || !ran || st.ExpiredTokens < 10 {
		t.Fatalf("cleanup: %+v %v %v", st, ran, err)
	}
	if count() != 2 {
		t.Fatalf("%d tokens left, want the 2 live ones", count())
	}
	// The lease now covers the next hour for everyone, this replica included.
	for _, h := range []string{"replica-a", "replica-b"} {
		if _, ran, err := testStore.Cleanup(ctx, now, h, time.Hour); err != nil || ran {
			t.Fatalf("%s ran again within the interval: %v %v", h, ran, err)
		}
	}
	// Once it expires, whoever comes next runs.
	if _, err := testStore.DB().Exec(`UPDATE maintenance_leases SET expires_at = now() - interval '1 second'`); err != nil {
		t.Fatal(err)
	}
	if st, ran, err := testStore.Cleanup(ctx, now, "replica-b", time.Hour); err != nil || !ran || st.ExpiredTokens != 0 {
		t.Fatalf("after expiry: %+v %v %v", st, ran, err)
	}
	// Concurrent contenders: exactly one wins.
	if _, err := testStore.DB().Exec(`DELETE FROM maintenance_leases`); err != nil {
		t.Fatal(err)
	}
	var wins atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if ok, err := testStore.AcquireLease(ctx, "contended", fmt.Sprint("r", i), time.Minute); err == nil && ok {
				wins.Add(1)
			}
		}()
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("%d replicas won the lease", wins.Load())
	}
}

// ---- heartbeat batch semantics -------------------------------------------------

func TestHeartbeatBatchSemantics(t *testing.T) {
	e := newEnv(t)
	resetServers(t)
	id := e.createServer("hb-01", "PL", "203.0.113.80", "")["id"].(string)
	id2 := e.createServer("hb-02", "PL", "203.0.113.81", "")["id"].(string)
	// Two reachable results for one server in one batch apply in order
	// (healthy after 2), unknown ids are skipped, a null load keeps the old one.
	r := e.heartbeat(up(id, 10, 0.3), up(ids.New(), 1, 0), map[string]any{"server_id": id, "reachable": true, "rtt_ms_p50": 12.0, "load": nil},
		map[string]any{"server_id": id2, "reachable": false})
	expect(t, r, 202)
	if r.json(t)["accepted"].(float64) != 3 {
		t.Fatalf("accepted: %s", r.body)
	}
	_, tok := e.premium(e.clock.Now().Add(time.Hour))
	byName := map[string]map[string]any{}
	for _, s := range e.do("GET", "/v1/servers", nil, bearerHdr(tok)).list(t) {
		byName[s["name"].(string)] = s
	}
	if byName["hb-01"]["healthy"] != true || byName["hb-01"]["load"].(float64) != 0.3 || byName["hb-02"]["healthy"] != false {
		t.Fatalf("servers: %v", byName)
	}
	var p50 float64
	var cr int
	_ = testStore.DB().QueryRow(`SELECT rtt_ms_p50, consecutive_reachable FROM servers WHERE id = $1`, id).Scan(&p50, &cr)
	if p50 != 12 || cr != 2 {
		t.Fatalf("p50 %v reach %d", p50, cr)
	}
	expect(t, e.heartbeat(), 202) // empty batch
}

// ---- hostile request bodies -----------------------------------------------------

// TestHostileBodiesNever5xx throws malformed and adversarial JSON at every
// endpoint that takes a body. None may produce a 5xx.
func TestHostileBodiesNever5xx(t *testing.T) {
	e := newEnv(t, generousLimits)
	resetServers(t)
	uid, tok := e.premium(e.clock.Now().Add(time.Hour))
	dev := e.newDevice(tok)
	e.healthyServer("hostile-01", "DE", "203.0.113.90")
	deep := strings.Repeat("[", 20000) + strings.Repeat("]", 20000)
	deepObj := strings.Repeat(`{"a":`, 5000) + "1" + strings.Repeat("}", 5000)
	str := func(v string) string { b, _ := json.Marshal(v); return string(b) }
	values := []string{
		`1e400`, `-1e400`, `123456789012345678901234567890`, `-0`, `1.5`, `true`, `null`, `[]`, `{}`,
		`"\u0000"`, `"a\u0000b"`, `"\ud800"`, `"\udfff\ud800"`, "\"\xff\xfe\xfd\"", "\"\xc3\x28\"", `"‮​"`,
		str(strings.Repeat("x", 60000)), `"0000-01-01T00:00:00Z"`, `"9999-12-31T23:59:59Z"`, `"0001-01-01T00:00:00Z"`,
		`"2026-13-45T25:61:61Z"`, `"10000-01-01T00:00:00Z"`, `"-0001-01-01T00:00:00Z"`, deep, deepObj,
	}
	fields := map[string][]string{
		"/v1/auth/signup":                 {"email", "password"},
		"/v1/auth/login":                  {"email", "password"},
		"/v1/auth/refresh":                {"refresh_token"},
		"/v1/devices":                     {"name", "platform", "wg_public_key"},
		"/v1/devices/" + dev + "/config":  {"country"},
		"/admin/v1/servers":               {"name", "country", "city", "public_ipv4", "wg_port", "wg_public_key", "ss_port", "ss_master_secret"},
		"/internal/v1/entitlements":       {"event_id", "source", "user_id", "product_id", "status", "expires_at", "original_transaction_id", "occurred_at"},
		"/internal/v1/servers/heartbeats": {"prober_id", "observed_at", "results"},
	}
	valid := map[string]map[string]string{
		"/v1/auth/signup":                {"email": str(randEmail()), "password": str("correct horse battery staple")},
		"/v1/auth/login":                 {"email": str(randEmail()), "password": str("correct horse battery staple")},
		"/v1/auth/refresh":               {"refresh_token": str("x")},
		"/v1/devices":                    {"name": str("n"), "platform": str("ios"), "wg_public_key": str(wgKey())},
		"/v1/devices/" + dev + "/config": {"country": str("DE")},
		"/admin/v1/servers": {"name": str("h-x"), "country": str("DE"), "city": str("c"), "public_ipv4": str("203.0.113.91"),
			"wg_port": "51820", "wg_public_key": str(wgKey()), "ss_port": "8443"},
		"/internal/v1/entitlements": {"event_id": str("evt_h_" + ids.New()), "source": str("stripe"), "user_id": str(uid), "product_id": str("p"),
			"status": str("active"), "expires_at": str("2030-01-01T00:00:00Z"), "original_transaction_id": str("o"), "occurred_at": str("2026-01-01T00:00:00Z")},
		"/internal/v1/servers/heartbeats": {"prober_id": str("p"), "observed_at": str("2026-01-01T00:00:00Z"), "results": "[]"},
	}
	send := func(path string, body []byte) resp {
		switch {
		case strings.HasPrefix(path, "/internal/"):
			svc, secret := svcauth.ServiceBilling, billingSecret
			if strings.Contains(path, "heartbeats") {
				svc, secret = svcauth.ServiceProber, proberSecret
			}
			ts := strconv.FormatInt(e.clock.Now().Unix(), 10)
			return e.do("POST", path, body, map[string]string{svcauth.HeaderService: svc, svcauth.HeaderTimestamp: ts,
				svcauth.HeaderSignature: svcauth.Sign([]byte(secret), ts, "POST", path, body)})
		case strings.HasPrefix(path, "/admin/"):
			return e.do("POST", path, body, bearerHdr(adminToken))
		default:
			return e.do("POST", path, body, bearerHdr(tok))
		}
	}
	for path, fs := range fields {
		raw := [][]byte{[]byte(deep), []byte(deepObj), []byte(`[1,2]`), []byte(`"x"`), []byte(`{} {}`), []byte(`{"a":1`), []byte("\xff\xfe"), []byte(`nul`), []byte(`{"results":[` + strings.Repeat(`{"server_id":"x"},`, 1000) + `{}]}`)}
		for _, b := range raw {
			if r := send(path, b); r.status >= 500 {
				t.Errorf("%s raw %.40q: %d %s", path, b, r.status, r.body)
			}
		}
		for _, f := range fs {
			for _, v := range values {
				obj := map[string]string{}
				for k, vv := range valid[path] {
					obj[k] = vv
				}
				obj[f] = v
				var b strings.Builder
				b.WriteByte('{')
				first := true
				for k, vv := range obj {
					if !first {
						b.WriteByte(',')
					}
					first = false
					b.WriteString(str(k) + ":" + vv)
				}
				b.WriteByte('}')
				if r := send(path, []byte(b.String())); r.status >= 500 {
					t.Errorf("%s %s=%.60q: %d %s", path, f, v, r.status, r.body)
				}
			}
		}
	}
	// Query strings and paths too.
	for _, p := range []string{"/admin/v1/servers/%00/peers", "/admin/v1/servers/" + ids.New() + "/peers?limit=%ff", "/v1/devices/%c3%28/config"} {
		if r := e.do("GET", p, nil, bearerHdr(adminToken)); r.status >= 500 {
			t.Errorf("%s: %d", p, r.status)
		}
	}
}

func TestDrainFailsReadiness(t *testing.T) {
	e := newEnv(t)
	expect(t, e.do("GET", "/readyz", nil, nil), 200)
	e.api.Drain()
	r := e.do("GET", "/readyz", nil, nil)
	expect(t, r, 503)
	if r.json(t)["checks"].(map[string]any)["shutdown"] != "draining" {
		t.Fatalf("readyz while draining: %s", r.body)
	}
	expect(t, e.do("GET", "/healthz", nil, nil), 200) // still alive: in-flight work finishes
}

// TestHeartbeatsDoNotBlockOrDeadlockConfigIssuance: heartbeat batches lock
// server rows while first config issuances insert preshared keys whose
// foreign keys share-lock the same rows. With FOR UPDATE in the heartbeat
// path these deadlocked (500 after deadlock_timeout) under load; FOR NO KEY
// UPDATE does not conflict with FK checks at all.
func TestHeartbeatsDoNotBlockOrDeadlockConfigIssuance(t *testing.T) {
	e := newEnv(t, generousLimits, func(d *httpapi.Deps) { d.ServerCacheTTL = time.Minute })
	resetServers(t)
	var sids []string
	for i := 0; i < 24; i++ {
		sids = append(sids, e.createServer(fmt.Sprintf("dl-%02d", i), "CZ", fmt.Sprintf("203.0.113.%d", 100+i), "")["id"].(string))
	}
	batch := func() []map[string]any {
		var rs []map[string]any
		for i, id := range sids {
			// Scores vary so the top 3 are not in id order.
			rs = append(rs, up(id, float64((i*7)%24), 0.1))
		}
		return rs
	}
	expect(t, e.heartbeat(batch()...), 202)
	expect(t, e.heartbeat(batch()...), 202)
	type dev struct{ tok, id string }
	var devs []dev
	for i := 0; i < 128; i++ {
		_, tok := e.premium(e.clock.Now().Add(time.Hour))
		devs = append(devs, dev{tok, e.newDevice(tok)})
	}
	stop := make(chan struct{})
	var hbWG sync.WaitGroup
	for w := 0; w < 2; w++ {
		hbWG.Add(1)
		go func() {
			defer hbWG.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				buf, _ := json.Marshal(map[string]any{"prober_id": "p", "observed_at": time.Now().UTC().Format(time.RFC3339), "results": batch()})
				ts := strconv.FormatInt(e.clock.Now().Unix(), 10)
				req, _ := http.NewRequest("POST", e.srv.URL+"/internal/v1/servers/heartbeats", bytes.NewReader(buf))
				req.Header.Set(svcauth.HeaderService, svcauth.ServiceProber)
				req.Header.Set(svcauth.HeaderTimestamp, ts)
				req.Header.Set(svcauth.HeaderSignature, svcauth.Sign([]byte(proberSecret), ts, "POST", "/internal/v1/servers/heartbeats", buf))
				if res, err := http.DefaultClient.Do(req); err == nil {
					if res.StatusCode != 202 {
						t.Errorf("heartbeat %d", res.StatusCode)
					}
					res.Body.Close()
				}
			}
		}()
	}
	var wg sync.WaitGroup
	var slow sync.Map
	for _, d := range devs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Each country choice ranks a different trio, so every call
			// inserts fresh keys.
			start := time.Now()
			req, _ := http.NewRequest("POST", e.srv.URL+"/v1/devices/"+d.id+"/config", strings.NewReader(`{}`))
			req.Header.Set("Authorization", "Bearer "+d.tok)
			res, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Error(err)
				return
			}
			b, _ := io.ReadAll(res.Body)
			res.Body.Close()
			if res.StatusCode != 200 {
				t.Errorf("config %d: %s", res.StatusCode, b)
			}
			if el := time.Since(start); el > 900*time.Millisecond {
				slow.Store(d.id, el) // waited for deadlock_timeout (1 s)
			}
		}()
	}
	wg.Wait()
	close(stop)
	hbWG.Wait()
	slow.Range(func(k, v any) bool { t.Errorf("config for %v took %v (lock wait)", k, v); return true })
}
