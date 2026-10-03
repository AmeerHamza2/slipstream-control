package httpapi_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/redis/go-redis/v9"

	"github.com/ameerhamza2/slipstream-control/api"
	"github.com/ameerhamza2/slipstream-control/internal/auth"
	"github.com/ameerhamza2/slipstream-control/internal/crypto"
	"github.com/ameerhamza2/slipstream-control/internal/httpapi"
	"github.com/ameerhamza2/slipstream-control/internal/ids"
	"github.com/ameerhamza2/slipstream-control/internal/metrics"
	"github.com/ameerhamza2/slipstream-control/internal/ratelimit"
	"github.com/ameerhamza2/slipstream-control/internal/store"
	"github.com/ameerhamza2/slipstream-control/internal/svcauth"
)

var (
	testStore *store.Store
	testRedis *redis.Client
)

const (
	adminToken    = "test-admin-token-0123456789abcdef0123456789"
	billingSecret = "test-billing-secret-0123456789abcdef"
	proberSecret  = "test-prober-secret-0123456789abcdef"
)

func TestMain(m *testing.M) {
	dsn, rurl := os.Getenv("TEST_DATABASE_URL"), os.Getenv("TEST_REDIS_URL")
	if dsn == "" || rurl == "" {
		fmt.Println("TEST_DATABASE_URL / TEST_REDIS_URL not set: integration tests will be skipped")
		os.Exit(m.Run())
	}
	ctx := context.Background()
	var err error
	if testStore, err = store.Open(ctx, dsn); err != nil {
		fmt.Println("open db:", err)
		os.Exit(1)
	}
	if _, err := testStore.Migrate(ctx); err != nil {
		fmt.Println("migrate:", err)
		os.Exit(1)
	}
	// Migrating twice must be a no-op.
	if applied, err := testStore.Migrate(ctx); err != nil || len(applied) != 0 {
		fmt.Println("second migrate not idempotent:", applied, err)
		os.Exit(1)
	}
	if _, err := testStore.DB().ExecContext(ctx, `TRUNCATE users, refresh_tokens, devices, servers, device_server_keys, entitlement_events, subscriptions, peer_tombstones CASCADE`); err != nil {
		fmt.Println("truncate:", err)
		os.Exit(1)
	}
	opt, err := redis.ParseURL(rurl)
	if err != nil {
		fmt.Println("redis url:", err)
		os.Exit(1)
	}
	testRedis = redis.NewClient(opt)
	code := m.Run()
	testRedis.Close()
	testStore.Close()
	os.Exit(code)
}

// clock is a controllable time source shared by the server under test.
type clock struct{ offset atomic.Int64 }

func (c *clock) Now() time.Time          { return time.Now().Add(time.Duration(c.offset.Load())) }
func (c *clock) Advance(d time.Duration) { c.offset.Add(int64(d)) }

type env struct {
	t       *testing.T
	srv     *httptest.Server
	api     *httpapi.Server
	clock   *clock
	metrics *metrics.App
	tokens  *auth.TokenIssuer
}

type envOpt func(*httpapi.Deps)

func newEnv(t *testing.T, opts ...envOpt) *env {
	t.Helper()
	if testStore == nil {
		t.Skip("TEST_DATABASE_URL not set")
	}
	seed := make([]byte, 32)
	copy(seed, "integration-test-seed")
	tokens, err := auth.NewTokenIssuer(seed, nil)
	if err != nil {
		t.Fatal(err)
	}
	kr, err := crypto.NewKeyringFromBase64(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{42}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	clk := &clock{}
	tokens.SetClock(clk.Now)
	verifier := svcauth.NewVerifier(map[string][]byte{svcauth.ServiceBilling: []byte(billingSecret), svcauth.ServiceProber: []byte(proberSecret)})
	verifier.SetClock(clk.Now)
	m := metrics.NewApp()
	d := httpapi.Deps{
		Store:       testStore,
		Redis:       testRedis,
		Limiter:     ratelimit.NewRedis(testRedis, "test:"+ids.New()+":"), // per-test namespace
		Tokens:      tokens,
		Hasher:      auth.NewHasher(auth.Argon2Params{MemoryKiB: 1024, Iterations: 1, Parallelism: 1, SaltLen: 16, KeyLen: 32}, 0),
		Keyring:     kr,
		ServiceAuth: verifier,
		AdminToken:  adminToken,
		Metrics:     m,
		Logger:      slog.New(slog.NewJSONHandler(io.Discard, nil)),
		Limits:      httpapi.DefaultLimits,
		OpenAPI:     api.OpenAPI,
		Now:         clk.Now,
	}
	for _, o := range opts {
		o(&d)
	}
	api := httpapi.New(d)
	srv := httptest.NewServer(api)
	t.Cleanup(srv.Close)
	return &env{t: t, srv: srv, api: api, clock: clk, metrics: m, tokens: tokens}
}

type resp struct {
	status int
	header http.Header
	body   []byte
}

func (r resp) json(t *testing.T) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(r.body, &m); err != nil {
		t.Fatalf("not a JSON object (%d): %s", r.status, r.body)
	}
	return m
}

func (r resp) list(t *testing.T) []map[string]any {
	t.Helper()
	var l []map[string]any
	if err := json.Unmarshal(r.body, &l); err != nil {
		t.Fatalf("not a JSON array (%d): %s", r.status, r.body)
	}
	return l
}

func (r resp) errCode(t *testing.T) string {
	t.Helper()
	e, ok := r.json(t)["error"].(map[string]any)
	if !ok {
		t.Fatalf("no error envelope: %s", r.body)
	}
	if e["request_id"] == "" || e["message"] == "" {
		t.Fatalf("incomplete envelope: %s", r.body)
	}
	return e["code"].(string)
}

func (e *env) do(method, path string, body any, hdr map[string]string) resp {
	e.t.Helper()
	var rdr io.Reader
	switch b := body.(type) {
	case nil:
	case []byte:
		rdr = bytes.NewReader(b)
	case string:
		rdr = strings.NewReader(b)
	default:
		buf, _ := json.Marshal(b)
		rdr = bytes.NewReader(buf)
	}
	req, err := http.NewRequest(method, e.srv.URL+path, rdr)
	if err != nil {
		e.t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	res, err := e.srv.Client().Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	if res.Header.Get("X-Request-Id") == "" {
		e.t.Fatalf("%s %s: missing X-Request-Id", method, path)
	}
	return resp{status: res.StatusCode, header: res.Header, body: b}
}

func bearerHdr(tok string) map[string]string {
	return map[string]string{"Authorization": "Bearer " + tok}
}

func (e *env) signed(service, secret, method, path string, body any) resp {
	e.t.Helper()
	var buf []byte
	if body != nil {
		buf, _ = json.Marshal(body)
	}
	ts := strconv.FormatInt(e.clock.Now().Unix(), 10)
	return e.do(method, path, buf, map[string]string{
		svcauth.HeaderService:   service,
		svcauth.HeaderTimestamp: ts,
		svcauth.HeaderSignature: svcauth.Sign([]byte(secret), ts, method, path, buf),
	})
}

func (e *env) billing(body any) resp {
	return e.signed(svcauth.ServiceBilling, billingSecret, "POST", "/internal/v1/entitlements", body)
}

func (e *env) prober(method, path string, body any) resp {
	return e.signed(svcauth.ServiceProber, proberSecret, method, path, body)
}

func (e *env) admin(method, path string, body any) resp {
	return e.do(method, path, body, bearerHdr(adminToken))
}

func expect(t *testing.T, r resp, status int) {
	t.Helper()
	if r.status != status {
		t.Fatalf("status %d, want %d: %s", r.status, status, r.body)
	}
}

func randEmail() string { return "user-" + ids.New()[:13] + "@example.com" }

type account struct {
	id, email, password, access, refresh string
}

func (e *env) signupLogin() account {
	e.t.Helper()
	a := account{email: randEmail(), password: "correct horse battery staple"}
	r := e.do("POST", "/v1/auth/signup", map[string]string{"email": a.email, "password": a.password}, nil)
	expect(e.t, r, http.StatusCreated)
	a.id = r.json(e.t)["user_id"].(string)
	r = e.do("POST", "/v1/auth/login", map[string]string{"email": a.email, "password": a.password}, nil)
	expect(e.t, r, http.StatusOK)
	m := r.json(e.t)
	a.access, a.refresh = m["access_token"].(string), m["refresh_token"].(string)
	if m["expires_in"].(float64) != 900 {
		e.t.Fatalf("expires_in %v", m["expires_in"])
	}
	return a
}

func wgKey() string { return crypto.GeneratePresharedKey() } // any random 32 bytes is a valid-format key

func (e *env) entitle(userID, status string, expires, occurred time.Time, otid string) resp {
	e.t.Helper()
	return e.billing(map[string]any{
		"event_id": "evt_" + ids.New(), "source": "stripe", "user_id": userID, "product_id": "premium_monthly",
		"status": status, "expires_at": expires.UTC().Format(time.RFC3339), "original_transaction_id": otid,
		"occurred_at": occurred.UTC().Format(time.RFC3339),
	})
}

func resetServers(t *testing.T) {
	t.Helper()
	if _, err := testStore.DB().Exec(`DELETE FROM servers`); err != nil {
		t.Fatal(err)
	}
}

func (e *env) createServer(name, country, ip string, ssSecret string) map[string]any {
	e.t.Helper()
	body := map[string]any{"name": name, "country": country, "city": "Somewhere", "public_ipv4": ip,
		"wg_port": 51820, "wg_public_key": wgKey(), "ss_port": 8443}
	if ssSecret != "" {
		body["ss_master_secret"] = ssSecret
	}
	r := e.admin("POST", "/admin/v1/servers", body)
	expect(e.t, r, http.StatusCreated)
	return r.json(e.t)
}

func (e *env) heartbeat(results ...map[string]any) resp {
	e.t.Helper()
	return e.prober("POST", "/internal/v1/servers/heartbeats", map[string]any{
		"prober_id": "prober-test", "observed_at": e.clock.Now().UTC().Format(time.RFC3339), "results": results})
}

func up(id string, rtt, load float64) map[string]any {
	return map[string]any{"server_id": id, "reachable": true, "rtt_ms_p50": rtt, "rtt_ms_p95": rtt * 1.5, "loss": 0.0, "load": load}
}

func keys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sameKeys(t *testing.T, what string, m map[string]any, want ...string) {
	t.Helper()
	sort.Strings(want)
	if got := keys(m); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("%s keys = %v, want %v", what, got, want)
	}
}

// TestFullFlow walks the whole product: signup to config issuance to expiry.
func TestFullFlow(t *testing.T) {
	e := newEnv(t)
	resetServers(t)
	a := e.signupLogin()
	auth := bearerHdr(a.access)

	// Free account.
	me := e.do("GET", "/v1/me", nil, auth)
	expect(t, me, 200)
	m := me.json(t)
	sameKeys(t, "me", m, "user_id", "email", "plan", "entitlement", "devices_used", "devices_limit")
	if m["plan"] != "free" || m["devices_limit"].(float64) != 0 || m["email"] != a.email || m["user_id"] != a.id {
		t.Fatalf("me (free): %s", me.body)
	}
	ent := m["entitlement"].(map[string]any)
	if ent["active"] != false || ent["expires_at"] != nil || ent["source"] != nil {
		t.Fatalf("free entitlement: %v", ent)
	}

	// Free plan has 0 devices: 402 so the app routes to the paywall.
	devBody := map[string]string{"name": "Pixel 9", "platform": "android", "wg_public_key": wgKey()}
	r := e.do("POST", "/v1/devices", devBody, auth)
	expect(t, r, http.StatusPaymentRequired)
	if r.errCode(t) != "payment_required" {
		t.Fatal(r.errCode(t))
	}

	// Billing grants premium.
	now := e.clock.Now()
	r = e.entitle(a.id, "active", now.Add(30*24*time.Hour), now.Add(-time.Minute), "sub_"+a.id)
	expect(t, r, 200)
	if r.json(t)["applied"] != true {
		t.Fatalf("not applied: %s", r.body)
	}
	m = e.do("GET", "/v1/me", nil, auth).json(t)
	ent = m["entitlement"].(map[string]any)
	if m["plan"] != "premium" || m["devices_limit"].(float64) != 5 || ent["active"] != true || ent["source"] != "stripe" || ent["expires_at"] == nil {
		t.Fatalf("me (premium): %v", m)
	}

	// Device registration.
	r = e.do("POST", "/v1/devices", devBody, auth)
	expect(t, r, http.StatusCreated)
	dev := r.json(t)
	sameKeys(t, "device", dev, "device_id", "tunnel_address")
	deviceID, tunnel := dev["device_id"].(string), dev["tunnel_address"].(string)
	if !strings.HasPrefix(tunnel, "10.") || !strings.HasSuffix(tunnel, "/32") {
		t.Fatalf("tunnel %q", tunnel)
	}
	list := e.do("GET", "/v1/devices", nil, auth).list(t)
	if len(list) != 1 || list[0]["device_id"] != deviceID {
		t.Fatalf("devices: %v", list)
	}
	if e.do("GET", "/v1/me", nil, auth).json(t)["devices_used"].(float64) != 1 {
		t.Fatal("devices_used")
	}

	// No healthy servers yet.
	r = e.do("POST", "/v1/devices/"+deviceID+"/config", nil, auth)
	expect(t, r, http.StatusServiceUnavailable)

	// Admin endpoints require the admin token.
	expect(t, e.do("POST", "/admin/v1/servers", map[string]any{}, nil), 401)
	expect(t, e.do("POST", "/admin/v1/servers", map[string]any{}, bearerHdr("wrong")), 401)
	expect(t, e.do("POST", "/admin/v1/servers", map[string]any{}, auth), 401) // user JWT is not admin

	fra := e.createServer("fra-01", "DE", "203.0.113.10", "")
	ams := e.createServer("ams-01", "NL", "203.0.113.20", "operator-supplied-secret")
	if len(fra["ss_master_secret"].(string)) != 44 || ams["ss_master_secret"] != "operator-supplied-secret" {
		t.Fatalf("ss secrets: %v / %v", fra["ss_master_secret"], ams["ss_master_secret"])
	}
	r = e.admin("POST", "/admin/v1/servers", map[string]any{"name": "fra-01", "country": "DE", "city": "x", "public_ipv4": "203.0.113.11",
		"wg_port": 51820, "wg_public_key": wgKey(), "ss_port": 8443})
	expect(t, r, http.StatusConflict)

	// Prober discovers servers and reports them healthy twice.
	r = e.prober("GET", "/internal/v1/servers", nil)
	expect(t, r, 200)
	isrv := r.list(t)
	if len(isrv) != 2 {
		t.Fatalf("internal servers: %s", r.body)
	}
	sameKeys(t, "internal server", isrv[0], "id", "name", "public_ipv4", "wg_port", "ss_port")
	fraID, amsID := fra["id"].(string), ams["id"].(string)
	for i := 0; i < 2; i++ {
		r = e.heartbeat(up(fraID, 40, 0.2), up(amsID, 20, 0.1), up(ids.New(), 1, 0))
		expect(t, r, http.StatusAccepted)
		if r.json(t)["accepted"].(float64) != 2 {
			t.Fatalf("accepted: %s", r.body)
		}
	}
	pub := e.do("GET", "/v1/servers", nil, auth).list(t)
	if len(pub) != 2 {
		t.Fatalf("public servers %v", pub)
	}
	for _, s := range pub {
		sameKeys(t, "public server", s, "id", "name", "country", "city", "protocols", "load", "healthy")
		if s["healthy"] != true {
			t.Fatalf("not healthy: %v", s)
		}
	}

	// Config issuance (country filter prefers DE even though NL scores better).
	r = e.do("POST", "/v1/devices/"+deviceID+"/config", map[string]string{"country": "de"}, auth)
	expect(t, r, 200)
	if r.header.Get("Cache-Control") != "no-store" {
		t.Fatal("config must not be cacheable")
	}
	cfg := r.json(t)
	sameKeys(t, "config", cfg, "servers", "tunnel_addresses", "dns_servers", "mtu")
	if cfg["mtu"].(float64) != 1420 || fmt.Sprint(cfg["dns_servers"]) != "[10.64.0.1]" || fmt.Sprint(cfg["tunnel_addresses"]) != "["+tunnel+"]" {
		t.Fatalf("config: %s", r.body)
	}
	entries := cfg["servers"].([]any)
	if len(entries) != 2 {
		t.Fatalf("want 1 server x 2 protocols for DE, got %d", len(entries))
	}
	wg, ss := entries[0].(map[string]any), entries[1].(map[string]any)
	sameKeys(t, "wireguard entry", wg, "name", "protocol", "endpoint", "public_key", "preshared_key", "keepalive_seconds")
	sameKeys(t, "shadowsocks entry", ss, "name", "protocol", "endpoint", "method", "password")
	if wg["name"] != "fra-01" || wg["protocol"] != "wireguard" || wg["endpoint"] != "203.0.113.10:51820" || wg["public_key"] != fra["wg_public_key"] || wg["keepalive_seconds"].(float64) != 25 {
		t.Fatalf("wg entry: %v", wg)
	}
	if !crypto.ValidWireGuardKey(wg["preshared_key"].(string)) {
		t.Fatal("psk format")
	}
	wantPW := crypto.ShadowsocksPassword([]byte(fra["ss_master_secret"].(string)), a.id)
	if ss["name"] != "fra-01-ss" || ss["protocol"] != "shadowsocks" || ss["endpoint"] != "203.0.113.10:8443" || ss["method"] != "chacha20-ietf-poly1305" || ss["password"] != wantPW || len(wantPW) != 44 {
		t.Fatalf("ss entry: %v", ss)
	}

	// Global ranking: ams (20+40) beats fra (40+80); PSKs are stable per (device, server).
	r = e.do("POST", "/v1/devices/"+deviceID+"/config", nil, auth)
	expect(t, r, 200)
	entries = r.json(t)["servers"].([]any)
	if len(entries) != 4 {
		t.Fatalf("want 2 servers x 2 protocols, got %d", len(entries))
	}
	order := []string{}
	for _, en := range entries {
		order = append(order, en.(map[string]any)["name"].(string))
	}
	if strings.Join(order, ",") != "ams-01,ams-01-ss,fra-01,fra-01-ss" {
		t.Fatalf("order %v", order)
	}
	if entries[2].(map[string]any)["preshared_key"] != wg["preshared_key"] {
		t.Fatal("psk changed between issuances")
	}
	if entries[0].(map[string]any)["preshared_key"] == wg["preshared_key"] {
		t.Fatal("psk shared between servers")
	}
	// The PSK is stored encrypted, never in plaintext.
	var enc string
	if err := testStore.DB().QueryRow(`SELECT psk_enc FROM device_server_keys WHERE device_id=$1 AND server_id=$2`, deviceID, fraID).Scan(&enc); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(enc, "v1:") || strings.Contains(enc, wg["preshared_key"].(string)) {
		t.Fatalf("psk at rest: %q", enc)
	}

	// Node agent pulls peers.
	r = e.admin("GET", "/admin/v1/servers/"+fraID+"/peers", nil)
	expect(t, r, 200)
	peers := r.list(t)
	if len(peers) != 1 {
		t.Fatalf("peers: %s", r.body)
	}
	sameKeys(t, "peer", peers[0], "device_id", "wg_public_key", "tunnel_address", "preshared_key")
	if peers[0]["device_id"] != deviceID || peers[0]["preshared_key"] != wg["preshared_key"] || peers[0]["tunnel_address"] != tunnel || peers[0]["wg_public_key"] != devBody["wg_public_key"] {
		t.Fatalf("peer: %v", peers[0])
	}
	expect(t, e.admin("GET", "/admin/v1/servers/"+ids.New()+"/peers", nil), 404)

	// Subscription expires: config is refused and the node drops the peer.
	r = e.entitle(a.id, "expired", now.Add(-time.Second), now, "sub_"+a.id)
	expect(t, r, 200)
	if r.json(t)["applied"] != true {
		t.Fatalf("expire not applied: %s", r.body)
	}
	r = e.do("POST", "/v1/devices/"+deviceID+"/config", nil, auth)
	expect(t, r, http.StatusPaymentRequired)
	if r.errCode(t) != "payment_required" {
		t.Fatal("code")
	}
	if m := e.do("GET", "/v1/me", nil, auth).json(t); m["plan"] != "free" || m["entitlement"].(map[string]any)["active"] != false {
		t.Fatalf("me after expiry: %v", m)
	}
	if peers := e.admin("GET", "/admin/v1/servers/"+fraID+"/peers", nil).list(t); len(peers) != 0 {
		t.Fatalf("lapsed peer still listed: %v", peers)
	}

	// Delete the device.
	expect(t, e.do("DELETE", "/v1/devices/"+deviceID, nil, auth), http.StatusNoContent)
	expect(t, e.do("DELETE", "/v1/devices/"+deviceID, nil, auth), http.StatusNotFound)
}

func TestEntitlementIdempotencyAndOrdering(t *testing.T) {
	e := newEnv(t)
	a := e.signupLogin()
	now := e.clock.Now()
	otid := "txn_" + ids.New()
	ev := map[string]any{"event_id": "evt_" + ids.New(), "source": "app_store", "user_id": a.id, "product_id": "premium_monthly",
		"status": "active", "expires_at": now.Add(time.Hour).UTC().Format(time.RFC3339), "original_transaction_id": otid,
		"occurred_at": now.UTC().Format(time.RFC3339)}

	if r := e.billing(ev); r.json(t)["applied"] != true {
		t.Fatalf("first: %s", r.body)
	}
	r := e.billing(ev)
	expect(t, r, 200)
	if m := r.json(t); m["applied"] != false || m["reason"] != "duplicate" {
		t.Fatalf("duplicate: %s", r.body)
	}

	// A refund that happened later arrives first...
	refund := map[string]any{}
	for k, v := range ev {
		refund[k] = v
	}
	refund["event_id"], refund["status"], refund["occurred_at"] = "evt_"+ids.New(), "refunded", now.Add(10*time.Minute).UTC().Format(time.RFC3339)
	if r := e.billing(refund); r.json(t)["applied"] != true {
		t.Fatalf("refund: %s", r.body)
	}
	// ...then a delayed, older renewal must not resurrect the subscription.
	old := map[string]any{}
	for k, v := range ev {
		old[k] = v
	}
	old["event_id"], old["occurred_at"] = "evt_"+ids.New(), now.Add(5*time.Minute).UTC().Format(time.RFC3339)
	r = e.billing(old)
	if m := r.json(t); m["applied"] != false || m["reason"] != "stale" {
		t.Fatalf("stale: %s", r.body)
	}
	if m := e.do("GET", "/v1/me", nil, bearerHdr(a.access)).json(t); m["plan"] != "free" {
		t.Fatalf("stale event resurrected plan: %v", m)
	}
	// Stale and duplicate events are recorded for audit.
	var n int
	_ = testStore.DB().QueryRow(`SELECT count(*) FROM entitlement_events WHERE original_transaction_id=$1`, otid).Scan(&n)
	if n != 3 {
		t.Fatalf("recorded %d events", n)
	}
	if v := e.metrics.EntitlementEvents.Value("app_store", "stale"); v != 1 {
		t.Fatalf("stale metric %v", v)
	}

	// Validation and auth.
	bad := map[string]any{"event_id": "evt_x", "source": "paypal"}
	expect(t, e.billing(bad), 400)
	ev["event_id"], ev["user_id"] = "evt_"+ids.New(), ids.New()
	expect(t, e.billing(ev), 404)
	expect(t, e.prober("POST", "/internal/v1/entitlements", ev), 403) // prober cannot grant entitlements
	expect(t, e.signed(svcauth.ServiceBilling, "wrong-secret", "POST", "/internal/v1/entitlements", ev), 401)
	expect(t, e.do("POST", "/internal/v1/entitlements", ev, nil), 401)
	expect(t, e.billing(map[string]any{}), 400)

	// Concurrent deliveries of one event apply exactly once.
	ev["event_id"], ev["user_id"] = "evt_"+ids.New(), a.id
	ev["original_transaction_id"] = "txn_" + ids.New()
	var applied atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			buf, _ := json.Marshal(ev)
			ts := strconv.FormatInt(time.Now().Unix(), 10)
			req, _ := http.NewRequest("POST", e.srv.URL+"/internal/v1/entitlements", bytes.NewReader(buf))
			req.Header.Set(svcauth.HeaderService, svcauth.ServiceBilling)
			req.Header.Set(svcauth.HeaderTimestamp, ts)
			req.Header.Set(svcauth.HeaderSignature, svcauth.Sign([]byte(billingSecret), ts, "POST", "/internal/v1/entitlements", buf))
			res, err := http.DefaultClient.Do(req)
			if err != nil {
				return
			}
			defer res.Body.Close()
			var m map[string]any
			_ = json.NewDecoder(res.Body).Decode(&m)
			if m["applied"] == true {
				applied.Add(1)
			}
		}()
	}
	wg.Wait()
	if applied.Load() != 1 {
		t.Fatalf("applied %d times", applied.Load())
	}
}

func TestServiceAuthSkew(t *testing.T) {
	e := newEnv(t)
	path := "/internal/v1/servers"
	ts := strconv.FormatInt(e.clock.Now().Add(-301*time.Second).Unix(), 10)
	r := e.do("GET", path, nil, map[string]string{svcauth.HeaderService: svcauth.ServiceProber, svcauth.HeaderTimestamp: ts,
		svcauth.HeaderSignature: svcauth.Sign([]byte(proberSecret), ts, "GET", path, nil)})
	expect(t, r, 401)
	// Query string is not part of the signed path.
	ts = strconv.FormatInt(e.clock.Now().Unix(), 10)
	r = e.do("GET", path+"?x=1", nil, map[string]string{svcauth.HeaderService: svcauth.ServiceProber, svcauth.HeaderTimestamp: ts,
		svcauth.HeaderSignature: svcauth.Sign([]byte(proberSecret), ts, "GET", path, nil)})
	expect(t, r, 200)
	expect(t, e.billing(nil), 400) // billing may call entitlements, but body is required
	r = e.signed(svcauth.ServiceBilling, billingSecret, "POST", "/internal/v1/servers/heartbeats", map[string]any{})
	expect(t, r, 403)
}

func TestRefreshRotationAndReuseDetection(t *testing.T) {
	e := newEnv(t)
	a := e.signupLogin()

	r := e.do("POST", "/v1/auth/refresh", map[string]string{"refresh_token": a.refresh}, nil)
	expect(t, r, 200)
	p1 := r.json(t)
	sameKeys(t, "token pair", p1, "access_token", "refresh_token", "expires_in")
	if p1["refresh_token"] == a.refresh {
		t.Fatal("refresh token not rotated")
	}
	r = e.do("POST", "/v1/auth/refresh", map[string]string{"refresh_token": p1["refresh_token"].(string)}, nil)
	expect(t, r, 200)
	p2 := r.json(t)

	// Attacker replays the first (rotated) token: 401 and the family dies...
	r = e.do("POST", "/v1/auth/refresh", map[string]string{"refresh_token": a.refresh}, nil)
	expect(t, r, 401)
	// ...so even the legitimate latest token is now rejected.
	r = e.do("POST", "/v1/auth/refresh", map[string]string{"refresh_token": p2["refresh_token"].(string)}, nil)
	expect(t, r, 401)

	// Other sessions (families) of the same user are unaffected.
	r = e.do("POST", "/v1/auth/login", map[string]string{"email": a.email, "password": a.password}, nil)
	expect(t, r, 200)
	s2 := r.json(t)
	r = e.do("POST", "/v1/auth/refresh", map[string]string{"refresh_token": s2["refresh_token"].(string)}, nil)
	expect(t, r, 200)
	s3 := r.json(t)

	// Logout revokes the current family.
	expect(t, e.do("POST", "/v1/auth/logout", nil, bearerHdr(s3["access_token"].(string))), 204)
	expect(t, e.do("POST", "/v1/auth/refresh", map[string]string{"refresh_token": s3["refresh_token"].(string)}, nil), 401)

	// Garbage and expired tokens.
	expect(t, e.do("POST", "/v1/auth/refresh", map[string]string{"refresh_token": "nope"}, nil), 401)
	r = e.do("POST", "/v1/auth/login", map[string]string{"email": a.email, "password": a.password}, nil)
	old := r.json(t)["refresh_token"].(string)
	e.clock.Advance(auth.RefreshTokenTTL + time.Minute)
	expect(t, e.do("POST", "/v1/auth/refresh", map[string]string{"refresh_token": old}, nil), 401)
}

func TestAuthValidationAndJWT(t *testing.T) {
	e := newEnv(t)
	email := randEmail()
	expect(t, e.do("POST", "/v1/auth/signup", map[string]string{"email": email, "password": "short"}, nil), 400)
	expect(t, e.do("POST", "/v1/auth/signup", map[string]string{"email": "not-an-email", "password": "long enough password"}, nil), 400)
	expect(t, e.do("POST", "/v1/auth/signup", map[string]any{"email": email, "password": "long enough password", "admin": true}, nil), 400)
	expect(t, e.do("POST", "/v1/auth/signup", `{"email":`, nil), 400)
	expect(t, e.do("POST", "/v1/auth/signup", map[string]string{"email": strings.ToUpper(email), "password": "long enough password"}, nil), 201)
	r := e.do("POST", "/v1/auth/signup", map[string]string{"email": email, "password": "long enough password"}, nil)
	expect(t, r, 409)
	if r.errCode(t) != "conflict" {
		t.Fatal("code")
	}
	expect(t, e.do("POST", "/v1/auth/login", map[string]string{"email": email, "password": "wrong password!!"}, nil), 401)
	expect(t, e.do("POST", "/v1/auth/login", map[string]string{"email": randEmail(), "password": "whatever password"}, nil), 401)
	r = e.do("POST", "/v1/auth/login", map[string]string{"email": email, "password": "long enough password"}, nil)
	expect(t, r, 200)
	access := r.json(t)["access_token"].(string)

	// Body size limit.
	big := `{"email":"` + strings.Repeat("a", 70<<10) + `","password":"x"}`
	expect(t, e.do("POST", "/v1/auth/login", big, nil), http.StatusRequestEntityTooLarge)

	// The token verifies against the published JWKS (what billing-webhooks does).
	r = e.do("GET", "/.well-known/jwks.json", nil, nil)
	expect(t, r, 200)
	var jwks struct {
		Keys []struct{ Kty, Crv, X, Kid, Alg string }
	}
	_ = json.Unmarshal(r.body, &jwks)
	if len(jwks.Keys) != 1 || jwks.Keys[0].Kty != "OKP" || jwks.Keys[0].Crv != "Ed25519" {
		t.Fatalf("jwks: %s", r.body)
	}
	x, _ := base64.RawURLEncoding.DecodeString(jwks.Keys[0].X)
	claims := jwt.MapClaims{}
	tok, err := jwt.ParseWithClaims(access, claims, func(tk *jwt.Token) (any, error) {
		if tk.Header["kid"] != jwks.Keys[0].Kid {
			return nil, errors.New("kid mismatch")
		}
		return ed25519.PublicKey(x), nil
	}, jwt.WithValidMethods([]string{"EdDSA"}), jwt.WithAudience("slipstream-app"), jwt.WithIssuer("slipstream-control"))
	if err != nil || !tok.Valid {
		t.Fatalf("token does not verify via JWKS: %v", err)
	}
	for _, c := range []string{"sub", "exp", "iat", "jti"} {
		if claims[c] == nil {
			t.Fatalf("missing claim %s", c)
		}
	}

	// Protected endpoints.
	expect(t, e.do("GET", "/v1/me", nil, nil), 401)
	expect(t, e.do("GET", "/v1/me", nil, bearerHdr(access+"x")), 401)
	e.clock.Advance(16 * time.Minute)
	expect(t, e.do("GET", "/v1/me", nil, bearerHdr(access)), 401)
}

func TestLoginRateLimit(t *testing.T) {
	e := newEnv(t)
	a := e.signupLogin() // 2 IP hits, 2 email hits
	body := map[string]string{"email": a.email, "password": "wrong password!!"}
	for i := 0; i < 3; i++ {
		expect(t, e.do("POST", "/v1/auth/login", body, nil), 401)
	}
	r := e.do("POST", "/v1/auth/login", body, nil) // 6th for this email
	expect(t, r, http.StatusTooManyRequests)
	if r.errCode(t) != "rate_limited" {
		t.Fatal("code")
	}
	if ra, err := strconv.Atoi(r.header.Get("Retry-After")); err != nil || ra < 1 || ra > 60 {
		t.Fatalf("Retry-After %q", r.header.Get("Retry-After"))
	}
	// Per-IP: 10/min across signup+login. 6 used so far; other emails hit the IP cap.
	codes := []int{}
	for i := 0; i < 5; i++ {
		codes = append(codes, e.do("POST", "/v1/auth/login", map[string]string{"email": randEmail(), "password": "whatever password"}, nil).status)
	}
	if fmt.Sprint(codes) != "[401 401 401 401 429]" {
		t.Fatalf("ip limit codes %v", codes)
	}
	if e.metrics.RateLimitRejected.Value("auth_ip") != 1 || e.metrics.RateLimitRejected.Value("auth_email") != 1 {
		t.Fatal("rate limit metrics")
	}
}

func TestPerUserRateLimit(t *testing.T) {
	e := newEnv(t, func(d *httpapi.Deps) { d.Limits.PerUser = 3 })
	a := e.signupLogin()
	for i := 0; i < 3; i++ {
		expect(t, e.do("GET", "/v1/me", nil, bearerHdr(a.access)), 200)
	}
	r := e.do("GET", "/v1/devices", nil, bearerHdr(a.access))
	expect(t, r, 429)
	if r.header.Get("Retry-After") == "" {
		t.Fatal("no Retry-After")
	}
}

type brokenLimiter struct{}

func (brokenLimiter) Allow(context.Context, string, int, time.Duration) (ratelimit.Decision, error) {
	return ratelimit.Decision{}, errors.New("redis: connection refused")
}

func TestRateLimiterOutage(t *testing.T) {
	healthy := newEnv(t)
	a := healthy.signupLogin()

	e := newEnv(t, func(d *httpapi.Deps) { d.Limiter = brokenLimiter{} })
	// Auth endpoints fail closed...
	r := e.do("POST", "/v1/auth/login", map[string]string{"email": a.email, "password": a.password}, nil)
	expect(t, r, http.StatusServiceUnavailable)
	expect(t, e.do("POST", "/v1/auth/refresh", map[string]string{"refresh_token": a.refresh}, nil), 503)
	// ...everything else fails open, and it is counted.
	expect(t, e.do("GET", "/v1/me", nil, bearerHdr(a.access)), 200)
	if e.metrics.RateLimitFailOpen.Value("user") != 1 || e.metrics.RateLimitFailShut.Value("auth_ip") != 1 || e.metrics.RateLimitFailShut.Value("refresh_ip") != 1 {
		t.Fatalf("fail metrics open=%v closed=%v", e.metrics.RateLimitFailOpen.Value("user"), e.metrics.RateLimitFailShut.Value("auth_ip"))
	}
	r = e.do("GET", "/metrics", nil, nil)
	if !strings.Contains(string(r.body), `slipstream_ratelimit_fail_open_total{scope="user"} 1`) {
		t.Fatalf("metric not exposed:\n%s", r.body)
	}
}

func TestDevicesLimitIPAMAndValidation(t *testing.T) {
	e := newEnv(t)
	a := e.signupLogin()
	auth := bearerHdr(a.access)
	now := e.clock.Now()
	expect(t, e.entitle(a.id, "grace", now.Add(time.Hour), now, "sub_"+ids.New()), 200)

	for _, bad := range []map[string]string{
		{"name": "x", "platform": "windows", "wg_public_key": wgKey()},
		{"name": "", "platform": "ios", "wg_public_key": wgKey()},
		{"name": "x", "platform": "ios", "wg_public_key": "not-a-key"},
		{"name": "x", "platform": "ios", "wg_public_key": base64.StdEncoding.EncodeToString(make([]byte, 31))},
	} {
		expect(t, e.do("POST", "/v1/devices", bad, auth), 400)
	}

	// Five concurrent registrations all succeed with unique addresses.
	var mu sync.Mutex
	addrs := map[string]bool{}
	var wg sync.WaitGroup
	firstKey := wgKey()
	for i := 0; i < 5; i++ {
		wg.Add(1)
		key := wgKey()
		if i == 0 {
			key = firstKey
		}
		go func() {
			defer wg.Done()
			buf, _ := json.Marshal(map[string]string{"name": "phone", "platform": "ios", "wg_public_key": key})
			req, _ := http.NewRequest("POST", e.srv.URL+"/v1/devices", bytes.NewReader(buf))
			req.Header.Set("Authorization", "Bearer "+a.access)
			res, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Error(err)
				return
			}
			defer res.Body.Close()
			var m map[string]string
			_ = json.NewDecoder(res.Body).Decode(&m)
			if res.StatusCode != 201 {
				t.Errorf("status %d", res.StatusCode)
			}
			mu.Lock()
			addrs[m["tunnel_address"]] = true
			mu.Unlock()
		}()
	}
	wg.Wait()
	if len(addrs) != 5 {
		t.Fatalf("addresses not unique: %v", addrs)
	}
	for addr := range addrs {
		if addr == "10.64.0.0/32" || addr == "10.64.0.1/32" {
			t.Fatalf("reserved address allocated: %s", addr)
		}
	}
	// Sixth device: limit.
	r := e.do("POST", "/v1/devices", map[string]string{"name": "six", "platform": "ios", "wg_public_key": wgKey()}, auth)
	expect(t, r, http.StatusForbidden)
	if r.errCode(t) != "forbidden" {
		t.Fatal("code")
	}

	// Duplicate public key (another premium user): conflict.
	b := e.signupLogin()
	expect(t, e.entitle(b.id, "active", now.Add(time.Hour), now, "sub_"+ids.New()), 200)
	r = e.do("POST", "/v1/devices", map[string]string{"name": "dup", "platform": "android", "wg_public_key": firstKey}, bearerHdr(b.access))
	expect(t, r, http.StatusConflict)

	// Users cannot see or touch each other's devices.
	devs := e.do("GET", "/v1/devices", nil, auth).list(t)
	if len(devs) != 5 {
		t.Fatalf("devices %d", len(devs))
	}
	sameKeys(t, "device view", devs[0], "device_id", "name", "platform", "wg_public_key", "tunnel_address", "created_at")
	victim := devs[0]["device_id"].(string)
	expect(t, e.do("DELETE", "/v1/devices/"+victim, nil, bearerHdr(b.access)), 404)
	expect(t, e.do("POST", "/v1/devices/"+victim+"/config", nil, bearerHdr(b.access)), 404)
	expect(t, e.do("DELETE", "/v1/devices/not-a-uuid", nil, auth), 404)

	// Freeing a slot allows a new device.
	expect(t, e.do("DELETE", "/v1/devices/"+victim, nil, auth), 204)
	expect(t, e.do("POST", "/v1/devices", map[string]string{"name": "new", "platform": "ios", "wg_public_key": wgKey()}, auth), 201)
}

func TestHealthStateMachineViaAPI(t *testing.T) {
	e := newEnv(t)
	resetServers(t)
	a := e.signupLogin()
	srv := e.createServer("hc-01", "SE", "198.51.100.7", "")
	id := srv["id"].(string)
	healthy := func() bool {
		for _, s := range e.do("GET", "/v1/servers", nil, bearerHdr(a.access)).list(t) {
			if s["id"] == id {
				return s["healthy"].(bool)
			}
		}
		t.Fatal("server missing")
		return false
	}
	down := map[string]any{"server_id": id, "reachable": false, "rtt_ms_p50": nil, "loss": 1.0, "load": nil}
	if healthy() {
		t.Fatal("new server healthy")
	}
	e.heartbeat(up(id, 10, 0.5))
	if healthy() {
		t.Fatal("healthy after 1")
	}
	e.heartbeat(up(id, 10, 0.5))
	if !healthy() {
		t.Fatal("not healthy after 2")
	}
	e.heartbeat(down)
	e.heartbeat(down)
	if !healthy() {
		t.Fatal("unhealthy after 2 failures")
	}
	e.heartbeat(down)
	if healthy() {
		t.Fatal("healthy after 3 failures")
	}
	e.heartbeat(up(id, 10, 0.5))
	e.heartbeat(up(id, 10, 0.5))
	if !healthy() {
		t.Fatal("did not recover")
	}
	// Silence: no heartbeat for >90s means unhealthy, evaluated at read time.
	e.clock.Advance(91 * time.Second)
	if healthy() {
		t.Fatal("healthy after 91s silence")
	}
	// load null keeps the last value.
	e.heartbeat(map[string]any{"server_id": id, "reachable": true, "rtt_ms_p50": 5, "load": nil})
	for _, s := range e.do("GET", "/v1/servers", nil, bearerHdr(a.access)).list(t) {
		if s["id"] == id && s["load"].(float64) != 0.5 {
			t.Fatalf("load not kept: %v", s["load"])
		}
	}
	// Validation.
	expect(t, e.heartbeat(map[string]any{"server_id": id, "reachable": true, "loss": 2.0}), 400)
	expect(t, e.heartbeat(map[string]any{"server_id": "x", "reachable": true}), 400)
	expect(t, e.heartbeat(map[string]any{"server_id": id}), 400)
	if e.metrics.Heartbeats.Value("false") != 3 {
		t.Fatalf("heartbeat metric %v", e.metrics.Heartbeats.Value("false"))
	}
}

func TestOpsAndErrorEnvelope(t *testing.T) {
	e := newEnv(t)
	expect(t, e.do("GET", "/healthz", nil, nil), 200)
	r := e.do("GET", "/readyz", nil, nil)
	expect(t, r, 200)
	r = e.do("GET", "/openapi.yaml", nil, nil)
	expect(t, r, 200)
	if !strings.HasPrefix(string(r.body), "openapi: 3.1") {
		t.Fatal("openapi not served")
	}
	r = e.do("GET", "/nope", nil, map[string]string{"X-Request-Id": "abc-123"})
	expect(t, r, 404)
	if r.errCode(t) != "not_found" || r.header.Get("X-Request-Id") != "abc-123" || r.json(t)["error"].(map[string]any)["request_id"] != "abc-123" {
		t.Fatalf("404 envelope: %s %v", r.body, r.header)
	}
	r = e.do("PUT", "/v1/me", nil, nil)
	expect(t, r, 405)
	if r.header.Get("Allow") == "" || r.errCode(t) != "not_found" {
		t.Fatalf("405: %s", r.body)
	}
	// Hostile request ids are replaced.
	r = e.do("GET", "/healthz", nil, map[string]string{"X-Request-Id": "evil\" injected"})
	if r.header.Get("X-Request-Id") == "evil\" injected" {
		t.Fatal("request id not sanitised")
	}
	r = e.do("GET", "/metrics", nil, nil)
	if !strings.Contains(string(r.body), `slipstream_http_requests_total{route="GET /healthz",method="GET",status="200"}`) ||
		!strings.Contains(string(r.body), "slipstream_http_request_duration_seconds_bucket") {
		t.Fatalf("metrics:\n%s", r.body)
	}
	// Readiness reports a dead Redis.
	dead := newEnv(t, func(d *httpapi.Deps) {
		d.Redis = redis.NewClient(&redis.Options{Addr: "127.0.0.1:1", MaxRetries: -1, DialTimeout: 100 * time.Millisecond})
	})
	r = dead.do("GET", "/readyz", nil, nil)
	expect(t, r, 503)
	if r.json(t)["checks"].(map[string]any)["redis"] != "unavailable" {
		t.Fatal(string(r.body))
	}
}

// TestConcurrentIPAMAcrossUsers exercises the unique-constraint + retry path:
// different users do not share a row lock, so their allocators race for the
// same "next" address and the losers must retry.
func TestConcurrentIPAMAcrossUsers(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	now := e.clock.Now()
	const n = 12
	tokens := make([]string, n)
	for i := range tokens {
		id := ids.New()
		if err := testStore.CreateUser(ctx, id, randEmail(), "x"); err != nil {
			t.Fatal(err)
		}
		expect(t, e.entitle(id, "active", now.Add(time.Hour), now, "sub_"+ids.New()), 200)
		tokens[i], _, _ = e.tokens.Issue(id, ids.New())
	}
	var mu sync.Mutex
	addrs := map[string]bool{}
	var wg sync.WaitGroup
	for _, tok := range tokens {
		wg.Add(1)
		go func() {
			defer wg.Done()
			buf, _ := json.Marshal(map[string]string{"name": "d", "platform": "android", "wg_public_key": wgKey()})
			req, _ := http.NewRequest("POST", e.srv.URL+"/v1/devices", bytes.NewReader(buf))
			req.Header.Set("Authorization", "Bearer "+tok)
			res, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Error(err)
				return
			}
			defer res.Body.Close()
			var m map[string]string
			_ = json.NewDecoder(res.Body).Decode(&m)
			if res.StatusCode != 201 {
				t.Errorf("status %d: %v", res.StatusCode, m)
				return
			}
			mu.Lock()
			addrs[m["tunnel_address"]] = true
			mu.Unlock()
		}()
	}
	wg.Wait()
	if len(addrs) != n {
		t.Fatalf("got %d unique addresses for %d devices", len(addrs), n)
	}
}

// TestUndecryptableServerIsSkipped: one server whose stored secret no longer
// decrypts (registered under another DATA_ENCRYPTION_KEY, a botched rotation,
// a corrupted row) must cost that server only. It used to fail config issuance
// with a 500 for every user in the fleet.
func TestUndecryptableServerIsSkipped(t *testing.T) {
	e := newEnv(t)
	resetServers(t)
	a := e.signupLogin()
	auth := bearerHdr(a.access)
	now := e.clock.Now()
	expect(t, e.entitle(a.id, "active", now.Add(24*time.Hour), now.Add(-time.Minute), "sub_"+a.id), 200)
	r := e.do("POST", "/v1/devices", map[string]string{"name": "p", "platform": "ios", "wg_public_key": wgKey()}, auth)
	expect(t, r, http.StatusCreated)
	deviceID := r.json(t)["device_id"].(string)

	good := e.createServer("good-01", "DE", "198.51.100.10", "")["id"].(string)
	bad := e.createServer("bad-01", "DE", "198.51.100.11", "")["id"].(string)
	// Valid envelope format, wrong key: exactly what a key mix-up looks like.
	if _, err := testStore.DB().Exec(`UPDATE servers SET ss_master_secret_enc = $1 WHERE id = $2`,
		"v1:"+wgKey()+wgKey(), bad); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		expect(t, e.heartbeat(up(good, 40, 0.5), up(bad, 10, 0.1)), http.StatusAccepted)
	}

	var cfg map[string]any
	deadline := time.Now().Add(5 * time.Second) // the server snapshot may be up to one TTL stale
	for {
		r = e.do("POST", "/v1/devices/"+deviceID+"/config", nil, auth)
		if r.status == http.StatusOK {
			cfg = r.json(t)
			if len(cfg["servers"].([]any)) == 2 || time.Now().After(deadline) {
				break
			}
		} else if time.Now().After(deadline) {
			t.Fatalf("config with one undecryptable server = %d %s, want 200", r.status, r.body)
		}
		time.Sleep(100 * time.Millisecond)
	}
	servers := cfg["servers"].([]any)
	if len(servers) != 2 {
		t.Fatalf("got %d entries, want only good-01's wireguard + shadowsocks: %v", len(servers), servers)
	}
	for _, s := range servers {
		if n := s.(map[string]any)["name"].(string); !strings.HasPrefix(n, "good-01") {
			t.Fatalf("undecryptable server leaked into config: %s", n)
		}
	}
	if !strings.Contains(string(e.do("GET", "/metrics", nil, nil).body), `slipstream_secret_decrypt_failures_total{kind="ss_master_secret"}`) {
		t.Fatal("decrypt failure not counted")
	}
}
