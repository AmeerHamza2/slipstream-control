package httpapi_test

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ameerhamza2/slipstream-control/internal/httpapi"
	"github.com/ameerhamza2/slipstream-control/internal/nodeagent"
)

const nodeSecret = "test-node-agent-secret-0123456789abcdef"

// TestNodeAgentAgainstRealAPI runs the real node agent client against the real
// api and Postgres: a device issued this node shows up on the interface, a
// second subscriber is added incrementally, and when a subscription ends the
// peer is removed, which is what stops a lapsed user's handshakes. It also
// checks that node tokens are scoped to their own server.
func TestNodeAgentAgainstRealAPI(t *testing.T) {
	e := newEnv(t, func(d *httpapi.Deps) { d.NodeAgentSecret = nodeSecret })
	resetServers(t)

	fra := e.createServer("fra-agent", "DE", "198.51.100.20", "")
	ams := e.createServer("ams-agent", "NL", "198.51.100.21", "")
	fraID, amsID := fra["id"].(string), ams["id"].(string)
	fraTok, _ := fra["agent_token"].(string)
	amsTok, _ := ams["agent_token"].(string)
	if !strings.HasPrefix(fraTok, "nat1.") || fraTok == amsTok {
		t.Fatalf("server creation must return a distinct node token per server: %q %q", fraTok, amsTok)
	}
	for range 2 {
		expect(t, e.heartbeat(up(fraID, 20, 0.1), up(amsID, 30, 0.1)), http.StatusAccepted)
	}

	// The token endpoint re-issues the same derived token.
	r := e.admin("POST", "/admin/v1/servers/"+fraID+"/agent-token", nil)
	expect(t, r, 200)
	if r.json(t)["agent_token"] != fraTok {
		t.Fatal("agent-token endpoint disagrees with the token returned at creation")
	}

	// A subscriber gets a device and a config; that issues them this node.
	subscribe := func() (account, string, map[string]any) {
		a := e.signupLogin()
		now := e.clock.Now()
		expect(t, e.entitle(a.id, "active", now.Add(30*24*time.Hour), now.Add(-time.Minute), "sub_"+a.id), 200)
		r := e.do("POST", "/v1/devices", map[string]string{"name": "p", "platform": "android", "wg_public_key": wgKey()}, bearerHdr(a.access))
		expect(t, r, http.StatusCreated)
		dev := r.json(t)
		var cfg map[string]any
		deadline := time.Now().Add(5 * time.Second) // server snapshot is up to one TTL stale
		for {
			r = e.do("POST", "/v1/devices/"+dev["device_id"].(string)+"/config", nil, bearerHdr(a.access))
			if r.status == 200 || time.Now().After(deadline) {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		expect(t, r, 200)
		cfg = r.json(t)
		return a, dev["device_id"].(string), cfg
	}
	alice, aliceDev, aliceCfg := subscribe()

	app := nodeagent.NewMemoryApplier()
	agent := &nodeagent.Agent{
		Source:  &nodeagent.Client{BaseURL: e.srv.URL, ServerID: fraID, Token: fraTok, PageSize: 1},
		Applier: app,
		Log:     quietLogger(),
	}
	ctx := context.Background()
	if err := agent.SyncOnce(ctx); err != nil {
		t.Fatalf("full sync with a node token: %v", err)
	}
	peers, _ := app.Current(ctx)
	if len(peers) != 1 {
		t.Fatalf("node has %d peers after full sync, want alice's device", len(peers))
	}
	var alicePeer nodeagent.AppliedPeer
	for _, p := range peers {
		alicePeer = p
	}
	// The PSK on the node must be the one the phone was given for this node.
	var wantPSK string
	for _, s := range aliceCfg["servers"].([]any) {
		m := s.(map[string]any)
		if m["name"] == "fra-agent" {
			wantPSK = m["preshared_key"].(string)
		}
	}
	if wantPSK == "" || alicePeer.PresharedKey != wantPSK {
		t.Fatal("node PSK does not match the PSK issued to the phone for this node")
	}
	if !strings.HasSuffix(alicePeer.AllowedIP, "/32") {
		t.Fatalf("allowed ip %q", alicePeer.AllowedIP)
	}

	// A second subscriber arrives: picked up incrementally (paging was
	// exercised above with PageSize 1).
	_, bobDev, _ := subscribe()
	if err := agent.SyncOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if peers, _ = app.Current(ctx); len(peers) != 2 {
		t.Fatalf("after bob subscribed: %d peers, want 2", len(peers))
	}
	_ = bobDev

	// Alice's subscription ends. Her peer must leave the node.
	now := e.clock.Now()
	expect(t, e.entitle(alice.id, "expired", now.Add(-time.Second), now, "sub_"+alice.id), 200)
	if err := agent.SyncOnce(ctx); err != nil {
		t.Fatal(err)
	}
	peers, _ = app.Current(ctx)
	if _, still := peers[alicePeer.PublicKey]; still || len(peers) != 1 {
		t.Fatalf("lapsed subscriber's peer still on the node (%d peers)", len(peers))
	}
	_ = aliceDev

	// Scoping: fra's token cannot read ams's peers; a forged token fails;
	// the admin token still works.
	for _, tc := range []struct {
		name, server, token string
		want                int
	}{
		{"own node", fraID, fraTok, 200},
		{"other node", amsID, fraTok, 401},
		{"forged", fraID, "nat1.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", 401},
		{"admin", amsID, adminToken, 200},
	} {
		r := e.do("GET", "/admin/v1/servers/"+tc.server+"/peers", nil, bearerHdr(tc.token))
		if r.status != tc.want {
			t.Errorf("%s: GET peers = %d, want %d", tc.name, r.status, tc.want)
		}
	}
	// A node token is not an admin token.
	if r := e.do("POST", "/admin/v1/servers", map[string]any{}, bearerHdr(fraTok)); r.status != 401 {
		t.Fatalf("node token on an admin route = %d, want 401", r.status)
	}
}

func TestAgentTokenEndpointWithoutSecret(t *testing.T) {
	e := newEnv(t)
	resetServers(t)
	s := e.createServer("solo-01", "DE", "198.51.100.30", "")
	if _, ok := s["agent_token"]; ok {
		t.Fatal("agent_token returned although NODE_AGENT_SECRET is not configured")
	}
	r := e.admin("POST", "/admin/v1/servers/"+s["id"].(string)+"/agent-token", nil)
	expect(t, r, http.StatusConflict)
}

func quietLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }
