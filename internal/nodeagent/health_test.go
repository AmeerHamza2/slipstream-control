package nodeagent

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestServeEcho(t *testing.T) {
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- ServeEcho(ctx, pc) }()

	c, err := net.Dial("udp4", pc.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))

	nonce := []byte("0123456789abcdef")
	if _, err := c.Write(nonce); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 128)
	n, err := c.Read(buf)
	if err != nil || string(buf[:n]) != string(nonce) {
		t.Fatalf("echo = %q, %v", buf[:n], err)
	}

	// Oversized datagrams are dropped, so the port cannot amplify.
	if _, err := c.Write(make([]byte, maxEcho+1)); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
	if _, err := c.Read(buf); err == nil {
		t.Fatal("oversized datagram was echoed")
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ServeEcho did not stop")
	}
}

func TestHandler(t *testing.T) {
	a := newAgent(newFakeSource(peer("2", "K2"), peer("3", "K3")), NewMemoryApplier())
	srv := httptest.NewServer(Handler(a, PeerLoad(a, 4)))
	defer srv.Close()

	// Before any sync: unhealthy.
	if r, _ := http.Get(srv.URL + "/healthz"); r.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("healthz before sync = %d", r.StatusCode)
	}
	if err := a.SyncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if r, _ := http.Get(srv.URL + "/healthz"); r.StatusCode != http.StatusOK {
		t.Fatalf("healthz after sync = %d", r.StatusCode)
	}

	r, err := http.Get(srv.URL + "/load")
	if err != nil {
		t.Fatal(err)
	}
	var body map[string]float64
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body["load"] != 0.5 {
		t.Fatalf("load = %v, %v; want 0.5 (2 peers / capacity 4)", body, err)
	}

	r, _ = http.Get(srv.URL + "/metrics")
	var sb strings.Builder
	buf := make([]byte, 4096)
	n, _ := r.Body.Read(buf)
	sb.Write(buf[:n])
	for _, want := range []string{"slipstream_agent_peers 2", `slipstream_agent_syncs_total{result="ok"} 1`, "slipstream_agent_load 0.5000"} {
		if !strings.Contains(sb.String(), want) {
			t.Errorf("metrics lack %q:\n%s", want, sb.String())
		}
	}
}

func TestLoadUnknownIs404(t *testing.T) {
	a := newAgent(newFakeSource(), NewMemoryApplier())
	srv := httptest.NewServer(Handler(a, PeerLoad(a, 0)))
	defer srv.Close()
	if r, _ := http.Get(srv.URL + "/load"); r.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown load = %d, want 404 (the prober reports null)", r.StatusCode)
	}
}

func TestMaxLoad(t *testing.T) {
	f := MaxLoad(func() (float64, bool) { return 0.2, true }, func() (float64, bool) { return 0, false }, func() (float64, bool) { return 0.7, true })
	if v, ok := f(); !ok || v != 0.7 {
		t.Fatalf("MaxLoad = %v %v", v, ok)
	}
	if _, ok := MaxLoad(func() (float64, bool) { return 0, false })(); ok {
		t.Fatal("all-unknown should be unknown")
	}
}
