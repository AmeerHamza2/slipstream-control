package nodeagent

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"
)

// fakeSource is an api the test can change between syncs.
type fakeSource struct {
	mu       sync.Mutex
	peers    map[string]Peer // device id -> peer
	removed  []string        // device ids removed since the last Changes call
	gen      int
	failNext error
	gone     bool // next Changes answers 410
	fulls    int
	changes  int
}

func newFakeSource(ps ...Peer) *fakeSource {
	f := &fakeSource{peers: map[string]Peer{}}
	for _, p := range ps {
		f.peers[p.DeviceID] = p
	}
	return f
}

func (f *fakeSource) FullSync(context.Context) ([]Peer, string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.failNext; err != nil {
		f.failNext = nil
		return nil, "", err
	}
	f.fulls++
	f.removed = nil
	out := make([]Peer, 0, len(f.peers))
	for _, p := range f.peers {
		out = append(out, p)
	}
	return out, "tok", nil
}

func (f *fakeSource) Changes(_ context.Context, _ string) (Changes, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.failNext; err != nil {
		f.failNext = nil
		return Changes{}, err
	}
	if f.gone {
		f.gone = false
		return Changes{}, ErrResync
	}
	f.changes++
	ch := Changes{SyncToken: "tok", Removals: f.removed}
	for _, p := range f.peers {
		ch.Upserts = append(ch.Upserts, p) // the api repeats overlap; the agent must cope
	}
	f.removed = nil
	return ch, nil
}

func (f *fakeSource) add(p Peer) { f.mu.Lock(); f.peers[p.DeviceID] = p; f.mu.Unlock() }
func (f *fakeSource) remove(id string) {
	f.mu.Lock()
	delete(f.peers, id)
	f.removed = append(f.removed, id)
	f.mu.Unlock()
}

func peer(id, key string) Peer {
	return Peer{DeviceID: id, PublicKey: key, TunnelAddress: "10.64.0." + id + "/32", PresharedKey: "psk-" + id}
}

func quietLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func newAgent(src Source, app Applier) *Agent {
	return &Agent{Source: src, Applier: app, Log: quietLog(), Interval: 10 * time.Millisecond}
}

func keys(t *testing.T, app *MemoryApplier) map[string]AppliedPeer {
	t.Helper()
	m, err := app.Current(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestFullThenIncrementalSync(t *testing.T) {
	src := newFakeSource(peer("2", "K2"), peer("3", "K3"))
	app := NewMemoryApplier()
	a := newAgent(src, app)
	ctx := context.Background()

	if err := a.SyncOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if got := keys(t, app); len(got) != 2 || got["K2"].AllowedIP != "10.64.0.2/32" || got["K2"].PresharedKey != "psk-2" {
		t.Fatalf("after full sync: %+v", got)
	}

	// A user subscribes: their device is issued this node.
	src.add(peer("4", "K4"))
	if err := a.SyncOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok := keys(t, app)["K4"]; !ok {
		t.Fatal("new peer not added by incremental sync")
	}

	// A subscription lapses: the api lists the device as removed.
	src.remove("2")
	if err := a.SyncOnce(ctx); err != nil {
		t.Fatal(err)
	}
	got := keys(t, app)
	if _, ok := got["K2"]; ok {
		t.Fatal("lapsed user's peer is still on the interface")
	}
	if len(got) != 2 || a.PeerCount() != 2 {
		t.Fatalf("peers = %d (agent believes %d), want 2", len(got), a.PeerCount())
	}
	if src.fulls != 1 || src.changes != 2 {
		t.Fatalf("fulls=%d changes=%d; want one full sync then incrementals", src.fulls, src.changes)
	}
}

// TestRepeatedUpsertsAreNotReapplied: the api repeats up to 60 s of changes
// on every incremental sync. Re-running wg for unchanged peers every 15 s on
// a 100k-peer node would be pure churn.
func TestRepeatedUpsertsAreNotReapplied(t *testing.T) {
	src := newFakeSource(peer("2", "K2"))
	app := NewMemoryApplier()
	changes := 0
	app.Log = func(string, AppliedPeer) { changes++ }
	a := newAgent(src, app)
	for range 5 {
		if err := a.SyncOnce(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if changes != 1 {
		t.Fatalf("applied %d changes for one unchanging peer, want 1", changes)
	}
}

// TestFailStatic: when the api is down the interface must not change. An api
// incident must not become a VPN outage.
func TestFailStatic(t *testing.T) {
	src := newFakeSource(peer("2", "K2"), peer("3", "K3"))
	app := NewMemoryApplier()
	a := newAgent(src, app)
	if err := a.SyncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	src.failNext = errors.New("api: connection refused")
	if err := a.SyncOnce(context.Background()); err == nil {
		t.Fatal("expected the sync error to be returned")
	}
	if got := keys(t, app); len(got) != 2 {
		t.Fatalf("interface changed during an api outage: %+v", got)
	}
	if !a.LastSuccess().IsZero() && a.Healthy() == false {
		t.Fatal("one failed sync right after a success should not mark the agent unhealthy")
	}
}

func TestResyncOn410(t *testing.T) {
	src := newFakeSource(peer("2", "K2"))
	app := NewMemoryApplier()
	a := newAgent(src, app)
	_ = a.SyncOnce(context.Background())
	src.gone = true
	src.mu.Lock()
	delete(src.peers, "2") // removed while the token was too old to report it
	src.mu.Unlock()
	if err := a.SyncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if src.fulls != 2 {
		t.Fatalf("fulls = %d, want a second full sync after 410", src.fulls)
	}
	if len(keys(t, app)) != 0 {
		t.Fatal("full resync did not remove the peer the token could no longer report")
	}
}

// TestFullSyncRepairsDrift: the agent owns the peer table. A peer added by
// hand (or left behind by a crash) is removed, and a peer whose PSK was
// changed by hand is put back.
func TestFullSyncRepairsDrift(t *testing.T) {
	src := newFakeSource(peer("2", "K2"))
	app := NewMemoryApplier()
	app.Set(AppliedPeer{PublicKey: "INTRUDER", AllowedIP: "10.64.9.9/32"})
	app.Set(AppliedPeer{PublicKey: "K2", AllowedIP: "10.64.0.2/32", PresharedKey: "tampered"})
	a := newAgent(src, app)
	if err := a.SyncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	got := keys(t, app)
	if _, ok := got["INTRUDER"]; ok {
		t.Fatal("unknown peer survived a full sync")
	}
	if got["K2"].PresharedKey != "psk-2" {
		t.Fatalf("tampered PSK not repaired: %+v", got["K2"])
	}
}

func TestPeriodicFullResync(t *testing.T) {
	src := newFakeSource(peer("2", "K2"))
	a := newAgent(src, NewMemoryApplier())
	a.FullResyncEvery = 20 * time.Millisecond
	_ = a.SyncOnce(context.Background())
	time.Sleep(30 * time.Millisecond)
	_ = a.SyncOnce(context.Background())
	if src.fulls != 2 {
		t.Fatalf("fulls = %d, want a drift-repair full sync", src.fulls)
	}
}

func TestKeyRotationRemovesOldKey(t *testing.T) {
	src := newFakeSource(peer("2", "OLD"))
	app := NewMemoryApplier()
	a := newAgent(src, app)
	_ = a.SyncOnce(context.Background())
	src.add(peer("2", "NEW"))
	if err := a.SyncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	got := keys(t, app)
	if _, ok := got["OLD"]; ok || len(got) != 1 {
		t.Fatalf("old key left behind after rotation: %+v", got)
	}
}

func TestRunStopsOnCancel(t *testing.T) {
	a := newAgent(newFakeSource(), NewMemoryApplier())
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()
	time.Sleep(30 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not stop")
	}
	if !a.Healthy() {
		t.Fatal("agent with recent successful syncs reports unhealthy")
	}
}
