package httpapi

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ameerhamza2/slipstream-control/internal/store"
)

type fakeLoader struct {
	calls   atomic.Int64
	gate    chan struct{} // if non-nil, each load waits for a token
	fail    atomic.Bool
	version atomic.Int64
}

func (f *fakeLoader) load(ctx context.Context) ([]store.Server, error) {
	f.calls.Add(1)
	v := f.version.Load() // what the DB held when the query started
	if f.gate != nil {
		select {
		case <-f.gate:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if f.fail.Load() {
		return nil, errors.New("db down")
	}
	return []store.Server{{ID: "s1", Name: "a", City: time.Duration(v).String()}}, nil
}

func TestServerCacheSingleFlightAndTTL(t *testing.T) {
	var mu sync.Mutex
	now := time.Unix(1000, 0)
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	advance := func(d time.Duration) { mu.Lock(); now = now.Add(d); mu.Unlock() }
	f := &fakeLoader{gate: make(chan struct{})}
	c := &serverCache{ttl: 2 * time.Second, now: clock, load: f.load}

	// 50 concurrent misses share one load.
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := c.get(context.Background()); err != nil {
				t.Error(err)
			}
		}()
	}
	for f.calls.Load() == 0 {
		time.Sleep(time.Millisecond)
	}
	time.Sleep(20 * time.Millisecond)
	close(f.gate)
	wg.Wait()
	if n := f.calls.Load(); n != 1 {
		t.Fatalf("%d loads for 50 concurrent misses", n)
	}
	f.gate = nil
	if _, _ = c.get(context.Background()); f.calls.Load() != 1 {
		t.Fatal("fresh snapshot reloaded")
	}
	advance(2 * time.Second)
	if _, _ = c.get(context.Background()); f.calls.Load() != 2 {
		t.Fatal("expired snapshot not reloaded")
	}
	advance(-time.Hour) // clock went backwards: never trust a future snapshot
	if _, _ = c.get(context.Background()); f.calls.Load() != 3 {
		t.Fatal("snapshot from the future reused")
	}
	c.invalidate()
	if _, _ = c.get(context.Background()); f.calls.Load() != 4 {
		t.Fatal("invalidate ignored")
	}

	// Errors are returned to the waiters but not cached.
	c.invalidate()
	f.fail.Store(true)
	if _, err := c.get(context.Background()); err == nil {
		t.Fatal("error swallowed")
	}
	f.fail.Store(false)
	if s, err := c.get(context.Background()); err != nil || len(s.servers) != 1 {
		t.Fatalf("after recovery: %v", err)
	}
}

// A write that lands while a load is in flight must not be hidden by that
// (possibly older) load.
func TestServerCacheInvalidateDuringLoad(t *testing.T) {
	f := &fakeLoader{gate: make(chan struct{}, 2)}
	c := &serverCache{ttl: time.Minute, now: time.Now, load: f.load}
	first := make(chan *serverSnapshot)
	go func() { s, _ := c.get(context.Background()); first <- s }()
	for f.calls.Load() == 0 {
		time.Sleep(time.Millisecond)
	}
	f.version.Add(1) // a heartbeat lands after the first load's query began...
	c.invalidate()   // ...and invalidates the cache
	f.gate <- struct{}{}
	f.gate <- struct{}{}
	if s := <-first; s.servers[0].City != time.Duration(0).String() {
		t.Fatalf("first load should have seen the old data: %v", s.servers[0].City)
	}
	s, err := c.get(context.Background())
	if err != nil || s.servers[0].City != time.Duration(1).String() {
		t.Fatalf("stale snapshot served after invalidate: %+v %v", s, err)
	}
}

func TestServerCacheWaiterCancellation(t *testing.T) {
	f := &fakeLoader{gate: make(chan struct{})}
	c := &serverCache{ttl: time.Minute, now: time.Now, load: f.load}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error)
	go func() { _, err := c.get(ctx); done <- err }()
	for f.calls.Load() == 0 {
		time.Sleep(time.Millisecond)
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("waiter: %v", err)
	}
	// The load itself is detached from the first caller and still completes.
	close(f.gate)
	if _, err := c.get(context.Background()); err != nil {
		t.Fatal(err)
	}
	if f.calls.Load() != 1 {
		t.Fatalf("loads: %d", f.calls.Load())
	}
}
