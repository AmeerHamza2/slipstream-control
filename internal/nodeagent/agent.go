package nodeagent

import (
	"context"
	"errors"
	"log/slog"
	"math/rand/v2"
	"sync"
	"sync/atomic"
	"time"
)

// Source is what the agent syncs from; *Client implements it.
type Source interface {
	FullSync(ctx context.Context) ([]Peer, string, error)
	Changes(ctx context.Context, token string) (Changes, error)
}

// Agent keeps one node's WireGuard peers in sync with the api.
type Agent struct {
	Source  Source
	Applier Applier
	Log     *slog.Logger

	// Interval between incremental syncs. Default 15s; the contract asks for
	// 15–30s, which bounds how long a lapsed user keeps access.
	Interval time.Duration
	// FullResyncEvery forces a full sync to repair drift (a peer added or
	// removed by hand, an agent restart that missed a change). Default 1h.
	FullResyncEvery time.Duration

	mu       sync.Mutex
	desired  map[string]Peer // device id -> peer
	token    string
	lastFull time.Time

	// Observable state for /healthz and /metrics.
	lastSuccess  atomic.Int64 // unix nanos
	syncOK       atomic.Uint64
	syncFailed   atomic.Uint64
	peersAdded   atomic.Uint64
	peersRemoved atomic.Uint64
	fullSyncs    atomic.Uint64
}

func (a *Agent) log() *slog.Logger {
	if a.Log != nil {
		return a.Log
	}
	return slog.Default()
}

func (a *Agent) interval() time.Duration {
	if a.Interval > 0 {
		return a.Interval
	}
	return 15 * time.Second
}

func (a *Agent) fullEvery() time.Duration {
	if a.FullResyncEvery > 0 {
		return a.FullResyncEvery
	}
	return time.Hour
}

// Run syncs until ctx is cancelled. It never returns an error for a failed
// sync: it logs, counts, backs off, and leaves the interface as it was.
func (a *Agent) Run(ctx context.Context) error {
	failures := 0
	for {
		err := a.SyncOnce(ctx)
		if ctx.Err() != nil {
			return nil
		}
		wait := a.interval()
		if err != nil {
			failures++
			a.syncFailed.Add(1)
			// Exponential backoff with full jitter, capped at 4 intervals, so
			// a fleet of agents does not stampede an api that just came back.
			backoff := a.interval() * time.Duration(1<<min(failures-1, 2))
			wait = time.Duration(rand.Int64N(int64(backoff)) + 1)
			lvl := slog.LevelWarn
			if errors.Is(err, ErrUnauthorized) || errors.Is(err, ErrUnknownServer) {
				lvl = slog.LevelError // needs an operator, not a retry
			}
			a.log().Log(ctx, lvl, "peer sync failed; interface left unchanged", "error", err.Error(), "retry_in", wait.Round(time.Millisecond).String())
		} else {
			failures = 0
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(wait):
		}
	}
}

// SyncOnce does one sync step: a full sync if none has happened, the token
// expired, or drift repair is due; otherwise an incremental sync.
func (a *Agent) SyncOnce(ctx context.Context) error {
	a.mu.Lock()
	needFull := a.token == "" || time.Since(a.lastFull) >= a.fullEvery()
	token := a.token
	a.mu.Unlock()

	if !needFull {
		err := a.incremental(ctx, token)
		if !errors.Is(err, ErrResync) {
			return a.done(err)
		}
		a.log().Info("sync token expired; doing a full sync")
	}
	return a.done(a.full(ctx))
}

func (a *Agent) done(err error) error {
	if err == nil {
		a.syncOK.Add(1)
		a.lastSuccess.Store(time.Now().UnixNano())
	}
	return err
}

// full fetches every peer and reconciles the interface to exactly that set,
// removing anything the api no longer lists, including peers added by hand.
// The agent owns the interface's peer table.
func (a *Agent) full(ctx context.Context) error {
	peers, token, err := a.Source.FullSync(ctx)
	if err != nil {
		return err
	}
	current, err := a.Applier.Current(ctx)
	if err != nil {
		return err
	}
	desired := make(map[string]Peer, len(peers))
	want := make(map[string]AppliedPeer, len(peers))
	for _, p := range peers {
		desired[p.DeviceID] = p
		want[p.PublicKey] = applied(p)
	}
	var ups []AppliedPeer
	var rems []string
	for k, w := range want {
		if c, ok := current[k]; !ok || c != w {
			ups = append(ups, w)
		}
	}
	for k := range current {
		if _, ok := want[k]; !ok {
			rems = append(rems, k)
		}
	}
	if err := a.Applier.Apply(ctx, ups, rems); err != nil {
		return err
	}
	a.peersAdded.Add(uint64(len(ups)))
	a.peersRemoved.Add(uint64(len(rems)))
	a.fullSyncs.Add(1)

	a.mu.Lock()
	a.desired, a.token, a.lastFull = desired, token, time.Now()
	a.mu.Unlock()
	a.log().Info("full peer sync", "peers", len(desired), "added_or_updated", len(ups), "removed", len(rems))
	return nil
}

// incremental applies changes since token: upserts first, then removals, as
// the contract specifies. Both are idempotent, and the api repeats up to 60 s
// of changes before the token, so unchanged upserts are skipped rather than
// re-applied every interval.
func (a *Agent) incremental(ctx context.Context, token string) error {
	ch, err := a.Source.Changes(ctx, token)
	if err != nil {
		return err
	}

	a.mu.Lock()
	desired := make(map[string]Peer, len(a.desired))
	for k, v := range a.desired {
		desired[k] = v
	}
	a.mu.Unlock()

	var ups []AppliedPeer
	var rems []string
	for _, p := range ch.Upserts {
		if old, ok := desired[p.DeviceID]; ok && old == p {
			continue
		}
		if old, ok := desired[p.DeviceID]; ok && old.PublicKey != p.PublicKey {
			rems = append(rems, old.PublicKey) // device rotated its key
		}
		desired[p.DeviceID] = p
		ups = append(ups, applied(p))
	}
	for _, id := range ch.Removals {
		if p, ok := desired[id]; ok {
			rems = append(rems, p.PublicKey)
			delete(desired, id)
		}
	}
	if len(ups) > 0 || len(rems) > 0 {
		if err := a.Applier.Apply(ctx, ups, rems); err != nil {
			return err
		}
		a.peersAdded.Add(uint64(len(ups)))
		a.peersRemoved.Add(uint64(len(rems)))
		a.log().Info("incremental peer sync", "peers", len(desired), "added_or_updated", len(ups), "removed", len(rems))
	}

	a.mu.Lock()
	a.desired, a.token = desired, ch.SyncToken
	a.mu.Unlock()
	return nil
}

func applied(p Peer) AppliedPeer {
	return AppliedPeer{PublicKey: p.PublicKey, AllowedIP: p.TunnelAddress, PresharedKey: p.PresharedKey}
}

// PeerCount is the number of peers the agent believes the node should have.
func (a *Agent) PeerCount() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.desired)
}

// LastSuccess is when the last sync succeeded (zero if never).
func (a *Agent) LastSuccess() time.Time {
	ns := a.lastSuccess.Load()
	if ns == 0 {
		return time.Time{}
	}
	return time.Unix(0, ns)
}

// Healthy reports whether a sync succeeded within three intervals.
func (a *Agent) Healthy() bool {
	last := a.LastSuccess()
	return !last.IsZero() && time.Since(last) < 3*a.interval()+a.interval()/2
}
