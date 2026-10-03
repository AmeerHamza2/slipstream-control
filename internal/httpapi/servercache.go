package httpapi

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sync"
	"time"

	"github.com/ameerhamza2/slipstream-control/internal/health"
	"github.com/ameerhamza2/slipstream-control/internal/selection"
	"github.com/ameerhamza2/slipstream-control/internal/store"
)

// serverSnapshot is an immutable view of the server table plus the
// responses derived from it. GET /v1/servers and config issuance read the
// whole fleet on every call; at millions of users that is the hottest query
// in the system and its answer changes only when a heartbeat batch lands, so
// each replica keeps one snapshot for a short TTL.
//
// Health stays correct: the snapshot holds the raw persisted state, and the
// 90 s silence rule is applied at read time against the request's clock
// (health.Effective), so a snapshot can never keep a silent server healthy.
// The pre-encoded /v1/servers body bakes in health as of loadedAt, which is
// at most one TTL old.
type serverSnapshot struct {
	servers  []store.Server // ordered by name
	byID     map[string]*store.Server
	ranking  *selection.Ranking // by score; health applied per request
	loadedAt time.Time

	publicJSON, publicGzip []byte
	publicETag             string
	internalJSON           []byte
}

func buildSnapshot(servers []store.Server, now time.Time) (*serverSnapshot, error) {
	snap := &serverSnapshot{servers: servers, byID: make(map[string]*store.Server, len(servers)), loadedAt: now}
	pub := make([]publicServer, 0, len(servers))
	internal := make([]internalServer, 0, len(servers))
	cands := make([]selection.Candidate, 0, len(servers))
	for i := range servers {
		sv := &servers[i]
		snap.byID[sv.ID] = sv
		cands = append(cands, selection.Candidate{ID: sv.ID, Name: sv.Name, Country: sv.Country,
			RTTp50: sv.Health.RTTp50, Load: sv.Health.Load, Loss: sv.Health.Loss})
		pub = append(pub, publicServer{ID: sv.ID, Name: sv.Name, Country: sv.Country, City: sv.City,
			Protocols: protocols, Load: sv.Health.Load, Healthy: health.Effective(sv.Health, now)})
		internal = append(internal, internalServer{ID: sv.ID, Name: sv.Name, PublicIPv4: sv.PublicIPv4, WGPort: sv.WGPort, SSPort: sv.SSPort})
	}
	snap.ranking = selection.NewRanking(cands)
	var err error
	if snap.publicJSON, err = marshalLine(pub); err != nil {
		return nil, err
	}
	if snap.internalJSON, err = marshalLine(internal); err != nil {
		return nil, err
	}
	var gz bytes.Buffer
	zw, _ := gzip.NewWriterLevel(&gz, gzip.BestSpeed)
	_, _ = zw.Write(snap.publicJSON)
	_ = zw.Close()
	snap.publicGzip = gz.Bytes()
	sum := sha256.Sum256(snap.publicJSON)
	snap.publicETag = `"` + hex.EncodeToString(sum[:12]) + `"`
	return snap, nil
}

// marshalLine matches json.Encoder output (trailing newline) so cached and
// uncached responses are byte-identical.
func marshalLine(v any) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

var protocols = []string{"wireguard", "shadowsocks"}

// serverCache holds the current snapshot. Refreshes are single-flight: when
// the snapshot expires, one request loads it and concurrent requests wait
// for that load instead of stampeding Postgres. Writes made through this
// replica (heartbeats, new servers) invalidate it immediately; writes on
// other replicas become visible within one TTL.
type serverCache struct {
	ttl  time.Duration // <= 0: no caching (every get loads)
	now  func() time.Time
	load func(context.Context) ([]store.Server, error)

	mu       sync.Mutex
	cur      *serverSnapshot
	gen      uint64 // bumped by invalidate
	curGen   uint64
	inflight *serverFlight
}

type serverFlight struct {
	gen  uint64
	done chan struct{}
	snap *serverSnapshot
	err  error
}

const serverLoadTimeout = 5 * time.Second

func (c *serverCache) get(ctx context.Context) (*serverSnapshot, error) {
	if c.ttl <= 0 {
		servers, err := c.load(ctx)
		if err != nil {
			return nil, err
		}
		return buildSnapshot(servers, c.now())
	}
	c.mu.Lock()
	now := c.now()
	if cur := c.cur; cur != nil && c.curGen == c.gen && !now.Before(cur.loadedAt) && now.Sub(cur.loadedAt) < c.ttl {
		c.mu.Unlock()
		return cur, nil
	}
	f := c.inflight
	if f == nil || f.gen != c.gen {
		f = &serverFlight{gen: c.gen, done: make(chan struct{})}
		c.inflight = f
		go c.refresh(ctx, f)
	}
	c.mu.Unlock()
	select {
	case <-f.done:
		return f.snap, f.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// refresh runs detached from the triggering request (its cancellation must
// not fail every waiter) but bounded by serverLoadTimeout.
func (c *serverCache) refresh(ctx context.Context, f *serverFlight) {
	lctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), serverLoadTimeout)
	defer cancel()
	servers, err := c.load(lctx)
	if err == nil {
		f.snap, f.err = buildSnapshot(servers, c.now())
	} else {
		f.err = err
	}
	c.mu.Lock()
	if f.err == nil && f.gen == c.gen {
		c.cur, c.curGen = f.snap, f.gen
	}
	if c.inflight == f {
		c.inflight = nil
	}
	c.mu.Unlock()
	close(f.done)
}

// invalidate drops the snapshot; a load already in flight is not reused by
// later callers because it may predate the write.
func (c *serverCache) invalidate() {
	c.mu.Lock()
	c.gen++
	c.mu.Unlock()
}
