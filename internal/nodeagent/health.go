package nodeagent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// maxEcho is the largest datagram echoed. Probes send 16-byte nonces; replies
// are never larger than the request, so the port cannot be used to amplify
// traffic toward a spoofed source.
const maxEcho = 64

// ServeEcho answers UDP datagrams on pc with the same bytes until ctx is
// cancelled. This is the health port the fleet prober and the app's latency
// probe measure, beside the WireGuard port (WireGuard itself never answers
// unauthenticated packets, so a healthy node and a blackholed one would look
// identical from outside).
func ServeEcho(ctx context.Context, pc net.PacketConn) error {
	go func() {
		<-ctx.Done()
		_ = pc.Close()
	}()
	buf := make([]byte, maxEcho+1)
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		if n == 0 || n > maxEcho {
			continue
		}
		_, _ = pc.WriteTo(buf[:n], from)
	}
}

// LoadFunc reports node load in [0, 1], or ok=false when unknown.
type LoadFunc func() (load float64, ok bool)

// PeerLoad is load as peers / capacity: the simplest honest measure of how
// full a node is, and the one that matters for placing new devices.
func PeerLoad(a *Agent, capacity int) LoadFunc {
	return func() (float64, bool) {
		if capacity <= 0 {
			return 0, false
		}
		return min(float64(a.PeerCount())/float64(capacity), 1), true
	}
}

// CPULoad is the 1-minute load average divided by the CPU count, from
// /proc/loadavg. Unavailable off Linux.
func CPULoad() LoadFunc {
	return func() (float64, bool) {
		b, err := os.ReadFile("/proc/loadavg")
		if err != nil {
			return 0, false
		}
		f := strings.Fields(string(b))
		if len(f) == 0 {
			return 0, false
		}
		v, err := strconv.ParseFloat(f[0], 64)
		if err != nil {
			return 0, false
		}
		return min(v/float64(runtime.NumCPU()), 1), true
	}
}

// MaxLoad combines load sources: a node is as loaded as its busiest
// dimension.
func MaxLoad(fs ...LoadFunc) LoadFunc {
	return func() (float64, bool) {
		best, any := 0.0, false
		for _, f := range fs {
			if v, ok := f(); ok {
				best, any = max(best, v), true
			}
		}
		return best, any
	}
}

// Handler serves the node's HTTP endpoints:
//
//	GET /load     {"load": 0.35} for the fleet prober; 404 when unknown
//	GET /healthz  200 when a peer sync succeeded recently, else 503
//	GET /metrics  Prometheus text
func Handler(a *Agent, load LoadFunc) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /load", func(w http.ResponseWriter, _ *http.Request) {
		v, ok := load()
		if !ok {
			http.NotFound(w, nil)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]float64{"load": v})
	})
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		if !a.Healthy() {
			http.Error(w, "peer sync stale", http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		last := 0.0
		if t := a.LastSuccess(); !t.IsZero() {
			last = float64(t.UnixNano()) / 1e9
		}
		fmt.Fprintf(w, "# HELP slipstream_agent_peers Peers this node should accept.\n# TYPE slipstream_agent_peers gauge\nslipstream_agent_peers %d\n", a.PeerCount())
		fmt.Fprintf(w, "# HELP slipstream_agent_syncs_total Peer sync attempts by result.\n# TYPE slipstream_agent_syncs_total counter\n")
		fmt.Fprintf(w, "slipstream_agent_syncs_total{result=\"ok\"} %d\nslipstream_agent_syncs_total{result=\"failed\"} %d\n", a.syncOK.Load(), a.syncFailed.Load())
		fmt.Fprintf(w, "# TYPE slipstream_agent_full_syncs_total counter\nslipstream_agent_full_syncs_total %d\n", a.fullSyncs.Load())
		fmt.Fprintf(w, "# TYPE slipstream_agent_peer_changes_total counter\nslipstream_agent_peer_changes_total{op=\"upsert\"} %d\nslipstream_agent_peer_changes_total{op=\"remove\"} %d\n", a.peersAdded.Load(), a.peersRemoved.Load())
		fmt.Fprintf(w, "# HELP slipstream_agent_last_sync_timestamp_seconds Last successful sync.\n# TYPE slipstream_agent_last_sync_timestamp_seconds gauge\nslipstream_agent_last_sync_timestamp_seconds %.3f\n", last)
		if v, ok := load(); ok {
			fmt.Fprintf(w, "# TYPE slipstream_agent_load gauge\nslipstream_agent_load %.4f\n", v)
		}
	})
	return mux
}

// NewHTTPServer wraps h with conservative timeouts: these endpoints are
// probed from the internet.
func NewHTTPServer(addr string, h http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      5 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    8 << 10,
	}
}
