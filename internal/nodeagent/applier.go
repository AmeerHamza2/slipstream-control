package nodeagent

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// AppliedPeer is a peer as configured on the WireGuard interface.
type AppliedPeer struct {
	PublicKey    string
	AllowedIP    string // the single /32 the agent sets
	PresharedKey string
}

// Applier changes the node's WireGuard peer table.
type Applier interface {
	// Current returns the peers on the interface, keyed by public key.
	Current(ctx context.Context) (map[string]AppliedPeer, error)
	// Apply adds or updates upserts and removes the given public keys.
	Apply(ctx context.Context, upserts []AppliedPeer, removals []string) error
}

// --- in-memory applier: dry-run mode and tests ---

// MemoryApplier keeps the peer table in memory. With a Log function it is the
// agent's dry-run mode: every change is reported, nothing touches the kernel.
type MemoryApplier struct {
	mu    sync.Mutex
	peers map[string]AppliedPeer
	// Log, if set, is called once per change.
	Log func(action string, p AppliedPeer)
}

// NewMemoryApplier returns an empty in-memory peer table.
func NewMemoryApplier() *MemoryApplier {
	return &MemoryApplier{peers: map[string]AppliedPeer{}}
}

func (m *MemoryApplier) Current(context.Context) (map[string]AppliedPeer, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make(map[string]AppliedPeer, len(m.peers))
	for k, v := range m.peers {
		out[k] = v
	}
	return out, nil
}

func (m *MemoryApplier) Apply(_ context.Context, upserts []AppliedPeer, removals []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, p := range upserts {
		m.peers[p.PublicKey] = p
		if m.Log != nil {
			m.Log("add", p)
		}
	}
	for _, k := range removals {
		if p, ok := m.peers[k]; ok {
			delete(m.peers, k)
			if m.Log != nil {
				m.Log("remove", p)
			}
		}
	}
	return nil
}

// Set seeds or overwrites a peer directly (tests: simulate drift).
func (m *MemoryApplier) Set(p AppliedPeer) {
	m.mu.Lock()
	m.peers[p.PublicKey] = p
	m.mu.Unlock()
}

// --- wg(8) applier: production ---

// Runner runs a command with optional stdin and returns its stdout.
type Runner func(ctx context.Context, stdin []byte, name string, args ...string) ([]byte, error)

func execRunner(ctx context.Context, stdin []byte, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w: %s", name, args[0], err, strings.TrimSpace(stderr.String()))
	}
	return out, nil
}

// WGApplier drives a kernel (or wireguard-go) interface with the standard
// wg(8) tool. That keeps the agent independent of the WireGuard
// implementation and avoids a netlink dependency; wgctrl would be the
// in-process alternative.
type WGApplier struct {
	Interface string
	// Run executes commands; nil uses os/exec. Replaced in tests.
	Run Runner
	// Batch is how many peers go into one `wg set` call. Default 256: a full
	// sync of 100k peers is then ~400 execs rather than 100k.
	Batch int
	// TempDir holds preshared-key files for the life of one wg call. Default
	// os.TempDir(); on a node it should be a tmpfs so keys never hit disk.
	TempDir string
}

func (w *WGApplier) run() Runner {
	if w.Run != nil {
		return w.Run
	}
	return execRunner
}

// Current parses `wg show <iface> dump`. The first line is the interface;
// each following line is: public-key preshared-key endpoint allowed-ips
// latest-handshake rx tx keepalive.
func (w *WGApplier) Current(ctx context.Context) (map[string]AppliedPeer, error) {
	out, err := w.run()(ctx, nil, "wg", "show", w.Interface, "dump")
	if err != nil {
		return nil, err
	}
	return parseDump(out)
}

func parseDump(out []byte) (map[string]AppliedPeer, error) {
	peers := map[string]AppliedPeer{}
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	first := true
	for sc.Scan() {
		if first {
			first = false // interface line
			continue
		}
		f := strings.Split(sc.Text(), "\t")
		if len(f) < 4 {
			return nil, fmt.Errorf("nodeagent: unexpected wg dump line with %d fields", len(f))
		}
		p := AppliedPeer{PublicKey: f[0], AllowedIP: f[3]}
		if f[1] != "(none)" {
			p.PresharedKey = f[1]
		}
		if p.AllowedIP == "(none)" {
			p.AllowedIP = ""
		}
		peers[p.PublicKey] = p
	}
	return peers, sc.Err()
}

// Apply batches peers into `wg set` calls. Preshared keys cannot go on the
// command line (any local user could read them from /proc), so each is
// written to a 0600 file in a private 0700 directory that is removed as soon
// as the call returns.
func (w *WGApplier) Apply(ctx context.Context, upserts []AppliedPeer, removals []string) error {
	batch := w.Batch
	if batch <= 0 {
		batch = 256
	}
	for len(upserts) > 0 {
		n := min(batch, len(upserts))
		if err := w.setPeers(ctx, upserts[:n]); err != nil {
			return err
		}
		upserts = upserts[n:]
	}
	sorted := append([]string(nil), removals...)
	sort.Strings(sorted)
	for len(sorted) > 0 {
		n := min(batch, len(sorted))
		args := []string{"set", w.Interface}
		for _, k := range sorted[:n] {
			args = append(args, "peer", k, "remove")
		}
		if _, err := w.run()(ctx, nil, "wg", args...); err != nil {
			return err
		}
		sorted = sorted[n:]
	}
	return nil
}

func (w *WGApplier) setPeers(ctx context.Context, peers []AppliedPeer) error {
	dir, err := os.MkdirTemp(w.TempDir, "slipstream-psk-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	args := []string{"set", w.Interface}
	for i, p := range peers {
		if p.PublicKey == "" || p.AllowedIP == "" {
			return errors.New("nodeagent: peer without public key or allowed ip")
		}
		args = append(args, "peer", p.PublicKey)
		if p.PresharedKey != "" {
			f := filepath.Join(dir, fmt.Sprintf("%d.psk", i))
			if err := os.WriteFile(f, []byte(p.PresharedKey+"\n"), 0o600); err != nil {
				return err
			}
			args = append(args, "preshared-key", f)
		}
		args = append(args, "allowed-ips", p.AllowedIP)
	}
	_, err = w.run()(ctx, nil, "wg", args...)
	return err
}
