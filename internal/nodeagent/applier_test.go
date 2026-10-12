package nodeagent

import (
	"context"
	"os"
	"strings"
	"testing"
)

func TestParseDump(t *testing.T) {
	dump := "privkey\tpubkey\t51820\toff\n" +
		"K2\tPSK2\t198.51.100.7:4242\t10.64.0.2/32\t1700000000\t100\t200\t25\n" +
		"K3\t(none)\t(none)\t(none)\t0\t0\t0\toff\n"
	got, err := parseDump([]byte(dump))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got["K2"].PresharedKey != "PSK2" || got["K2"].AllowedIP != "10.64.0.2/32" {
		t.Fatalf("K2: %+v", got["K2"])
	}
	if got["K3"].PresharedKey != "" || got["K3"].AllowedIP != "" {
		t.Fatalf("K3: %+v", got["K3"])
	}
	if _, err := parseDump([]byte("iface\nbroken\n")); err == nil {
		t.Fatal("malformed line accepted")
	}
}

// TestWGApplierCommands checks the exact wg(8) invocations: batched peers,
// preshared keys passed as 0600 files (never on the command line, where any
// local user could read them from /proc), files gone afterwards, removals
// batched.
func TestWGApplierCommands(t *testing.T) {
	var calls [][]string
	var pskSeen []string
	run := func(_ context.Context, _ []byte, name string, args ...string) ([]byte, error) {
		calls = append(calls, append([]string{name}, args...))
		for i, a := range args {
			if a == "preshared-key" {
				f := args[i+1]
				st, err := os.Stat(f)
				if err != nil {
					t.Errorf("psk file missing during the wg call: %v", err)
					continue
				}
				if st.Mode().Perm() != 0o600 {
					t.Errorf("psk file mode %v, want 0600", st.Mode().Perm())
				}
				b, _ := os.ReadFile(f)
				pskSeen = append(pskSeen, strings.TrimSpace(string(b)))
				pskSeen = append(pskSeen, f)
			}
		}
		return nil, nil
	}
	w := &WGApplier{Interface: "wg0", Run: run, Batch: 2, TempDir: t.TempDir()}
	ups := []AppliedPeer{
		{PublicKey: "A", AllowedIP: "10.64.0.2/32", PresharedKey: "SECRET-A"},
		{PublicKey: "B", AllowedIP: "10.64.0.3/32", PresharedKey: "SECRET-B"},
		{PublicKey: "C", AllowedIP: "10.64.0.4/32"},
	}
	if err := w.Apply(context.Background(), ups, []string{"Z", "Y", "X"}); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 4 {
		t.Fatalf("got %d wg calls, want 2 upsert batches + 2 removal batches: %v", len(calls), calls)
	}
	for _, c := range calls {
		if strings.Contains(strings.Join(c, " "), "SECRET") {
			t.Fatalf("preshared key on the command line: %v", c)
		}
	}
	if got := strings.Join(calls[2], " "); got != "wg set wg0 peer X remove peer Y remove" {
		t.Fatalf("removal batch = %q", got)
	}
	if pskSeen[0] != "SECRET-A" || pskSeen[2] != "SECRET-B" {
		t.Fatalf("psk files had %v", pskSeen)
	}
	for i := 1; i < len(pskSeen); i += 2 {
		if _, err := os.Stat(pskSeen[i]); !os.IsNotExist(err) {
			t.Fatalf("psk file %s left on disk after the call", pskSeen[i])
		}
	}
	if !strings.Contains(strings.Join(calls[1], " "), "peer C allowed-ips 10.64.0.4/32") {
		t.Fatalf("peer without psk: %v", calls[1])
	}
}
