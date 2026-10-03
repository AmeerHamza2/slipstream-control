package ipam

import (
	"net/netip"
	"testing"
)

func TestAllocatable(t *testing.T) {
	cases := map[string]bool{
		"10.64.0.0":        false, // network
		"10.64.0.1":        false, // DNS
		"10.64.0.2":        true,
		"10.100.3.4":       true,
		"10.127.255.254":   true,
		"10.127.255.255":   false,
		"10.128.0.1":       false,
		"10.63.255.255":    false,
		"192.168.1.1":      false,
		"::ffff:10.64.0.2": false,
	}
	for s, want := range cases {
		if got := Allocatable(netip.MustParseAddr(s)); got != want {
			t.Errorf("Allocatable(%s)=%v want %v", s, got, want)
		}
	}
	if Size() != 1<<22-3 {
		t.Fatalf("size %d", Size())
	}
}

func TestNext(t *testing.T) {
	a, ok := Next(netip.Addr{}, false)
	if !ok || a.String() != "10.64.0.2" {
		t.Fatalf("first allocation %v", a)
	}
	a, ok = Next(netip.MustParseAddr("10.64.0.255"), true)
	if !ok || a.String() != "10.64.1.0" {
		t.Fatalf("next after .255 = %v", a)
	}
	if _, ok := Next(netip.MustParseAddr("10.127.255.254"), true); ok {
		t.Fatal("expected wrap signal at end of pool")
	}
	// A corrupt "highest" value is ignored rather than trusted.
	if a, _ := Next(netip.MustParseAddr("8.8.8.8"), true); a.String() != "10.64.0.2" {
		t.Fatalf("got %v", a)
	}
}

func TestRandomStaysInPool(t *testing.T) {
	for i := 0; i < 10000; i++ {
		if a := Random(); !Allocatable(a) {
			t.Fatalf("random produced %v", a)
		}
	}
}

func TestPrefix(t *testing.T) {
	if p := Prefix(netip.MustParseAddr("10.64.0.7")); p != "10.64.0.7/32" {
		t.Fatal(p)
	}
	if DNS.String() != "10.64.0.1" {
		t.Fatal("dns")
	}
}

func TestRange(t *testing.T) {
	r, err := NewRange(netip.MustParseAddr("10.100.0.2"), netip.MustParseAddr("10.100.0.5"))
	if err != nil {
		t.Fatal(err)
	}
	if r.Size() != 4 || r.First().String() != "10.100.0.2" || r.Last().String() != "10.100.0.5" {
		t.Fatalf("%v %v %v", r.Size(), r.First(), r.Last())
	}
	for _, bad := range [][2]string{{"10.64.0.1", "10.64.0.9"}, {"10.100.0.5", "10.100.0.2"}, {"10.64.0.2", "10.128.0.1"}} {
		if _, err := NewRange(netip.MustParseAddr(bad[0]), netip.MustParseAddr(bad[1])); err == nil {
			t.Errorf("accepted %v", bad)
		}
	}
	cases := []struct {
		highest string
		any     bool
		skip    uint32
		want    string
		ok      bool
	}{
		{"", false, 0, "10.100.0.2", true},
		{"10.64.0.9", true, 0, "10.100.0.2", true}, // highest outside the range
		{"10.100.0.2", true, 0, "10.100.0.3", true},
		{"10.100.0.2", true, 1, "10.100.0.4", true},
		{"10.100.0.3", true, 9, "10.100.0.4", true}, // skip clamps instead of overflowing
		{"10.100.0.5", true, 0, "", false},          // end of range: caller searches gaps
		{"10.100.0.5", true, 3, "", false},
	}
	for _, c := range cases {
		var h netip.Addr
		if c.highest != "" {
			h = netip.MustParseAddr(c.highest)
		}
		got, ok := r.Next(h, c.any, c.skip)
		if ok != c.ok || (ok && got.String() != c.want) {
			t.Errorf("Next(%s, %v, %d) = %v %v, want %s %v", c.highest, c.any, c.skip, got, ok, c.want, c.ok)
		}
	}
	for i := 0; i < 1000; i++ {
		if a := r.Random(); !r.Contains(a) {
			t.Fatalf("Random out of range: %v", a)
		}
	}
	if last, ok := Default.Next(Default.Last(), true, 0); ok {
		t.Fatalf("Default.Next past the end: %v", last)
	}
}
