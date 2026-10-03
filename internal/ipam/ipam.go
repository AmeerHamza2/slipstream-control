// Package ipam allocates WireGuard tunnel addresses from 10.64.0.0/10.
//
// Uniqueness is enforced by the database (UNIQUE(tunnel_ip)); this package
// only proposes candidates. The store inserts a candidate and, on a unique
// violation, asks for the next one, which makes allocation race-safe across
// any number of API replicas without a global lock. Once the sequential
// cursor reaches the end of the range, the store reuses addresses freed by
// deleted devices with an index-backed gap search (see store.CreateDevice).
package ipam

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net/netip"
)

var (
	// Pool is the tunnel address pool.
	Pool = netip.MustParsePrefix("10.64.0.0/10")
	// DNS is the in-tunnel resolver address (reserved, never allocated).
	DNS = netip.MustParseAddr("10.64.0.1")

	// ErrExhausted means no candidate could be found.
	ErrExhausted = errors.New("ipam: address pool exhausted")
)

var (
	first = toUint(Pool.Addr()) + 2                    // skip .0 (network) and .1 (DNS/gateway)
	last  = toUint(Pool.Addr()) + (1 << (32 - 10)) - 2 // skip the final (broadcast-style) address
)

func toUint(a netip.Addr) uint32 { b := a.As4(); return binary.BigEndian.Uint32(b[:]) }

func fromUint(u uint32) netip.Addr {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], u)
	return netip.AddrFrom4(b)
}

// Range is an inclusive block of allocatable addresses. Default is the whole
// pool; smaller ranges exist for tests (exhaustion) and for carving the pool
// up per region later.
type Range struct{ lo, hi uint32 }

// Default is every allocatable address of Pool.
var Default = Range{first, last}

// NewRange returns [lo, hi]; both must be allocatable and lo <= hi.
func NewRange(lo, hi netip.Addr) (Range, error) {
	if !Allocatable(lo) || !Allocatable(hi) || toUint(lo) > toUint(hi) {
		return Range{}, errors.New("ipam: range must be allocatable addresses with lo <= hi")
	}
	return Range{toUint(lo), toUint(hi)}, nil
}

// First and Last are the range bounds.
func (r Range) First() netip.Addr { return fromUint(r.lo) }
func (r Range) Last() netip.Addr  { return fromUint(r.hi) }

// Size is the number of addresses in the range.
func (r Range) Size() uint32 { return r.hi - r.lo + 1 }

// Contains reports whether a lies in the range.
func (r Range) Contains(a netip.Addr) bool {
	if !a.Is4() {
		return false
	}
	u := toUint(a)
	return u >= r.lo && u <= r.hi
}

// Next returns highest+1+skip, or First when nothing is allocated (any false
// or highest outside the range). ok is false when that would run past the
// end of the range; callers then search for a gap left by deleted devices.
// skip spreads concurrent allocators that all read the same maximum.
func (r Range) Next(highest netip.Addr, any bool, skip uint32) (netip.Addr, bool) {
	if !any || !r.Contains(highest) {
		return fromUint(r.lo), true
	}
	u := uint64(toUint(highest)) + 1 + uint64(skip)
	if u > uint64(r.hi) {
		if skip > 0 && toUint(highest) < r.hi {
			return fromUint(toUint(highest) + 1), true
		}
		return netip.Addr{}, false
	}
	return fromUint(uint32(u)), true
}

// Random returns a uniformly random address of the range.
func (r Range) Random() netip.Addr {
	var b [4]byte
	_, _ = rand.Read(b[:])
	return fromUint(r.lo + binary.BigEndian.Uint32(b[:])%r.Size())
}

// Allocatable reports whether a is a host address devices may receive.
func Allocatable(a netip.Addr) bool {
	if !a.Is4() || !Pool.Contains(a) {
		return false
	}
	u := toUint(a)
	return u >= first && u <= last
}

// Size is the number of allocatable addresses.
func Size() uint32 { return Default.Size() }

// Next is Default.Next without skip, kept for callers of the original API:
// the address following highest, or the first address when nothing is
// allocated; ok is false when highest is the last address in the pool.
func Next(highest netip.Addr, any bool) (netip.Addr, bool) {
	if any && !Allocatable(highest) {
		any = false
	}
	return Default.Next(highest, any, 0)
}

// Random returns a uniformly random allocatable address.
func Random() netip.Addr { return Default.Random() }

// Prefix formats a as a /32 for WireGuard AllowedIPs / Address.
func Prefix(a netip.Addr) string { return netip.PrefixFrom(a, 32).String() }
