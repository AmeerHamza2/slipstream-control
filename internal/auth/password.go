// Package auth implements password hashing (argon2id), EdDSA access tokens
// with a JWKS, and the opaque refresh-token primitives.
package auth

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/argon2"
)

// Argon2Params are the argon2id cost parameters. They are encoded into every
// hash (PHC string format) so they can be raised later without invalidating
// existing hashes; NeedsRehash tells the caller when to upgrade on login.
type Argon2Params struct {
	MemoryKiB   uint32
	Iterations  uint32
	Parallelism uint8
	SaltLen     uint32
	KeyLen      uint32
}

// DefaultArgon2Params follows the OWASP Password Storage Cheat Sheet
// recommendation for argon2id (19 MiB, t=2, p=1).
var DefaultArgon2Params = Argon2Params{MemoryKiB: 19 * 1024, Iterations: 2, Parallelism: 1, SaltLen: 16, KeyLen: 32}

// ErrInvalidHash means a stored hash could not be parsed.
var ErrInvalidHash = errors.New("auth: invalid password hash encoding")

// Hasher hashes and verifies passwords. Argon2id is deliberately expensive
// (MemoryKiB of RAM and tens of milliseconds of one core per call), so the
// Hasher admits at most Concurrency computations at a time and at most Queue
// callers waiting for a slot, each for at most QueueTimeout. Anything beyond
// that fails fast with ErrBusy, which the API turns into 503 + Retry-After:
// under a login storm a replica sheds load in microseconds instead of
// building an unbounded queue whose every member eventually times out.
type Hasher struct {
	params  Argon2Params
	sem     chan struct{}
	waiting atomic.Int64
	limits  HashLimits
	dummy   string
}

// HashLimits bounds concurrent hashing. Zero values pick defaults:
// Concurrency = GOMAXPROCS (argon2 with p=1 is single-threaded and CPU
// bound, so more only adds memory and latency), Queue = 4*Concurrency,
// QueueTimeout = 1s.
type HashLimits struct {
	Concurrency  int
	Queue        int
	QueueTimeout time.Duration
}

// ErrBusy means the hashing capacity is saturated; retry shortly.
var ErrBusy = errors.New("auth: password hashing capacity saturated")

// NewHasher returns a Hasher using p, allowing up to maxConcurrent hashes at
// once (<=0 means GOMAXPROCS) with default queueing limits.
func NewHasher(p Argon2Params, maxConcurrent int) *Hasher {
	return NewHasherWithLimits(p, HashLimits{Concurrency: maxConcurrent})
}

// NewHasherWithLimits returns a Hasher with explicit admission limits.
func NewHasherWithLimits(p Argon2Params, l HashLimits) *Hasher {
	if l.Concurrency <= 0 {
		l.Concurrency = runtime.GOMAXPROCS(0)
	}
	if l.Queue <= 0 {
		l.Queue = 4 * l.Concurrency
	}
	if l.QueueTimeout <= 0 {
		l.QueueTimeout = time.Second
	}
	h := &Hasher{params: p, sem: make(chan struct{}, l.Concurrency), limits: l}
	// A real hash of a random password, used to equalise timing when the
	// account does not exist (prevents user enumeration via latency).
	h.dummy, _ = h.hash(context.Background(), base64.StdEncoding.EncodeToString(randomBytes(16)))
	return h
}

// Limits returns the effective admission limits.
func (h *Hasher) Limits() HashLimits { return h.limits }

func (h *Hasher) acquire(ctx context.Context) error {
	select {
	case h.sem <- struct{}{}:
		return nil
	default:
	}
	if h.waiting.Add(1) > int64(h.limits.Queue) {
		h.waiting.Add(-1)
		return ErrBusy
	}
	defer h.waiting.Add(-1)
	t := time.NewTimer(h.limits.QueueTimeout)
	defer t.Stop()
	select {
	case h.sem <- struct{}{}:
		return nil
	case <-t.C:
		return ErrBusy
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (h *Hasher) release() { <-h.sem }

// Hash returns a PHC-formatted argon2id hash of password.
func (h *Hasher) Hash(ctx context.Context, password string) (string, error) {
	return h.hash(ctx, password)
}

func (h *Hasher) hash(ctx context.Context, password string) (string, error) {
	if err := h.acquire(ctx); err != nil {
		return "", err
	}
	defer h.release()
	p := h.params
	salt := randomBytes(int(p.SaltLen))
	key := argon2.IDKey([]byte(password), salt, p.Iterations, p.MemoryKiB, p.Parallelism, p.KeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, p.MemoryKiB, p.Iterations, p.Parallelism,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key)), nil
}

// Verify reports whether password matches encoded, comparing in constant time.
func (h *Hasher) Verify(ctx context.Context, password, encoded string) (bool, error) {
	p, salt, want, err := decodeHash(encoded)
	if err != nil {
		return false, err
	}
	if err := h.acquire(ctx); err != nil {
		return false, err
	}
	defer h.release()
	got := argon2.IDKey([]byte(password), salt, p.Iterations, p.MemoryKiB, p.Parallelism, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}

// VerifyDummy burns the same CPU/memory as a real verification. Call it when
// the user does not exist so response timing does not reveal that. It is
// admitted exactly like a real verification, so it returns ErrBusy under the
// same conditions (an unknown email must not be answerable when a known one
// is not).
func (h *Hasher) VerifyDummy(ctx context.Context, password string) error {
	_, err := h.Verify(ctx, password, h.dummy)
	return err
}

// NeedsRehash reports whether encoded was produced with weaker parameters
// than the hasher's current ones.
func (h *Hasher) NeedsRehash(encoded string) bool {
	p, _, _, err := decodeHash(encoded)
	if err != nil {
		return true
	}
	return p.MemoryKiB < h.params.MemoryKiB || p.Iterations < h.params.Iterations || p.Parallelism < h.params.Parallelism
}

func decodeHash(encoded string) (Argon2Params, []byte, []byte, error) {
	var p Argon2Params
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		return p, nil, nil, ErrInvalidHash
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return p, nil, nil, ErrInvalidHash
	}
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &p.MemoryKiB, &p.Iterations, &p.Parallelism); err != nil {
		return p, nil, nil, ErrInvalidHash
	}
	// Refuse absurd parameters from a tampered row rather than OOM.
	if p.MemoryKiB == 0 || p.MemoryKiB > 1<<20 || p.Iterations == 0 || p.Iterations > 100 || p.Parallelism == 0 {
		return p, nil, nil, ErrInvalidHash
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil || len(salt) < 8 {
		return p, nil, nil, ErrInvalidHash
	}
	key, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(key) < 16 || len(key) > 128 {
		return p, nil, nil, ErrInvalidHash
	}
	p.SaltLen, p.KeyLen = uint32(len(salt)), uint32(len(key))
	return p, salt, key, nil
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	return b
}
