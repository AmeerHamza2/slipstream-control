package auth

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var fastParams = Argon2Params{MemoryKiB: 1024, Iterations: 1, Parallelism: 1, SaltLen: 16, KeyLen: 32}

func TestPasswordHashAndVerify(t *testing.T) {
	ctx := context.Background()
	h := NewHasher(DefaultArgon2Params, 0)
	enc, err := h.Hash(ctx, "correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(enc, "$argon2id$v=19$m=19456,t=2,p=1$") {
		t.Fatalf("unexpected encoding %q", enc)
	}
	if ok, err := h.Verify(ctx, "correct horse battery staple", enc); !ok || err != nil {
		t.Fatalf("verify failed: %v %v", ok, err)
	}
	if ok, _ := h.Verify(ctx, "correct horse battery stapl3", enc); ok {
		t.Fatal("wrong password verified")
	}
	enc2, _ := h.Hash(ctx, "correct horse battery staple")
	if enc == enc2 {
		t.Fatal("salt not random")
	}
	if h.NeedsRehash(enc) {
		t.Fatal("fresh hash needs rehash")
	}
}

func TestPasswordParamsAreReadFromHash(t *testing.T) {
	ctx := context.Background()
	weak := NewHasher(fastParams, 1)
	enc, _ := weak.Hash(ctx, "password-1234")
	strong := NewHasher(DefaultArgon2Params, 1)
	if ok, err := strong.Verify(ctx, "password-1234", enc); !ok || err != nil {
		t.Fatalf("strong hasher cannot verify weak hash: %v", err)
	}
	if !strong.NeedsRehash(enc) {
		t.Fatal("weak hash should need rehash")
	}
}

func TestPasswordRejectsMalformed(t *testing.T) {
	h := NewHasher(fastParams, 1)
	for _, enc := range []string{"", "$argon2i$v=19$m=1024,t=1,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA",
		"$argon2id$v=19$m=99999999,t=1,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA", "$argon2id$v=19$m=1024,t=1,p=1$!!$aGFzaA"} {
		if _, err := h.Verify(context.Background(), "x", enc); err == nil {
			t.Errorf("accepted %q", enc)
		}
	}
}

func newIssuer(t *testing.T) *TokenIssuer {
	t.Helper()
	ti, err := NewTokenIssuer(make([]byte, 32), nil)
	if err != nil {
		t.Fatal(err)
	}
	return ti
}

const uid = "123e4567-e89b-42d3-a456-426614174000"

func TestJWTIssueVerify(t *testing.T) {
	ti := newIssuer(t)
	tok, exp, err := ti.Issue(uid, "fam-1")
	if err != nil || exp != 900 {
		t.Fatalf("issue: %v %d", err, exp)
	}
	parts := strings.Split(tok, ".")
	hdr, _ := base64.RawURLEncoding.DecodeString(parts[0])
	var h map[string]string
	_ = json.Unmarshal(hdr, &h)
	if h["alg"] != "EdDSA" || h["kid"] != ti.KeyID() {
		t.Fatalf("header %v", h)
	}
	c, err := ti.Verify(tok)
	if err != nil {
		t.Fatal(err)
	}
	if c.Subject != uid || c.Issuer != Issuer || c.Audience[0] != Audience || c.ID == "" || c.SessionID != "fam-1" {
		t.Fatalf("claims %+v", c)
	}
}

func TestJWTRejects(t *testing.T) {
	ti := newIssuer(t)
	tok, _, _ := ti.Issue(uid, "f")

	// Expired.
	ti.SetClock(func() time.Time { return time.Now().Add(16 * time.Minute) })
	if _, err := ti.Verify(tok); err == nil {
		t.Error("accepted expired token")
	}
	ti.SetClock(time.Now)

	// Tampered payload.
	parts := strings.Split(tok, ".")
	parts[1] = base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"` + uid + `","iss":"slipstream-control","aud":"slipstream-app","exp":9999999999,"iat":1,"jti":"x"}`))
	if _, err := ti.Verify(strings.Join(parts, ".")); err == nil {
		t.Error("accepted tampered token")
	}

	// Signed by a different key with the same kid.
	other, _ := NewTokenIssuer(append(make([]byte, 31), 1), nil)
	other.kid = ti.kid
	forged, _, _ := other.Issue(uid, "f")
	if _, err := ti.Verify(forged); err == nil {
		t.Error("accepted token signed by another key")
	}

	// alg=none and HS256 confusion.
	none := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims{"sub": uid, "iss": Issuer, "aud": Audience, "exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(), "jti": "x"})
	none.Header["kid"] = ti.kid
	s, _ := none.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if _, err := ti.Verify(s); err == nil {
		t.Error("accepted alg=none")
	}
	hs := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"sub": uid, "iss": Issuer, "aud": Audience, "exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(), "jti": "x"})
	hs.Header["kid"] = ti.kid
	s, _ = hs.SignedString([]byte(ti.priv.Public().(ed25519.PublicKey)))
	if _, err := ti.Verify(s); err == nil {
		t.Error("accepted HS256 key confusion")
	}

	// Wrong audience.
	wrong := jwt.NewWithClaims(jwt.SigningMethodEdDSA, jwt.MapClaims{"sub": uid, "iss": Issuer, "aud": "other", "exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(), "jti": "x"})
	wrong.Header["kid"] = ti.kid
	s, _ = wrong.SignedString(ti.priv)
	if _, err := ti.Verify(s); err == nil {
		t.Error("accepted wrong audience")
	}
}

func TestJWKSAndRotation(t *testing.T) {
	old := newIssuer(t)
	tok, _, _ := old.Issue(uid, "f")
	oldPub := old.priv.Public().(ed25519.PublicKey)

	next, err := NewTokenIssuer(append(make([]byte, 31), 9), []ed25519.PublicKey{oldPub})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := next.Verify(tok); err != nil {
		t.Fatalf("token from previous key rejected: %v", err)
	}
	jwks := next.JWKS()
	if len(jwks.Keys) != 2 || jwks.Keys[0].Kid != next.KeyID() || jwks.Keys[1].Kid != old.KeyID() {
		t.Fatalf("jwks %+v", jwks)
	}
	k := jwks.Keys[0]
	if k.Kty != "OKP" || k.Crv != "Ed25519" || k.Alg != "EdDSA" {
		t.Fatalf("jwk %+v", k)
	}
	x, _ := base64.RawURLEncoding.DecodeString(k.X)
	if len(x) != 32 {
		t.Fatal("x not 32 bytes")
	}
}

func TestThumbprintRFC8037Vector(t *testing.T) {
	// RFC 8037 Appendix A.3.
	x, _ := base64.RawURLEncoding.DecodeString("11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo")
	if got := Thumbprint(x); got != "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k" {
		t.Fatalf("thumbprint %s", got)
	}
}

func TestRefreshTokenAndRotationDecision(t *testing.T) {
	tok, hash := NewRefreshToken()
	raw, err := base64.RawURLEncoding.DecodeString(tok)
	if err != nil || len(raw) != 32 {
		t.Fatalf("token not 32 bytes base64url: %v", err)
	}
	if string(HashRefreshToken(tok)) != string(hash) || len(hash) != 32 {
		t.Fatal("hash mismatch")
	}
	now := time.Now()
	past := now.Add(-time.Minute)
	cases := []struct {
		name string
		rec  RefreshRecord
		want RotationDecision
	}{
		{"current", RefreshRecord{ExpiresAt: now.Add(time.Hour)}, RotateOK},
		{"expired", RefreshRecord{ExpiresAt: now}, RotateExpired},
		{"already rotated (reuse)", RefreshRecord{ExpiresAt: now.Add(time.Hour), RotatedAt: &past}, RotateReuse},
		{"family revoked", RefreshRecord{ExpiresAt: now.Add(time.Hour), RevokedAt: &past}, RotateReuse},
		{"rotated and expired is still reuse", RefreshRecord{ExpiresAt: past, RotatedAt: &past}, RotateReuse},
	}
	for _, c := range cases {
		if got := DecideRotation(c.rec, now); got != c.want {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}
}

// TestHasherFailsFastWhenSaturated: with every slot busy, one caller may
// wait (bounded by QueueTimeout) and any further caller is refused at once,
// so a login storm cannot build an unbounded queue.
func TestHasherFailsFastWhenSaturated(t *testing.T) {
	h := NewHasherWithLimits(fastParams, HashLimits{Concurrency: 1, Queue: 1, QueueTimeout: 150 * time.Millisecond})
	enc, err := h.Hash(context.Background(), "password-1234")
	if err != nil {
		t.Fatal(err)
	}
	h.sem <- struct{}{} // occupy the only slot

	waiter := make(chan error, 1)
	go func() { _, err := h.Verify(context.Background(), "password-1234", enc); waiter <- err }()
	for h.waiting.Load() != 1 {
		time.Sleep(time.Millisecond)
	}
	start := time.Now()
	if _, err := h.Verify(context.Background(), "password-1234", enc); err != ErrBusy {
		t.Fatalf("queue full: err = %v, want ErrBusy", err)
	}
	if err := h.VerifyDummy(context.Background(), "x"); err != ErrBusy {
		t.Fatalf("dummy verify must be admitted like a real one: %v", err)
	}
	if time.Since(start) > 50*time.Millisecond {
		t.Fatal("rejection was not immediate")
	}
	if err := <-waiter; err != ErrBusy {
		t.Fatalf("queued caller: err = %v, want ErrBusy after QueueTimeout", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := h.Hash(ctx, "x"); err != context.Canceled {
		t.Fatalf("cancelled ctx: %v", err)
	}

	// A waiter is admitted as soon as the slot frees up.
	go func() { _, err := h.Verify(context.Background(), "password-1234", enc); waiter <- err }()
	for h.waiting.Load() != 1 {
		time.Sleep(time.Millisecond)
	}
	h.release()
	if err := <-waiter; err != nil {
		t.Fatalf("after release: %v", err)
	}
	if h.waiting.Load() != 0 || len(h.sem) != 0 {
		t.Fatalf("leaked: waiting=%d inflight=%d", h.waiting.Load(), len(h.sem))
	}
	if l := NewHasher(fastParams, 0).Limits(); l.Concurrency < 1 || l.Queue != 4*l.Concurrency {
		t.Fatalf("defaults: %+v", l)
	}
}
