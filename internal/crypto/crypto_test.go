package crypto

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

func testKeyring(t *testing.T) *Keyring {
	t.Helper()
	kr, err := NewKeyringFromBase64(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	return kr
}

func TestEnvelopeRoundTrip(t *testing.T) {
	kr := testKeyring(t)
	ct, err := kr.Encrypt([]byte("hunter2"), []byte("row:1"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(ct, "v1:") {
		t.Fatalf("missing key id prefix: %q", ct)
	}
	pt, err := kr.Decrypt(ct, []byte("row:1"))
	if err != nil || string(pt) != "hunter2" {
		t.Fatalf("got %q, %v", pt, err)
	}
	ct2, _ := kr.Encrypt([]byte("hunter2"), []byte("row:1"))
	if ct == ct2 {
		t.Fatal("nonce reuse: identical ciphertexts")
	}
}

func TestEnvelopeRejectsTamperingAndWrongContext(t *testing.T) {
	kr := testKeyring(t)
	ct, _ := kr.Encrypt([]byte("secret"), []byte("row:1"))
	if _, err := kr.Decrypt(ct, []byte("row:2")); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("wrong aad: %v", err)
	}
	raw, _ := base64.StdEncoding.DecodeString(strings.TrimPrefix(ct, "v1:"))
	raw[len(raw)-1] ^= 1
	if _, err := kr.Decrypt("v1:"+base64.StdEncoding.EncodeToString(raw), []byte("row:1")); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("tampered: %v", err)
	}
	if _, err := kr.Decrypt("v9:"+strings.TrimPrefix(ct, "v1:"), []byte("row:1")); !errors.Is(err, ErrUnknownKeyID) {
		t.Fatalf("unknown kid: %v", err)
	}
	for _, bad := range []string{"", "nocolon", "v1:!!!", "v1:AAAA"} {
		if _, err := kr.Decrypt(bad, nil); !errors.Is(err, ErrMalformed) {
			t.Fatalf("%q: %v", bad, err)
		}
	}
}

func TestKeyRotation(t *testing.T) {
	k1, k2 := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)
	old, _ := NewKeyring("v1", map[string][]byte{"v1": k1})
	ct, _ := old.Encrypt([]byte("x"), nil)
	rotated, err := NewKeyring("v2", map[string][]byte{"v1": k1, "v2": k2})
	if err != nil {
		t.Fatal(err)
	}
	if pt, err := rotated.Decrypt(ct, nil); err != nil || string(pt) != "x" {
		t.Fatalf("old ciphertext unreadable after rotation: %v", err)
	}
	ct2, _ := rotated.Encrypt([]byte("y"), nil)
	if !strings.HasPrefix(ct2, "v2:") {
		t.Fatalf("not encrypted under primary: %q", ct2)
	}
}

func TestKeyringValidation(t *testing.T) {
	if _, err := NewKeyringFromBase64(base64.StdEncoding.EncodeToString(make([]byte, 16))); err == nil {
		t.Fatal("accepted 16-byte key")
	}
	if _, err := NewKeyringFromBase64("%%%"); err == nil {
		t.Fatal("accepted bad base64")
	}
}

func TestShadowsocksPassword(t *testing.T) {
	master := []byte("master-secret")
	uid := "123e4567-e89b-42d3-a456-426614174000"
	got := ShadowsocksPassword(master, uid)
	m := hmac.New(sha256.New, master)
	m.Write([]byte("ss-user:" + uid))
	want := base64.StdEncoding.EncodeToString(m.Sum(nil))
	if got != want || len(got) != 44 {
		t.Fatalf("got %q (%d), want %q", got, len(got), want)
	}
	if ShadowsocksPassword(master, "other") == got {
		t.Fatal("password not user-specific")
	}
	if ShadowsocksPassword([]byte("other"), uid) == got {
		t.Fatal("password not server-specific")
	}
}

func TestValidWireGuardKey(t *testing.T) {
	good := GeneratePresharedKey()
	if !ValidWireGuardKey(good) {
		t.Fatalf("rejected %q", good)
	}
	bad := []string{
		"",
		base64.StdEncoding.EncodeToString(make([]byte, 31)),
		base64.StdEncoding.EncodeToString(make([]byte, 32)), // all zero
		base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0xfb}, 32)) + "=",
		strings.Repeat("A", 43) + "!",
	}
	for _, b := range bad {
		if ValidWireGuardKey(b) {
			t.Errorf("accepted %q", b)
		}
	}
}
