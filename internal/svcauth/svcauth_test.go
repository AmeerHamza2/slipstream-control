package svcauth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"testing"
	"time"
)

func TestSignMatchesContract(t *testing.T) {
	body := []byte(`{"a":1}`)
	m := hmac.New(sha256.New, []byte("s3cret"))
	m.Write([]byte("1700000000.POST./internal/v1/entitlements." + string(body)))
	want := "v1=" + hex.EncodeToString(m.Sum(nil))
	if got := Sign([]byte("s3cret"), "1700000000", "POST", "/internal/v1/entitlements", body); got != want {
		t.Fatalf("got %s want %s", got, want)
	}
}

func TestVerify(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	v := NewVerifier(map[string][]byte{ServiceBilling: []byte("b"), ServiceProber: []byte("p")})
	v.SetClock(func() time.Time { return now })
	ts := strconv.FormatInt(now.Unix(), 10)
	body := []byte(`{"x":1}`)
	path := "/internal/v1/entitlements"
	good := Sign([]byte("b"), ts, "POST", path, body)

	if err := v.Verify(ServiceBilling, ts, good, "POST", path, body); err != nil {
		t.Fatalf("valid request rejected: %v", err)
	}
	cases := []struct {
		name                    string
		svc, ts, sig, method, p string
		body                    []byte
		want                    error
	}{
		{"unknown service", "evil", ts, good, "POST", path, body, ErrUnknownService},
		{"other service's secret", ServiceProber, ts, good, "POST", path, body, ErrBadSignature},
		{"tampered body", ServiceBilling, ts, good, "POST", path, []byte(`{"x":2}`), ErrBadSignature},
		{"different path", ServiceBilling, ts, good, "POST", "/internal/v1/servers/heartbeats", body, ErrBadSignature},
		{"different method", ServiceBilling, ts, good, "PUT", path, body, ErrBadSignature},
		{"missing prefix", ServiceBilling, ts, good[3:], "POST", path, body, ErrBadSignature},
		{"bad timestamp", ServiceBilling, "abc", good, "POST", path, body, ErrBadTimestamp},
		{"too old", ServiceBilling, strconv.FormatInt(now.Add(-301*time.Second).Unix(), 10), good, "POST", path, body, ErrSkew},
		{"too far in future", ServiceBilling, strconv.FormatInt(now.Add(301*time.Second).Unix(), 10), good, "POST", path, body, ErrSkew},
	}
	for _, c := range cases {
		if err := v.Verify(c.svc, c.ts, c.sig, c.method, c.p, c.body); !errors.Is(err, c.want) {
			t.Errorf("%s: got %v want %v", c.name, err, c.want)
		}
	}
	// Edge of the window is accepted.
	edge := strconv.FormatInt(now.Add(-300*time.Second).Unix(), 10)
	if err := v.Verify(ServiceBilling, edge, Sign([]byte("b"), edge, "POST", path, body), "POST", path, body); err != nil {
		t.Fatalf("300s skew rejected: %v", err)
	}
}
