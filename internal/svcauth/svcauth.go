// Package svcauth implements HMAC-SHA256 service-to-service request signing:
//
//	X-Slipstream-Service:   billing-webhooks | fleet-prober
//	X-Slipstream-Timestamp: <unix seconds>
//	X-Slipstream-Signature: v1=<hex(HMAC_SHA256(secret, ts + "." + METHOD + "." + path + "." + body))>
package svcauth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"time"
)

const (
	HeaderService   = "X-Slipstream-Service"
	HeaderTimestamp = "X-Slipstream-Timestamp"
	HeaderSignature = "X-Slipstream-Signature"

	ServiceBilling = "billing-webhooks"
	ServiceProber  = "fleet-prober"

	// MaxSkew is the maximum allowed distance between the caller's timestamp
	// and our clock, in either direction.
	MaxSkew = 300 * time.Second
)

var (
	ErrUnknownService = errors.New("svcauth: unknown service")
	ErrBadTimestamp   = errors.New("svcauth: missing or malformed timestamp")
	ErrSkew           = errors.New("svcauth: timestamp outside allowed skew")
	ErrBadSignature   = errors.New("svcauth: signature mismatch")
)

// Sign computes the "v1=<hex>" signature value.
func Sign(secret []byte, timestamp, method, path string, body []byte) string {
	m := hmac.New(sha256.New, secret)
	m.Write([]byte(timestamp))
	m.Write([]byte{'.'})
	m.Write([]byte(method))
	m.Write([]byte{'.'})
	m.Write([]byte(path))
	m.Write([]byte{'.'})
	m.Write(body)
	return "v1=" + hex.EncodeToString(m.Sum(nil))
}

// Verifier checks signed requests against per-service secrets.
type Verifier struct {
	secrets map[string][]byte
	now     func() time.Time
}

// NewVerifier returns a verifier for service name -> shared secret.
func NewVerifier(secrets map[string][]byte) *Verifier {
	return &Verifier{secrets: secrets, now: time.Now}
}

// SetClock overrides the time source (tests).
func (v *Verifier) SetClock(now func() time.Time) { v.now = now }

// Verify authenticates a request. path must exclude the query string.
// The timestamp is checked before the HMAC is computed so stale requests are
// cheap to reject; the signature comparison is constant time.
func (v *Verifier) Verify(service, timestamp, signature, method, path string, body []byte) error {
	secret, ok := v.secrets[service]
	if !ok || len(secret) == 0 {
		return ErrUnknownService
	}
	ts, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil || ts <= 0 {
		return ErrBadTimestamp
	}
	skew := v.now().Sub(time.Unix(ts, 0))
	if skew > MaxSkew || skew < -MaxSkew {
		return ErrSkew
	}
	if !strings.HasPrefix(signature, "v1=") {
		return ErrBadSignature
	}
	want := Sign(secret, timestamp, method, path, body)
	if !hmac.Equal([]byte(want), []byte(signature)) {
		return ErrBadSignature
	}
	return nil
}
