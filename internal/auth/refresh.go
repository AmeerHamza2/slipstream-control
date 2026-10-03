package auth

import (
	"crypto/sha256"
	"encoding/base64"
	"time"
)

// RefreshTokenTTL bounds how long a refresh family can stay idle.
const RefreshTokenTTL = 30 * 24 * time.Hour

// NewRefreshToken returns an opaque 32-byte random token (base64url, no
// padding) and the SHA-256 digest that is the only thing persisted.
func NewRefreshToken() (token string, hash []byte) {
	token = base64.RawURLEncoding.EncodeToString(randomBytes(32))
	return token, HashRefreshToken(token)
}

// HashRefreshToken returns the storage digest of a presented token. A plain
// SHA-256 is sufficient (and lets us index by it): the input is 256 bits of
// entropy, so it is not brute-forceable the way a password is.
func HashRefreshToken(token string) []byte {
	h := sha256.Sum256([]byte(token))
	return h[:]
}

// RefreshRecord is the persisted state of one refresh token.
type RefreshRecord struct {
	ID        string
	UserID    string
	FamilyID  string
	ExpiresAt time.Time
	RotatedAt *time.Time
	RevokedAt *time.Time
}

// RotationDecision is what to do with a presented refresh token.
type RotationDecision int

const (
	// RotateOK: the token is current; mark it rotated and issue a successor.
	RotateOK RotationDecision = iota
	// RotateReuse: the token was already rotated or its family revoked. This
	// is the theft signal: revoke the whole family.
	RotateReuse
	// RotateExpired: reject without side effects.
	RotateExpired
)

// DecideRotation is the pure core of refresh-token rotation. Storage locks
// the row (SELECT ... FOR UPDATE) and then acts on the decision in the same
// transaction, so two concurrent uses of one token cannot both rotate.
func DecideRotation(rec RefreshRecord, now time.Time) RotationDecision {
	if rec.RotatedAt != nil || rec.RevokedAt != nil {
		return RotateReuse
	}
	if !now.Before(rec.ExpiresAt) {
		return RotateExpired
	}
	return RotateOK
}
