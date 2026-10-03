package auth

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/ameerhamza2/slipstream-control/internal/ids"
)

const (
	Issuer         = "slipstream-control"
	Audience       = "slipstream-app"
	AccessTokenTTL = 15 * time.Minute
)

// ErrInvalidToken is returned for any access token that fails verification.
// Callers should not distinguish reasons to clients.
var ErrInvalidToken = errors.New("auth: invalid access token")

// Claims are the access-token claims. sid (session id) is the refresh-token
// family the token was minted from, so logout can revoke "the current family".
type Claims struct {
	SessionID string `json:"sid,omitempty"`
	jwt.RegisteredClaims
}

// JWK is an RFC 8037 OKP public key.
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
}

// JWKS is a JSON Web Key Set.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// TokenIssuer signs and verifies access tokens. It signs with one Ed25519 key
// and verifies against that key plus any previous public keys (rotation).
type TokenIssuer struct {
	priv   ed25519.PrivateKey
	kid    string
	verify map[string]ed25519.PublicKey
	jwks   JWKS
	now    func() time.Time
	parser *jwt.Parser
}

// NewTokenIssuer builds an issuer from a 32-byte Ed25519 seed and optional
// previous public keys that remain valid for verification.
func NewTokenIssuer(seed []byte, previous []ed25519.PublicKey) (*TokenIssuer, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("auth: JWT signing seed must be %d bytes, got %d", ed25519.SeedSize, len(seed))
	}
	priv := ed25519.NewKeyFromSeed(seed)
	ti := &TokenIssuer{priv: priv, verify: map[string]ed25519.PublicKey{}, now: time.Now}
	pubs := append([]ed25519.PublicKey{priv.Public().(ed25519.PublicKey)}, previous...)
	for i, pub := range pubs {
		if len(pub) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("auth: previous public key %d has wrong length", i)
		}
		kid := Thumbprint(pub)
		if i == 0 {
			ti.kid = kid
		}
		ti.verify[kid] = pub
		ti.jwks.Keys = append(ti.jwks.Keys, JWK{Kty: "OKP", Crv: "Ed25519", X: base64.RawURLEncoding.EncodeToString(pub), Kid: kid, Use: "sig", Alg: "EdDSA"})
	}
	ti.parser = jwt.NewParser(
		jwt.WithValidMethods([]string{jwt.SigningMethodEdDSA.Alg()}),
		jwt.WithIssuer(Issuer),
		jwt.WithAudience(Audience),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
		jwt.WithLeeway(30*time.Second),
		jwt.WithTimeFunc(func() time.Time { return ti.now() }),
	)
	return ti, nil
}

// Thumbprint is the RFC 7638 JWK thumbprint of an Ed25519 public key, used as kid.
func Thumbprint(pub ed25519.PublicKey) string {
	// Members in lexicographic order, no whitespace, per RFC 7638 section 3.2.
	canon := `{"crv":"Ed25519","kty":"OKP","x":"` + base64.RawURLEncoding.EncodeToString(pub) + `"}`
	sum := sha256.Sum256([]byte(canon))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// KeyID returns the kid of the current signing key.
func (t *TokenIssuer) KeyID() string { return t.kid }

// JWKS returns the published key set.
func (t *TokenIssuer) JWKS() JWKS { return t.jwks }

// JWKSJSON returns the JWKS marshalled once.
func (t *TokenIssuer) JWKSJSON() []byte {
	b, _ := json.Marshal(t.jwks)
	return b
}

// SetClock overrides the time source (tests).
func (t *TokenIssuer) SetClock(now func() time.Time) { t.now = now }

// Issue mints an access token for userID within refresh family sessionID.
func (t *TokenIssuer) Issue(userID, sessionID string) (token string, expiresIn int, err error) {
	now := t.now().UTC().Truncate(time.Second)
	claims := Claims{
		SessionID: sessionID,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    Issuer,
			Audience:  jwt.ClaimStrings{Audience},
			Subject:   userID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(AccessTokenTTL)),
			ID:        ids.New(),
		},
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	tok.Header["kid"] = t.kid
	s, err := tok.SignedString(t.priv)
	if err != nil {
		return "", 0, err
	}
	return s, int(AccessTokenTTL / time.Second), nil
}

// Verify validates signature, algorithm, kid, iss, aud, exp and iat.
func (t *TokenIssuer) Verify(token string) (*Claims, error) {
	var claims Claims
	_, err := t.parser.ParseWithClaims(token, &claims, func(tok *jwt.Token) (any, error) {
		kid, _ := tok.Header["kid"].(string)
		pub, ok := t.verify[kid]
		if !ok {
			return nil, errors.New("unknown kid")
		}
		return pub, nil
	})
	if err != nil || !ids.Valid(claims.Subject) || claims.ID == "" {
		return nil, ErrInvalidToken
	}
	return &claims, nil
}
