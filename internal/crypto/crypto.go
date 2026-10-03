// Package crypto holds the application-level cryptography: AES-256-GCM
// envelope encryption for secrets at rest, the Shadowsocks per-user password
// derivation, and small helpers for random secrets and WireGuard keys.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// KeySize is the required length of a data-encryption key (AES-256).
const KeySize = 32

var (
	// ErrUnknownKeyID means the ciphertext names a key the keyring does not hold.
	ErrUnknownKeyID = errors.New("crypto: unknown key id")
	// ErrMalformed means the ciphertext envelope could not be parsed.
	ErrMalformed = errors.New("crypto: malformed ciphertext")
	// ErrDecrypt means authentication failed (wrong key, wrong AAD or tampering).
	ErrDecrypt = errors.New("crypto: decryption failed")
)

// Keyring encrypts with a primary key and decrypts with any known key, so the
// "v1:" key-id prefix lets keys be rotated without a flag day: add "v2",
// make it primary, re-encrypt lazily or in a batch, then retire "v1".
type Keyring struct {
	primary string
	aeads   map[string]cipher.AEAD
}

// NewKeyring builds a keyring from key id -> raw 32-byte key.
func NewKeyring(primary string, keys map[string][]byte) (*Keyring, error) {
	if _, ok := keys[primary]; !ok {
		return nil, fmt.Errorf("crypto: primary key %q not in keyring", primary)
	}
	kr := &Keyring{primary: primary, aeads: make(map[string]cipher.AEAD, len(keys))}
	for id, k := range keys {
		if id == "" || strings.Contains(id, ":") {
			return nil, fmt.Errorf("crypto: invalid key id %q", id)
		}
		if len(k) != KeySize {
			return nil, fmt.Errorf("crypto: key %q must be %d bytes, got %d", id, KeySize, len(k))
		}
		block, err := aes.NewCipher(k)
		if err != nil {
			return nil, err
		}
		aead, err := cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}
		kr.aeads[id] = aead
	}
	return kr, nil
}

// NewKeyringFromBase64 is the common case: a single "v1" key from env.
func NewKeyringFromBase64(b64 string) (*Keyring, error) {
	k, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil {
		return nil, fmt.Errorf("crypto: DATA_ENCRYPTION_KEY is not valid base64: %w", err)
	}
	return NewKeyring("v1", map[string][]byte{"v1": k})
}

// Encrypt seals plaintext as "<kid>:<base64(nonce|ciphertext)>". The aad
// binds the ciphertext to its context (e.g. the row it belongs to) so a value
// copied into another row fails to decrypt.
func (k *Keyring) Encrypt(plaintext, aad []byte) (string, error) {
	aead := k.aeads[k.primary]
	nonce := make([]byte, aead.NonceSize(), aead.NonceSize()+len(plaintext)+aead.Overhead())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	sealed := aead.Seal(nonce, nonce, plaintext, aad)
	return k.primary + ":" + base64.StdEncoding.EncodeToString(sealed), nil
}

// Decrypt opens a value produced by Encrypt.
func (k *Keyring) Decrypt(envelope string, aad []byte) ([]byte, error) {
	kid, b64, ok := strings.Cut(envelope, ":")
	if !ok {
		return nil, ErrMalformed
	}
	aead, ok := k.aeads[kid]
	if !ok {
		return nil, ErrUnknownKeyID
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(raw) < aead.NonceSize()+aead.Overhead() {
		return nil, ErrMalformed
	}
	pt, err := aead.Open(nil, raw[:aead.NonceSize()], raw[aead.NonceSize():], aad)
	if err != nil {
		return nil, ErrDecrypt
	}
	return pt, nil
}

// ShadowsocksPassword derives the per-user, per-server Shadowsocks password:
// base64std(HMAC_SHA256(master_secret, "ss-user:" + user_id)), 44 chars.
// The HMAC key is the master secret string's bytes exactly as configured on
// the node, so the node can run the same derivation without a database.
func ShadowsocksPassword(masterSecret []byte, userID string) string {
	m := hmac.New(sha256.New, masterSecret)
	m.Write([]byte("ss-user:" + userID))
	return base64.StdEncoding.EncodeToString(m.Sum(nil))
}

// RandomBase64 returns n random bytes, standard-base64 encoded.
func RandomBase64(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	return base64.StdEncoding.EncodeToString(b)
}

// GeneratePresharedKey returns a fresh WireGuard preshared key (32 random
// bytes, standard base64, as `wg genpsk` prints it).
func GeneratePresharedKey() string { return RandomBase64(32) }

// ValidWireGuardKey reports whether s is standard base64 of exactly 32 bytes
// (the encoding wg(8) uses for public, private and preshared keys). The
// all-zero key is rejected: it is the result of an unset/invalid point.
func ValidWireGuardKey(s string) bool {
	if len(s) != 44 {
		return false
	}
	b, err := base64.StdEncoding.Strict().DecodeString(s)
	if err != nil || len(b) != 32 {
		return false
	}
	var zero [32]byte
	return !hmac.Equal(b, zero[:])
}
