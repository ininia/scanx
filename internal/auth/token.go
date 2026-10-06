package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"math/big"
	"strings"
)

// Token prefixes make leaked tokens recognizable by secret scanners.
const (
	PrefixPersonal = "scanx_pat_"
	PrefixCI       = "scanx_ci_"
	PrefixInvite   = "scanx_inv_"
)

const base62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

// NewToken returns a random token with the given prefix and its SHA-256
// hash. Only the hash is stored (spec §5.3).
func NewToken(prefix string) (plain string, hash []byte, err error) {
	var b strings.Builder
	b.WriteString(prefix)
	max := big.NewInt(int64(len(base62)))
	for i := 0; i < 40; i++ { // ~238 bits of entropy
		n, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", nil, fmt.Errorf("auth: token: %w", err)
		}
		b.WriteByte(base62[n.Int64()])
	}
	plain = b.String()
	return plain, HashToken(plain), nil
}

// HashToken hashes a presented token for lookup.
func HashToken(plain string) []byte {
	sum := sha256.Sum256([]byte(plain))
	return sum[:]
}

// TokenDisplayPrefix is the non-secret part shown in UIs ("scanx_pat_AbC1…").
func TokenDisplayPrefix(plain string) string {
	if len(plain) <= 14 {
		return plain
	}
	return plain[:14]
}

// NewSessionToken returns a random session cookie value and its hash.
func NewSessionToken() (plain string, hash []byte, err error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", nil, fmt.Errorf("auth: session token: %w", err)
	}
	plain = base64.RawURLEncoding.EncodeToString(b)
	return plain, HashToken(plain), nil
}

// CSRF protection: double-submit cookie with an HMAC-bound form token. The
// cookie holds a random value; the form/header token is HMAC(key, value), so
// an attacker who can set cookies still cannot forge the matching token.

// NewCSRFSeed returns a random cookie value.
func NewCSRFSeed() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("auth: csrf: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// CSRFToken derives the token embedded in forms for a cookie seed.
func CSRFToken(key []byte, seed string) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte("csrf:" + seed))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// VerifyCSRF checks a submitted token against the cookie seed.
func VerifyCSRF(key []byte, seed, token string) bool {
	if seed == "" || token == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(CSRFToken(key, seed)), []byte(token)) == 1
}
