package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // RFC 6238 TOTP with HMAC-SHA1 is what authenticator apps implement
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"
)

// TOTP parameters (RFC 6238 defaults understood by all authenticator apps).
const (
	totpPeriod = 30
	totpDigits = 6
	totpSkew   = 1 // accept one step before/after for clock drift
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewTOTPSecret returns a random 160-bit secret.
func NewTOTPSecret() ([]byte, error) {
	s := make([]byte, 20)
	if _, err := rand.Read(s); err != nil {
		return nil, fmt.Errorf("auth: totp secret: %w", err)
	}
	return s, nil
}

// EncodeTOTPSecret returns the base32 form users type into authenticator apps.
func EncodeTOTPSecret(secret []byte) string { return b32.EncodeToString(secret) }

// TOTPURI builds the otpauth:// provisioning URI shown as a QR code.
func TOTPURI(issuer, account string, secret []byte) string {
	label := url.PathEscape(issuer + ":" + account)
	q := url.Values{}
	q.Set("secret", EncodeTOTPSecret(secret))
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", "6")
	q.Set("period", "30")
	return "otpauth://totp/" + label + "?" + q.Encode()
}

// TOTPCode computes the code for a counter step.
func TOTPCode(secret []byte, step int64) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(step)) //nolint:gosec // steps are positive Unix-time counters
	mac := hmac.New(sha1.New, secret)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	v := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	return fmt.Sprintf("%0*d", totpDigits, v%1_000_000)
}

// VerifyTOTP checks code at time now and returns the matched step.
func VerifyTOTP(secret []byte, code string, now time.Time) (int64, bool) {
	code = strings.ReplaceAll(strings.TrimSpace(code), " ", "")
	if len(code) != totpDigits {
		return 0, false
	}
	cur := now.Unix() / totpPeriod
	for d := int64(-totpSkew); d <= totpSkew; d++ {
		if subtle.ConstantTimeCompare([]byte(TOTPCode(secret, cur+d)), []byte(code)) == 1 {
			return cur + d, true
		}
	}
	return 0, false
}

// ReplayGuard rejects a TOTP step that was already used by the same user,
// so an intercepted code cannot be reused within its validity window.
type ReplayGuard struct {
	mu   sync.Mutex
	used map[string]time.Time
}

// NewReplayGuard creates an empty guard.
func NewReplayGuard() *ReplayGuard { return &ReplayGuard{used: map[string]time.Time{}} }

// Use records (user, step) and reports false if it was seen before.
func (g *ReplayGuard) Use(user string, step int64, now time.Time) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	for k, at := range g.used {
		if now.Sub(at) > 3*totpPeriod*time.Second {
			delete(g.used, k)
		}
	}
	k := fmt.Sprintf("%s:%d", user, step)
	if _, seen := g.used[k]; seen {
		return false
	}
	g.used[k] = now
	return true
}
