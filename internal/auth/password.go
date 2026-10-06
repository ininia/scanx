// Package auth implements passwords, TOTP, tokens, CSRF protection, rate
// limiting and role-based authorization (spec §5.3).
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

// Argon2id parameters (RFC 9106 recommendation #2: 64 MiB, t=3).
const (
	argonTime    = 3
	argonMemory  = 64 * 1024
	argonThreads = 2
	argonKeyLen  = 32
	saltLen      = 16
)

// Password policy.
const (
	MinPasswordLen = 12
	MaxPasswordLen = 256
)

// Password validation errors (user-facing codes).
var (
	ErrPasswordTooShort = errors.New("password_too_short")
	ErrPasswordTooLong  = errors.New("password_too_long")
	ErrPasswordWeak     = errors.New("password_weak")
)

// ValidatePassword enforces the password policy.
func ValidatePassword(pw, email string) error {
	n := utf8.RuneCountInString(pw)
	switch {
	case n < MinPasswordLen:
		return ErrPasswordTooShort
	case n > MaxPasswordLen:
		return ErrPasswordTooLong
	}
	distinct := map[rune]bool{}
	for _, r := range pw {
		distinct[r] = true
	}
	lower := strings.ToLower(pw)
	if len(distinct) < 5 || (email != "" && strings.Contains(lower, strings.ToLower(strings.SplitN(email, "@", 2)[0]))) {
		return ErrPasswordWeak
	}
	for _, common := range commonPasswords {
		if strings.Contains(lower, common) && n < len(common)+6 {
			return ErrPasswordWeak
		}
	}
	return nil
}

// commonPasswords is a tiny offline deny-list of patterns; a fuller breached
// list can be plugged in later (spec §5.3 "opsiyonel, offline liste").
var commonPasswords = []string{"password", "parola", "123456", "qwerty", "letmein", "welcome", "admin", "scanx", "sifre", "şifre"}

// HashPassword returns a PHC-formatted Argon2id hash.
func HashPassword(pw string) (string, error) {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("auth: salt: %w", err)
	}
	key := argon2.IDKey([]byte(pw), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	b64 := base64.RawStdEncoding
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemory, argonTime, argonThreads, b64.EncodeToString(salt), b64.EncodeToString(key)), nil
}

// ErrInvalidHash is returned for malformed stored hashes.
var ErrInvalidHash = errors.New("auth: invalid password hash")

// VerifyPassword checks pw against a PHC Argon2id hash in constant time.
// needsRehash reports weaker-than-current parameters.
func VerifyPassword(pw, encoded string) (ok, needsRehash bool, err error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false, false, ErrInvalidHash
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return false, false, ErrInvalidHash
	}
	var m, t uint32
	var p uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil || m == 0 || t == 0 || p == 0 || m > 1<<22 || t > 32 {
		return false, false, ErrInvalidHash
	}
	b64 := base64.RawStdEncoding
	salt, err := b64.DecodeString(parts[4])
	if err != nil {
		return false, false, ErrInvalidHash
	}
	want, err := b64.DecodeString(parts[5])
	if err != nil || len(want) == 0 || len(want) > 128 {
		return false, false, ErrInvalidHash
	}
	got := argon2.IDKey([]byte(pw), salt, t, m, p, uint32(len(want))) //nolint:gosec // len bounded above
	ok = subtle.ConstantTimeCompare(got, want) == 1
	needsRehash = m < argonMemory || t < argonTime || p < argonThreads
	return ok, needsRehash, nil
}

// dummyHash is verified when a user does not exist so the response time does
// not reveal which e-mail addresses are registered.
var dummyHash, _ = HashPassword("dummy-password-for-timing-equalisation")

// VerifyDummy burns the same CPU as a real verification.
func VerifyDummy(pw string) {
	_, _, _ = VerifyPassword(pw, dummyHash)
}
