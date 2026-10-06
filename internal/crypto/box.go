// Package crypto wraps AES-256-GCM for encrypting secrets at rest (TOTP
// secrets, deploy keys, notification credentials) with the instance master key.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
)

// ErrDecrypt is returned for any authentication/decryption failure. The cause
// is deliberately not exposed.
var ErrDecrypt = errors.New("crypto: decryption failed")

// Box encrypts and decrypts with one AES-256-GCM key.
type Box struct {
	aead cipher.AEAD
}

// New creates a Box from a 32-byte key.
func New(key []byte) (*Box, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("crypto: key must be 32 bytes, got %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("crypto: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("crypto: %w", err)
	}
	return &Box{aead: aead}, nil
}

// Seal encrypts plaintext with a fresh random nonce. aad binds the
// ciphertext to its context (e.g. "totp:<user-id>") so it cannot be moved to
// another row and still decrypt.
func (b *Box) Seal(plaintext, aad []byte) (ciphertext, nonce []byte, err error) {
	nonce = make([]byte, b.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, fmt.Errorf("crypto: nonce: %w", err)
	}
	return b.aead.Seal(nil, nonce, plaintext, aad), nonce, nil
}

// Open decrypts and authenticates.
func (b *Box) Open(ciphertext, nonce, aad []byte) ([]byte, error) {
	if len(nonce) != b.aead.NonceSize() {
		return nil, ErrDecrypt
	}
	pt, err := b.aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, ErrDecrypt
	}
	return pt, nil
}
