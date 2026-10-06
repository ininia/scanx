package crypto

import (
	"bytes"
	"errors"
	"testing"
)

func key(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }

func TestSealOpenRoundTrip(t *testing.T) {
	box, err := New(key(1))
	if err != nil {
		t.Fatal(err)
	}
	ct, nonce, err := box.Seal([]byte("FAKE totp secret"), []byte("totp:user-1"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ct, []byte("FAKE")) {
		t.Fatal("ciphertext contains plaintext")
	}
	pt, err := box.Open(ct, nonce, []byte("totp:user-1"))
	if err != nil || string(pt) != "FAKE totp secret" {
		t.Fatalf("open: %q %v", pt, err)
	}
	ct2, nonce2, _ := box.Seal([]byte("FAKE totp secret"), []byte("totp:user-1"))
	if bytes.Equal(ct, ct2) || bytes.Equal(nonce, nonce2) {
		t.Fatal("nonces must be unique")
	}
}

func TestOpenRejectsTampering(t *testing.T) {
	box, _ := New(key(1))
	other, _ := New(key(2))
	ct, nonce, _ := box.Seal([]byte("secret"), []byte("totp:user-1"))
	tampered := append([]byte(nil), ct...)
	tampered[0] ^= 1
	cases := map[string]func() ([]byte, error){
		"wrong aad":   func() ([]byte, error) { return box.Open(ct, nonce, []byte("totp:user-2")) },
		"wrong key":   func() ([]byte, error) { return other.Open(ct, nonce, []byte("totp:user-1")) },
		"tampered":    func() ([]byte, error) { return box.Open(tampered, nonce, []byte("totp:user-1")) },
		"short nonce": func() ([]byte, error) { return box.Open(ct, nonce[:4], []byte("totp:user-1")) },
	}
	for name, fn := range cases {
		if _, err := fn(); !errors.Is(err, ErrDecrypt) {
			t.Errorf("%s: want ErrDecrypt, got %v", name, err)
		}
	}
}

func TestNewRejectsBadKey(t *testing.T) {
	if _, err := New([]byte("short")); err == nil {
		t.Fatal("expected error")
	}
}
