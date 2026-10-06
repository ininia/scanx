package app

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// GenerateSecrets writes freshly generated secrets in .env format. It is the
// single source for install.sh and the docs (no openssl dependency).
func GenerateSecrets(w io.Writer) error {
	b64 := func(n int) string {
		b := make([]byte, n)
		_, _ = rand.Read(b) // never fails (Go >= 1.24)
		return base64.StdEncoding.EncodeToString(b)
	}
	hx := func(n int) string {
		b := make([]byte, n)
		_, _ = rand.Read(b)
		return hex.EncodeToString(b)
	}
	setup := hx(6)
	_, err := fmt.Fprintf(w,
		"POSTGRES_PASSWORD=%s\nSCANX_APP_DB_PASSWORD=%s\nSCANX_MASTER_KEY=%s\nSCANX_SESSION_KEY=%s\nSCANX_SETUP_TOKEN=%s-%s-%s\n",
		hx(24), hx(24), b64(32), b64(48), setup[0:4], setup[4:8], setup[8:12])
	return err
}

// GenerateSelfSignedCert writes cert.pem and key.pem (ECDSA P-256, 825 days)
// into dir for the given hosts. With ifMissing, existing files are kept.
func GenerateSelfSignedCert(dir string, hosts []string, ifMissing bool) error {
	certPath, keyPath := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if ifMissing {
		if _, err := os.Stat(certPath); err == nil {
			if _, err := os.Stat(keyPath); err == nil {
				return nil
			}
		}
	}
	if len(hosts) == 0 {
		return errors.New("gen-cert: at least one host is required")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("gen-cert: key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return fmt.Errorf("gen-cert: serial: %w", err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: hosts[0], Organization: []string{"scanX self-signed"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(825 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return fmt.Errorf("gen-cert: create: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return fmt.Errorf("gen-cert: marshal key: %w", err)
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("gen-cert: %w", err)
	}
	if err := writePEM(keyPath, "PRIVATE KEY", keyDER, 0o600); err != nil {
		return err
	}
	return writePEM(certPath, "CERTIFICATE", der, 0o644)
}

func writePEM(path, typ string, der []byte, mode os.FileMode) error {
	f, err := os.OpenFile(filepath.Clean(path), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return fmt.Errorf("gen-cert: %w", err)
	}
	if err := pem.Encode(f, &pem.Block{Type: typ, Bytes: der}); err != nil {
		_ = f.Close()
		return fmt.Errorf("gen-cert: write %s: %w", filepath.Base(path), err)
	}
	return f.Close()
}

// Healthcheck performs a GET against url and fails unless it returns 200. It
// backs the container HEALTHCHECK (distroless images have no curl).
func Healthcheck(ctx context.Context, url string) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("healthcheck: %w", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("healthcheck: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("healthcheck: status %d", resp.StatusCode)
	}
	return nil
}
