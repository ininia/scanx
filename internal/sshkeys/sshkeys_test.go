package sshkeys

import (
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// Published fingerprints, copied from the providers' documentation (see the
// URLs on knownHosts). A mismatch means the pinned key was mistyped.
func TestKnownHostFingerprints(t *testing.T) {
	want := map[string]string{
		"github.com":    "SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU",
		"gitlab.com":    "SHA256:eUXGGm1YGsMAS7vkcx6JOJdOGHPem5gQp4taiCfCLB8",
		"bitbucket.org": "SHA256:ybgmFkzwOSotHTHLJgHO0QN8L0xErw6vd0VhFA9m3SM",
		"codeberg.org":  "SHA256:mIlxA9k46MmM6qdJOdMnAQpzGxF4WIVVL+fj+wZbw0g",
	}
	for host, fp := range want {
		pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(knownHosts[host]))
		if err != nil {
			t.Fatalf("%s: %v", host, err)
		}
		if got := ssh.FingerprintSHA256(pk); got != fp {
			t.Errorf("%s fingerprint = %s, want %s", host, got, fp)
		}
	}
}

func TestKnownHosts(t *testing.T) {
	if !strings.HasPrefix(KnownHosts("GitHub.com", ""), "github.com ssh-ed25519 ") {
		t.Fatal("github.com not pinned")
	}
	if KnownHosts("git.example.com", "") != "" {
		t.Fatal("unknown host must not be trusted")
	}
	extra := "# comment\ngit.example.com ssh-ed25519 AAAAX\n[git.example.com]:2222 ssh-ed25519 AAAAY\nother.com ssh-rsa AAAAZ\n"
	got := KnownHosts("git.example.com", extra)
	if !strings.Contains(got, "AAAAX") || !strings.Contains(got, "AAAAY") || strings.Contains(got, "AAAAZ") {
		t.Fatalf("extra known hosts not filtered: %q", got)
	}
}

func TestGenerate(t *testing.T) {
	k, err := Generate("scanx@example")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(k.PublicKey, "ssh-ed25519 ") || !strings.HasSuffix(k.PublicKey, " scanx@example") {
		t.Fatalf("public key %q", k.PublicKey)
	}
	signer, err := ssh.ParsePrivateKey(k.PrivatePEM)
	if err != nil {
		t.Fatal(err)
	}
	if ssh.FingerprintSHA256(signer.PublicKey()) != k.Fingerprint {
		t.Fatal("fingerprint does not match private key")
	}
}
