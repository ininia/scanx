// Package sshkeys generates per-project deploy keys and holds the SSH host
// keys scanX trusts for well-known Git hosting services.
package sshkeys

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"
)

// Key is a freshly generated deploy key.
type Key struct {
	PublicKey   string // authorized_keys line, e.g. "ssh-ed25519 AAAA… scanx-deploy-key"
	Fingerprint string // SHA256:…
	PrivatePEM  []byte // OpenSSH private key (store encrypted only)
}

// Generate creates an Ed25519 deploy key. comment is appended to the public
// key so it is recognizable in the provider's UI.
func Generate(comment string) (*Key, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("sshkeys: generate: %w", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("sshkeys: public key: %w", err)
	}
	block, err := ssh.MarshalPrivateKey(priv, comment)
	if err != nil {
		return nil, fmt.Errorf("sshkeys: marshal: %w", err)
	}
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub)))
	if comment != "" {
		line += " " + comment
	}
	return &Key{PublicKey: line, Fingerprint: ssh.FingerprintSHA256(sshPub), PrivatePEM: pem.EncodeToMemory(block)}, nil
}

// knownHosts are the published SSH host keys of public Git hosts. Verified
// against the providers' documented fingerprints (TestKnownHostFingerprints):
//
//	github.com     https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/githubs-ssh-key-fingerprints
//	gitlab.com     https://docs.gitlab.com/ee/user/gitlab_com/#ssh-host-keys-fingerprints
//	bitbucket.org  https://support.atlassian.com/bitbucket-cloud/docs/configure-ssh-and-two-step-verification/
//	codeberg.org   https://docs.codeberg.org/security/ssh-fingerprint/
var knownHosts = map[string]string{
	"github.com":    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl",
	"gitlab.com":    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAfuCHKVTjquxvt6CM6tdG4SLp1Btn/nOeHHE5UOzRdf",
	"bitbucket.org": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIazEu89wgQZ4bqs3d63QSMzYVa0MuJ2e2gKTKqu+UUO",
	"codeberg.org":  "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIVIC02vnjFyL+I4RHfvIGNtOgJMe769VTF1VR4EB3ZB",
}
