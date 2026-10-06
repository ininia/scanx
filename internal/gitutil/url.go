// Package gitutil validates repository URLs (spec §6.3). Network-level
// checks (private IP / SSRF) happen at connection time in the sandbox.
package gitutil

import (
	"errors"
	"net/url"
	"regexp"
	"strings"
)

// Errors returned by ParseRepoURL.
var (
	ErrScheme  = errors.New("unsupported repository URL scheme")
	ErrInvalid = errors.New("invalid repository URL")
)

// RepoURL is a validated repository location.
type RepoURL struct {
	Raw      string
	Scheme   string // ssh | https
	Host     string
	Path     string // owner/repo (without .git)
	Provider string // github | gitlab | gitea | bitbucket | generic
}

var (
	scpLike  = regexp.MustCompile(`^([A-Za-z0-9._-]+)@([A-Za-z0-9.-]+):([A-Za-z0-9._~/-]+)$`)
	hostRe   = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$`)
	pathRe   = regexp.MustCompile(`^[A-Za-z0-9._~-]+(/[A-Za-z0-9._~-]+)+$`)
	optionRe = regexp.MustCompile(`(^|/)-`)
)

// ParseRepoURL accepts ssh://, git@host:path and https:// URLs only.
// file://, ext::, local paths, credentials in URLs and option-like path
// segments (argument injection into git) are rejected.
func ParseRepoURL(raw string) (*RepoURL, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > 1000 || strings.ContainsAny(raw, " \t\r\n\x00\\") {
		return nil, ErrInvalid
	}
	r := &RepoURL{Raw: raw}
	switch {
	case scpLike.MatchString(raw):
		m := scpLike.FindStringSubmatch(raw)
		r.Scheme, r.Host, r.Path = "ssh", m[2], m[3]
	case strings.HasPrefix(raw, "ssh://"), strings.HasPrefix(raw, "https://"):
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" || u.RawQuery != "" || u.Fragment != "" {
			return nil, ErrInvalid
		}
		if _, hasPw := u.User.Password(); hasPw || (u.Scheme == "https" && u.User != nil) {
			return nil, ErrInvalid // never store credentials in URLs
		}
		r.Scheme, r.Host, r.Path = u.Scheme, u.Hostname(), strings.TrimPrefix(u.Path, "/")
	default:
		return nil, ErrScheme
	}
	r.Path = strings.TrimSuffix(strings.TrimSuffix(r.Path, "/"), ".git")
	if !hostRe.MatchString(r.Host) || strings.HasPrefix(r.Host, "-") {
		return nil, ErrInvalid
	}
	if !pathRe.MatchString(r.Path) || optionRe.MatchString(r.Path) || strings.Contains(r.Path, "..") {
		return nil, ErrInvalid
	}
	r.Provider = providerFor(r.Host)
	return r, nil
}

func providerFor(host string) string {
	h := strings.ToLower(host)
	switch {
	case h == "github.com" || strings.HasSuffix(h, ".github.com"):
		return "github"
	case h == "gitlab.com" || strings.HasPrefix(h, "gitlab."):
		return "gitlab"
	case h == "bitbucket.org" || strings.HasPrefix(h, "bitbucket."):
		return "bitbucket"
	case h == "codeberg.org" || strings.HasPrefix(h, "gitea.") || strings.HasPrefix(h, "forgejo."):
		return "gitea"
	default:
		return "generic"
	}
}

// Name returns the repository name (last path segment).
func (r *RepoURL) Name() string {
	if i := strings.LastIndex(r.Path, "/"); i >= 0 {
		return r.Path[i+1:]
	}
	return r.Path
}
