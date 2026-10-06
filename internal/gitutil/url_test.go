package gitutil

import (
	"errors"
	"testing"
)

func TestParseRepoURLAccepts(t *testing.T) {
	cases := map[string][3]string{ // raw → scheme, path, provider
		"git@github.com:ininia/scanx.git":             {"ssh", "ininia/scanx", "github"},
		"ssh://git@gitlab.example.com:2222/a/b/c.git": {"ssh", "a/b/c", "gitlab"},
		"https://gitlab.com/group/sub/proj":           {"https", "group/sub/proj", "gitlab"},
		"https://bitbucket.org/team/repo.git":         {"https", "team/repo", "bitbucket"},
		"git@git.internal.local:team/app":             {"ssh", "team/app", "generic"},
		"https://codeberg.org/forgejo/forgejo":        {"https", "forgejo/forgejo", "gitea"},
	}
	for raw, want := range cases {
		r, err := ParseRepoURL(raw)
		if err != nil {
			t.Errorf("%s: %v", raw, err)
			continue
		}
		if r.Scheme != want[0] || r.Path != want[1] || r.Provider != want[2] {
			t.Errorf("%s: got %s %s %s", raw, r.Scheme, r.Path, r.Provider)
		}
	}
	r, _ := ParseRepoURL("git@github.com:ininia/scanx.git")
	if r.Name() != "scanx" {
		t.Errorf("Name %q", r.Name())
	}
}

func TestParseRepoURLRejects(t *testing.T) {
	scheme := []string{"file:///etc/passwd", "ext::sh -c touch% /tmp/pwned", "/srv/git/repo", "../repo", "http://github.com/a/b", "ftp://x/a/b", "git://github.com/a/b"}
	for _, raw := range scheme {
		if _, err := ParseRepoURL(raw); !errors.Is(err, ErrScheme) && !errors.Is(err, ErrInvalid) {
			t.Errorf("%q accepted", raw)
		}
	}
	invalid := []string{
		"", "https://user:FAKEpass@github.com/a/b", "https://token@github.com/a/b",
		"git@github.com:-oProxyCommand=evil/x", "https://github.com/a/--upload-pack=x",
		"https://github.com/onlyone", "https://github.com/a/b?x=1", "https://github.com/a/b#frag",
		"git@-host.com:a/b", "https://github.com/a/../b", "git@github.com:a/b c", "https://github.com/a\\b/c",
	}
	for _, raw := range invalid {
		if _, err := ParseRepoURL(raw); err == nil {
			t.Errorf("%q accepted", raw)
		}
	}
}
