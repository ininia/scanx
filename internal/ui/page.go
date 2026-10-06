// Package ui contains the templ components and embedded static assets of the
// web interface (ADR-002). All output is escaped by templ; templ.Raw is not
// used anywhere.
package ui

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"io/fs"
	"strings"
	"time"

	"github.com/ininia/scanx/internal/auth"
	"github.com/ininia/scanx/internal/i18n"
	"github.com/ininia/scanx/internal/service"
)

//go:embed static
var staticFS embed.FS

// Static returns the embedded static files rooted at "static".
func Static() fs.FS {
	sub, err := fs.Sub(staticFS, "static")
	if err != nil {
		panic(err)
	}
	return sub
}

// AssetVersion is a content hash of the static files, appended to asset URLs
// so browsers never use stale CSS/JS after an upgrade.
var AssetVersion = func() string {
	h := sha256.New()
	_ = fs.WalkDir(staticFS, "static", func(path string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			b, _ := staticFS.ReadFile(path)
			h.Write(b)
		}
		return nil
	})
	return hex.EncodeToString(h.Sum(nil))[:12]
}()

// Asset returns a cache-busted static URL.
func Asset(path string) string { return "/static/" + path + "?v=" + AssetVersion }

// Page carries per-request data every template needs.
type Page struct {
	Lang      string
	Title     string
	Nav       string
	User      *auth.Principal
	Orgs      []service.MyOrg
	Org       *service.OrgCtx
	CSRF      string
	Instance  string
	Flash     string // i18n key
	FlashKind string // ok | err | warn
	Path      string
	Version   string
}

// T translates for this page.
func (p *Page) T(key string, args ...any) string { return i18n.T(p.Lang, key, args...) }

// OrgURL builds a URL inside the current organization.
func (p *Page) OrgURL(path string) string {
	if p.Org == nil {
		return "/"
	}
	return "/o/" + p.Org.Org.Slug + path
}

// Can reports whether the current user may perform act in the current org.
func (p *Page) Can(act auth.Action) bool {
	return p.Org != nil && auth.Can(p.Org.Role, act)
}

// OtherLang is the language the switcher offers.
func (p *Page) OtherLang() string {
	if p.Lang == i18n.TR {
		return i18n.EN
	}
	return i18n.TR
}

// Form holds submitted values and field errors for re-rendering.
type Form struct {
	Values map[string]string
	Errors map[string]string // field → i18n key
	Error  string            // general error i18n key
}

// NewForm returns an empty form.
func NewForm() *Form { return &Form{Values: map[string]string{}, Errors: map[string]string{}} }

// V returns a submitted value.
func (f *Form) V(k string) string {
	if f == nil {
		return ""
	}
	return f.Values[k]
}

// E returns the error key for a field ("" if none).
func (f *Form) E(k string) string {
	if f == nil {
		return ""
	}
	return f.Errors[k]
}

// Date formats a time for tables.
func Date(t time.Time) string {
	if t.IsZero() {
		return "—"
	}
	return t.Local().Format("2006-01-02 15:04")
}

// DatePtr formats an optional time.
func DatePtr(t *time.Time) string {
	if t == nil {
		return "—"
	}
	return Date(*t)
}

// Initials of a name for the avatar chip.
func Initials(name, email string) string {
	src := strings.TrimSpace(name)
	if src == "" {
		src = email
	}
	parts := strings.Fields(src)
	out := ""
	for _, p := range parts {
		r := []rune(p)
		out += strings.ToUpper(string(r[0]))
		if len([]rune(out)) == 2 {
			break
		}
	}
	if out == "" {
		return "?"
	}
	return out
}
