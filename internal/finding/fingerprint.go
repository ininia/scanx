package finding

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"sort"
	"strings"
)

// toolFamily maps tools whose results are interchangeable to one family so
// the same issue keeps its fingerprint when the engine changes.
var toolFamily = map[string]string{
	"opengrep": "semgrep",
	"semgrep":  "semgrep",
}

// family returns the fingerprint family: secrets and dependency findings are
// tool-agnostic (any tool finding the same thing yields the same issue).
func family(f *Finding) string {
	switch f.Category {
	case CategorySecret:
		return "secret"
	case CategorySCA:
		return "sca"
	}
	if fam, ok := toolFamily[f.Tool]; ok {
		return fam
	}
	return f.Tool
}

var (
	lineCommentRe = regexp.MustCompile(`(?m)^\s*(//|#|--|;|\*|/\*).*$`)
	spaceRe       = regexp.MustCompile(`\s+`)
	ruleNoiseRe   = regexp.MustCompile(`[^a-z0-9]+`)
)

// normalizeSnippet drops comment-only lines and all whitespace so formatting
// changes do not alter the fingerprint.
func normalizeSnippet(s string) string {
	s = lineCommentRe.ReplaceAllString(s, "")
	return spaceRe.ReplaceAllString(s, "")
}

// normalizeRule lower-cases a rule id and strips the engine-specific dotted
// path prefix Semgrep-family engines add (e.g. "opt.rules.gitlab.go.x" → "x").
func normalizeRule(f *Finding) string {
	r := strings.ToLower(f.RuleID)
	if family(f) == "semgrep" {
		if i := strings.LastIndex(r, "."); i >= 0 {
			r = r[i+1:]
		}
	}
	return ruleNoiseRe.ReplaceAllString(r, "-")
}

// Fingerprint computes the stable identity of a finding (spec §7.4):
// sha256(family + rule + file + normalized matched code + package@version).
// Line numbers are deliberately excluded so moved code keeps its identity.
func Fingerprint(f *Finding) string {
	h := sha256.New()
	write := func(parts ...string) {
		for _, p := range parts {
			h.Write([]byte(p))
			h.Write([]byte{0})
		}
	}
	switch f.Category {
	case CategorySCA:
		ids := append([]string(nil), f.CVE...)
		sort.Strings(ids)
		id := f.RuleID
		if len(ids) > 0 {
			id = ids[0]
		}
		var name, ver, eco string
		if f.Package != nil {
			name, ver, eco = strings.ToLower(f.Package.Name), f.Package.Version, strings.ToLower(f.Package.Ecosystem)
		}
		write("sca", id, eco, name, ver, f.File)
	case CategorySecret:
		code := normalizeSnippet(f.matchLines)
		if code == "" {
			code = normalizeRule(f)
		}
		write("secret", f.File, hashString(code))
	default:
		code := normalizeSnippet(f.matchLines)
		if code == "" {
			code = strings.ToLower(f.Title)
		}
		write(family(f), normalizeRule(f), f.File, hashString(code))
	}
	return hex.EncodeToString(h.Sum(nil))
}

func hashString(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}
