package finding

import (
	"path/filepath"
	"strings"
)

// NormalizeOptions controls Normalize.
type NormalizeOptions struct {
	// SourceRoot is the scanned tree, used to read snippets. Empty disables snippets.
	SourceRoot string
	// StoreSnippets keeps the context snippet in the finding (spec K6: on by
	// default, can be disabled per project). Matched lines are still used for
	// fingerprinting.
	StoreSnippets bool
}

// Normalize completes adapter output in place: cleans paths, reads snippets
// safely, masks secrets, clamps text sizes and computes fingerprints.
func Normalize(findings []Finding, opt NormalizeOptions) {
	for i := range findings {
		f := &findings[i]
		f.File = CleanPath(f.File)
		if f.EndLine < f.StartLine {
			f.EndLine = f.StartLine
		}
		if opt.SourceRoot != "" && f.File != "" && f.StartLine > 0 && (f.matchLines == "" || f.Snippet == "") {
			snip, match, err := Snippet(opt.SourceRoot, f.File, f.StartLine, f.EndLine, SnippetContext)
			if err == nil {
				if opt.StoreSnippets && f.Snippet == "" {
					f.Snippet = snip // masked below
				}
				// A tool-provided (redacted) match stays the fingerprint
				// identity; the file is only read for display then.
				if f.matchLines == "" {
					f.matchLines = match
				}
			}
		}
		// Any source line can contain a credential (e.g. a SAST rule matching a
		// config line), so snippets are masked for every category (spec §4.2/6).
		f.Snippet = MaskText(f.Snippet)
		f.matchLines = MaskText(f.matchLines)
		if f.Category == CategorySecret {
			f.Title = MaskLine(f.Title)
			f.Description = MaskText(f.Description)
			f.Raw = nil // raw tool records may contain the secret
		}
		if !opt.StoreSnippets {
			f.Snippet = ""
		}
		f.Title = clamp(f.Title, 300)
		f.Description = clamp(f.Description, 4000)
		f.Remediation = clamp(f.Remediation, 4000)
		f.Fingerprint = Fingerprint(f)
	}
}

// CleanPath turns tool paths into clean, slash-separated paths relative to the
// repository root ("/work/src/a/b.go", "./a/b.go" → "a/b.go").
func CleanPath(p string) string {
	if p == "" {
		return ""
	}
	p = filepath.ToSlash(p)
	for _, prefix := range []string{"file://", "/work/src/", "work/src/"} {
		p = strings.TrimPrefix(p, prefix)
	}
	p = filepath.ToSlash(filepath.Clean("/" + p))
	return strings.TrimPrefix(p, "/")
}

func clamp(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}
