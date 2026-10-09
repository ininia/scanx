package scanner

import (
	"io/fs"
	"path"
	"path/filepath"
	"strings"
)

// Excluded reports whether a repository-relative path matches one of the
// patterns (same semantics as opengrep --exclude: a pattern without "/"
// matches any path segment, one with "/" matches a path prefix).
func Excluded(rel string, patterns []string) bool {
	rel = filepath.ToSlash(rel)
	segs := strings.Split(rel, "/")
	for _, pat := range patterns {
		if !strings.Contains(pat, "/") {
			for _, s := range segs {
				if ok, _ := path.Match(pat, s); ok {
					return true
				}
			}
			continue
		}
		if rel == pat || strings.HasPrefix(rel, pat+"/") || strings.Contains("/"+rel+"/", "/"+pat+"/") {
			return true
		}
	}
	return false
}

// FindFiles walks root and returns the files accepted by match (absolute
// paths), skipping excluded paths, symlinks and anything beyond limit.
func FindFiles(root string, excludes []string, limit int, match func(rel, name string) bool) []string {
	var out []string
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || len(out) >= limit {
			return nil
		}
		rel, rerr := filepath.Rel(root, p)
		if rerr != nil || rel == "." {
			return nil
		}
		if Excluded(rel, excludes) {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.IsDir() || !d.Type().IsRegular() {
			return nil
		}
		if match(filepath.ToSlash(rel), d.Name()) {
			out = append(out, p)
		}
		return nil
	})
	return out
}

// AllExcludes is DefaultExcludes + SASTExcludes + the user's patterns.
func AllExcludes(s Settings) []string {
	return append(append(append([]string{}, DefaultExcludes...), SASTExcludes...), s.Exclude...)
}
