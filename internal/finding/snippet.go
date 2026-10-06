package finding

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

// Snippet limits.
const (
	SnippetContext    = 3
	maxSnippetFile    = 5 << 20 // do not open files larger than 5 MiB
	maxSnippetLineLen = 400
	maxSnippetLines   = 40
)

// ErrOutsideRoot is returned when a reported path escapes the source root
// (via "..", absolute paths or symlinks).
var ErrOutsideRoot = errors.New("path outside source root")

// SafeJoin resolves rel inside root, following symlinks, and rejects any
// result outside root (spec §5.1 path traversal protection).
func SafeJoin(root, rel string) (string, error) {
	rootReal, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", fmt.Errorf("resolve root: %w", err)
	}
	rel = filepath.FromSlash(strings.TrimPrefix(rel, "/"))
	if filepath.IsAbs(rel) || filepath.VolumeName(rel) != "" {
		return "", ErrOutsideRoot
	}
	candidate := filepath.Join(rootReal, filepath.Clean(string(filepath.Separator)+rel))
	real, err := filepath.EvalSymlinks(candidate)
	if err != nil {
		return "", fmt.Errorf("resolve path: %w", err)
	}
	r, err := filepath.Rel(rootReal, real)
	if err != nil || r == ".." || strings.HasPrefix(r, ".."+string(filepath.Separator)) || filepath.IsAbs(r) {
		return "", ErrOutsideRoot
	}
	return real, nil
}

// Snippet reads lines [start-ctx, end+ctx] of file inside root. It returns
// the context snippet and the exact matched lines. Binary and oversized files
// yield empty results without error.
func Snippet(root, file string, start, end, ctx int) (snippet, matched string, err error) {
	if start <= 0 {
		return "", "", nil
	}
	if end < start {
		end = start
	}
	path, err := SafeJoin(root, file)
	if err != nil {
		return "", "", err
	}
	st, err := os.Stat(path)
	if err != nil {
		return "", "", fmt.Errorf("stat: %w", err)
	}
	if !st.Mode().IsRegular() || st.Size() > maxSnippetFile {
		return "", "", nil
	}
	data, err := os.ReadFile(path) //nolint:gosec // path validated by SafeJoin
	if err != nil {
		return "", "", fmt.Errorf("read: %w", err)
	}
	if bytes.IndexByte(data[:min(len(data), 8000)], 0) >= 0 || !utf8.Valid(data) {
		return "", "", nil
	}
	from, to := max(1, start-ctx), end+ctx
	if to-from+1 > maxSnippetLines {
		to = from + maxSnippetLines - 1
	}
	var snip, match []string
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 64*1024), maxSnippetFile)
	for n := 1; sc.Scan(); n++ {
		if n < from {
			continue
		}
		if n > to {
			break
		}
		line := sc.Text()
		if len(line) > maxSnippetLineLen {
			line = line[:maxSnippetLineLen] + "…"
		}
		snip = append(snip, line)
		if n >= start && n <= end {
			match = append(match, line)
		}
	}
	return strings.Join(snip, "\n"), strings.Join(match, "\n"), nil
}
