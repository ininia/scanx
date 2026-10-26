package gitfetch

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// ChangedLinesFile is written next to the checkout (…/work/changed-lines.json):
// for every added or modified file the line ranges (in the new version)
// the push added or changed. An incremental scan reports only findings on
// those lines; issues already in the rest of the file belong to full scans.
const ChangedLinesFile = "changed-lines.json"

// LineRange is an inclusive range of line numbers.
type LineRange [2]int

// maxRangesPerFile bounds the file; beyond it the whole file counts as
// changed (a rewrite).
const maxRangesPerFile = 5000

// changedLines lists the added/modified line ranges between base and HEAD.
func (g *git) changedLines(ctx context.Context, base string) (map[string][]LineRange, error) {
	out, err := g.run(ctx, "-c", "core.quotepath=false", "diff", "-U0", "--no-color", "--no-ext-diff", "--no-textconv",
		"--no-renames", "--diff-filter=ACMT", base, "HEAD", "--")
	if err != nil {
		return nil, err
	}
	return ParseChangedLines(out), nil
}

// ParseChangedLines reads `git diff -U0` output. A file without ranges
// (binary, mode change) maps to nil: nothing on it is new.
func ParseChangedLines(diff string) map[string][]LineRange {
	res := map[string][]LineRange{}
	file := ""
	sc := bufio.NewScanner(strings.NewReader(diff))
	sc.Buffer(make([]byte, 64<<10), 16<<20)
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "+++ "):
			file = diffPath(strings.TrimPrefix(line, "+++ "))
			if file != "" {
				if _, ok := res[file]; !ok {
					res[file] = nil
				}
			}
		case strings.HasPrefix(line, "@@ ") && file != "":
			r, ok := hunkRange(line)
			if !ok {
				continue
			}
			if len(res[file]) >= maxRangesPerFile {
				res[file] = []LineRange{{1, 1 << 30}}
				continue
			}
			res[file] = append(res[file], r)
		}
	}
	return res
}

// diffPath turns `b/dir/file` (or a quoted form) into the repository path.
func diffPath(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, `"`) {
		u, err := strconv.Unquote(s)
		if err != nil {
			return ""
		}
		s = u
	}
	if s == "/dev/null" {
		return ""
	}
	return strings.TrimPrefix(s, "b/")
}

// hunkRange parses "@@ -a,b +c,d @@": the new-side lines c..c+d-1. Pure
// deletions (d = 0) add no line.
func hunkRange(line string) (LineRange, bool) {
	f := strings.Fields(line)
	if len(f) < 3 || !strings.HasPrefix(f[2], "+") {
		return LineRange{}, false
	}
	start, count := f[2][1:], "1"
	if a, b, ok := strings.Cut(start, ","); ok {
		start, count = a, b
	}
	c, err1 := strconv.Atoi(start)
	d, err2 := strconv.Atoi(count)
	if err1 != nil || err2 != nil || d <= 0 {
		return LineRange{}, false
	}
	return LineRange{c, c + d - 1}, true
}

// writeChangedLines stores the ranges next to the checkout; on any problem
// the scan falls back to whole changed files.
func (g *git) writeChangedLines(ctx context.Context, r *Request) {
	lines, err := g.changedLines(ctx, r.BaseCommit)
	if err != nil {
		return
	}
	b, err := json.Marshal(lines)
	if err != nil {
		return
	}
	_ = os.WriteFile(filepath.Join(filepath.Dir(r.Dest), ChangedLinesFile), b, 0o640) //nolint:gosec // inside the scan volume
}
