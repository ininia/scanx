// Package prune builds the tree that code analysis (SAST and quality
// tools) runs on: the repository without third-party bundles, minified or
// generated files, assets and oversized files. Analysing those finds
// nothing actionable and takes most of the scan time on large web
// projects; secret scanning and dependency analysis still see the full
// checkout. Files are hard-linked where possible, so building the tree is
// cheap and takes no extra disk space.
package prune

import (
	"bytes"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/ininia/scanx/internal/scanner"
)

// Skip reasons.
const (
	ReasonExcluded = "excluded" // an exclude pattern (default or the project's)
	ReasonBundle   = "bundle"   // detected third-party theme / library folder
	ReasonMinified = "minified" // minified or bundled JavaScript / CSS
	ReasonLarge    = "large"    // larger than the per-file limit
)

// Options control what is left out.
type Options struct {
	Excludes     []string // path patterns (scanner.Excluded semantics)
	MaxFileBytes int64    // 0 = no size limit
	SkipMinified bool
	SkipBundles  bool
}

// Dir is a folder (or file group) and its size.
type Dir struct {
	Path   string `json:"path"`
	Bytes  int64  `json:"bytes"`
	Files  int    `json:"files"`
	Reason string `json:"reason,omitempty"`
}

// Stats describe the analysis tree.
type Stats struct {
	Files        int              `json:"files"`
	Bytes        int64            `json:"bytes"`
	SkippedFiles int              `json:"skipped_files"`
	SkippedBytes int64            `json:"skipped_bytes"`
	Skipped      []Dir            `json:"skipped"` // largest skipped folders, with the reason
	Largest      []Dir            `json:"largest"` // largest analysed folders (exclusion candidates)
	ByExt        map[string]int64 `json:"by_ext"`  // analysed bytes per extension
	Linked       bool             `json:"linked"`  // hard links (false: copied)
}

// knownBundles are folder names of popular admin themes and front-end
// libraries that are copied into repositories as a whole.
var knownBundles = map[string]bool{
	"smartadmin": true, "metronic": true, "adminlte": true, "gentelella": true, "inspinia": true, "coreui": true,
	"vuexy": true, "materialize": true, "argon": true, "sb-admin": true, "sb-admin-2": true, "startbootstrap": true,
	"ckeditor": true, "ckeditor5": true, "tinymce": true, "ckfinder": true, "kcfinder": true, "elfinder": true,
	"fontawesome": true, "font-awesome": true, "fontawesome-free": true, "pdfjs": true, "pdf.js": true,
	"jquery-ui": true, "datatables": true, "fullcalendar": true, "highcharts": true, "amcharts": true,
	"amcharts4": true, "echarts": true, "summernote": true, "select2": true, "bootstrap-datepicker": true,
	"codemirror": true, "ace-builds": true, "monaco-editor": true, "swagger-ui": true, "mathjax": true,
	"phpmyadmin": true, "phpexcel": true, "tcpdf": true, "fpdf": true, "dompdf": true,
}

// assetDirs are typical sub-folders of a theme or library distribution.
var assetDirs = map[string]bool{
	"css": true, "js": true, "fonts": true, "webfonts": true, "img": true, "images": true, "plugin": true,
	"plugins": true, "vendors": true, "scss": true, "sass": true, "less": true, "dist": true, "media": true, "icons": true,
}

// serverCode are extensions of application code that a theme never has.
var serverCode = map[string]bool{
	".php": true, ".cs": true, ".py": true, ".java": true, ".go": true, ".rb": true, ".kt": true, ".vb": true,
	".aspx": true, ".cshtml": true, ".jsp": true,
}

// IsBundle reports whether dir looks like a vendored theme or library:
// a well-known name, or a demo distribution (many HTML pages next to
// css/js/fonts/plugins folders and no server-side code).
func IsBundle(dir string) bool {
	if knownBundles[strings.ToLower(filepath.Base(dir))] {
		return true
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	html, assets := 0, 0
	for _, e := range entries {
		name := strings.ToLower(e.Name())
		if e.IsDir() {
			if assetDirs[name] {
				assets++
			}
			continue
		}
		ext := filepath.Ext(name)
		if serverCode[ext] {
			return false
		}
		if ext == ".html" || ext == ".htm" {
			html++
		}
	}
	return html >= 10 && assets >= 3
}

// IsMinified reports whether a JavaScript/CSS file is minified or bundled
// (very long lines in its first 8 KB).
func IsMinified(path string) bool {
	f, err := os.Open(path) //nolint:gosec // inside the checkout
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()
	buf := make([]byte, 8<<10)
	n, _ := io.ReadFull(f, buf)
	buf = buf[:n]
	if n < 2048 {
		return false
	}
	longest, lines := 0, 0
	for len(buf) > 0 {
		i := bytes.IndexByte(buf, '\n')
		if i < 0 {
			i = len(buf)
		}
		longest = max(longest, i)
		lines++
		buf = buf[min(i+1, len(buf)):]
	}
	return longest > 1000 || n/lines > 300
}

func minifiable(name string) bool {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".js", ".mjs", ".cjs", ".css":
		return true
	}
	return false
}

// skipGroup is the folder a file is accounted to: its directory, cut to the top two
// path segments ("smartadmin/plugin"), or the whole path for root files.
func skipGroup(rel string, depth int) string {
	dir := path.Dir(rel)
	if dir == "." {
		return "/" // files at the repository root
	}
	parts := strings.Split(dir, "/")
	if len(parts) <= depth {
		return dir
	}
	return strings.Join(parts[:depth], "/")
}

// Build creates the analysis tree of src at dst and returns its stats.
func Build(src, dst string, opt Options) (*Stats, error) {
	if err := os.MkdirAll(dst, 0o750); err != nil {
		return nil, err
	}
	st := &Stats{ByExt: map[string]int64{}, Linked: true}
	skipped := map[string]*Dir{}
	kept := map[string]*Dir{}
	skip := func(group, reason string, size int64) {
		k := reason + "\x00" + group
		d := skipped[k]
		if d == nil {
			d = &Dir{Path: group, Reason: reason}
			skipped[k] = d
		}
		d.Files++
		d.Bytes += size
		st.SkippedFiles++
		st.SkippedBytes += size
	}
	err := filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil //nolint:nilerr // unreadable entries are skipped
		}
		rel, rerr := filepath.Rel(src, p)
		if rerr != nil || rel == "." {
			return nil
		}
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			if d.Name() == ".git" {
				return filepath.SkipDir
			}
			reason := ""
			switch {
			case scanner.Excluded(rel, opt.Excludes):
				reason = ReasonExcluded
			case opt.SkipBundles && IsBundle(p):
				reason = ReasonBundle
			}
			if reason != "" {
				size, files := dirSize(p)
				skipped[reason+"\x00"+rel] = &Dir{Path: rel, Reason: reason, Bytes: size, Files: files}
				st.SkippedFiles += files
				st.SkippedBytes += size
				return filepath.SkipDir
			}
			return os.MkdirAll(filepath.Join(dst, filepath.FromSlash(rel)), 0o750)
		}
		if !d.Type().IsRegular() {
			return nil
		}
		info, ierr := d.Info()
		if ierr != nil {
			return nil //nolint:nilerr // vanished file
		}
		size := info.Size()
		group := skipGroup(rel, 2)
		switch {
		case scanner.Excluded(rel, opt.Excludes):
			skip(group, ReasonExcluded, size)
			return nil
		case opt.MaxFileBytes > 0 && size > opt.MaxFileBytes:
			skip(rel, ReasonLarge, size)
			return nil
		case opt.SkipMinified && minifiable(d.Name()) && IsMinified(p):
			skip(group, ReasonMinified, size)
			return nil
		}
		to := filepath.Join(dst, filepath.FromSlash(rel))
		// The tree is built before any tool runs, in the network-less scan
		// container: nothing can swap a path between the walk and the link.
		if err := os.Link(p, to); err != nil { //nolint:gosec // see above; regular files only, symlinks are not followed
			st.Linked = false
			if err := copyFile(p, to); err != nil {
				return err
			}
		}
		st.Files++
		st.Bytes += size
		st.ByExt[strings.ToLower(filepath.Ext(d.Name()))] += size
		g := skipGroup(rel, 2)
		k := kept[g]
		if k == nil {
			k = &Dir{Path: g}
			kept[g] = k
		}
		k.Files++
		k.Bytes += size
		return nil
	})
	if err != nil {
		return nil, err
	}
	st.Skipped = top(skipped, 15)
	st.Largest = top(kept, 10)
	return st, nil
}

func top(m map[string]*Dir, n int) []Dir {
	out := make([]Dir, 0, len(m))
	for _, d := range m {
		out = append(out, *d)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Bytes != out[j].Bytes {
			return out[i].Bytes > out[j].Bytes
		}
		return out[i].Path < out[j].Path
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}

func dirSize(dir string) (int64, int) {
	var size int64
	files := 0
	_ = filepath.WalkDir(dir, func(_ string, d fs.DirEntry, err error) error {
		if err == nil && d.Type().IsRegular() {
			if info, err := d.Info(); err == nil {
				size += info.Size()
				files++
			}
		}
		return nil
	})
	return size, files
}

func copyFile(from, to string) error {
	in, err := os.Open(from) //nolint:gosec // inside the checkout
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	out, err := os.OpenFile(to, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o640) //nolint:gosec // inside the analysis tree
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}
