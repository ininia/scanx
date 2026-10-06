// Package rules assembles the SAST rule bundle shipped in the scanner image
// and enforces the rule license gate (ADR-003, ADR-006): only rule files with
// a known, allowed license are bundled; forbidden licenses fail the build.
package rules

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Source describes one rule repository checked out at a pinned commit.
type Source struct {
	Name    string   `json:"name"`
	URL     string   `json:"url,omitempty"`
	Commit  string   `json:"commit,omitempty"`
	Dir     string   `json:"dir"`               // local checkout path (relative to the sources file)
	Include []string `json:"include,omitempty"` // sub-directories to take; empty = whole repo
	// License is the SPDX id applying to every file, or "per-file" to read a
	// "License:" header from each rule file.
	License     string `json:"license"`
	LicenseFile string `json:"license_file,omitempty"`
	// Profile "full" puts the source under FullProfileDir: noisy/audit rules
	// that only run with --profile full.
	Profile string `json:"profile,omitempty"`
}

// FullProfileDir is the bundle sub-directory for full-profile-only sources.
const FullProfileDir = "_full"

// destName is the bundle directory of a source.
func (s Source) destName() string {
	if s.Profile == "full" {
		return FullProfileDir + "/" + s.Name
	}
	return s.Name
}

// Entry is one bundled rule file in the manifest.
type Entry struct {
	File   string `json:"file"`
	Source string `json:"source"`
	SPDX   string `json:"spdx"`
}

// Manifest is written as RULES-LICENSES.json next to the bundle.
type Manifest struct {
	Sources []Source `json:"sources"`
	Rules   []Entry  `json:"rules"`
	Skipped []Entry  `json:"skipped,omitempty"`
}

// allowed SPDX ids. Copyleft licenses are fine because rule files are shipped
// unmodified as separate data files with their source and license text.
var allowed = map[string]bool{
	"MIT": true, "Apache-2.0": true, "BSD-2-Clause": true, "BSD-3-Clause": true,
	"LGPL-2.1-only": true, "LGPL-2.1-or-later": true, "LGPL-3.0-only": true, "LGPL-3.0-or-later": true,
	"GPL-2.0-only": true, "GPL-2.0-or-later": true, "GPL-3.0-only": true, "GPL-3.0-or-later": true,
	"AGPL-3.0-only": true, "AGPL-3.0-or-later": true, "BUSL-1.1": true,
}

// forbidden markers anywhere in a rule file fail the gate.
var forbidden = []string{
	"commons clause", "semgrep rules license", "enterprise edition", "noncommercial",
	"non-commercial", "cc-by-nc", "gitlab enterprise",
}

// ErrForbidden is returned when a rule file carries a forbidden license.
var ErrForbidden = errors.New("forbidden rule license")

var headerRe = regexp.MustCompile(`(?im)^\s*#\s*License:\s*(?:License:\s*)?(.+?)\s*$`)

// headerSPDX maps the free-form "License:" headers found in rule repos.
func headerSPDX(h string) string {
	l := strings.ToLower(h)
	l = strings.NewReplacer(
		"gnu affero general public license", "agpl",
		"gnu lesser general public license", "lgpl",
		"gnu general public license", "gpl",
		" v", " ", "version ", "",
	).Replace(l)
	switch {
	case strings.HasPrefix(l, "agpl 3") || strings.HasPrefix(l, "agpl-3"):
		return "AGPL-3.0-only"
	case strings.HasPrefix(l, "mit"):
		return "MIT"
	case strings.HasPrefix(l, "apache"):
		return "Apache-2.0"
	case strings.HasPrefix(l, "lgpl 3") || strings.HasPrefix(l, "lgpl-3") || strings.HasPrefix(l, "lgpl v3"):
		return "LGPL-3.0-only"
	case strings.HasPrefix(l, "lgpl 2.1") || strings.HasPrefix(l, "lgpl-2.1"):
		return "LGPL-2.1-only"
	case strings.HasPrefix(l, "gpl 2") || strings.HasPrefix(l, "gpl-2"):
		return "GPL-2.0-only"
	case strings.HasPrefix(l, "gpl 3") || strings.HasPrefix(l, "gpl-3"):
		return "GPL-3.0-only"
	case strings.HasPrefix(l, "bsd"):
		return "BSD-3-Clause"
	}
	return ""
}

// isRuleFile reports whether data is a Semgrep-format rule file (top-level
// "rules:" key). Test targets and other YAML are ignored.
func isRuleFile(data []byte) bool {
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 64*1024), 4<<20)
	for sc.Scan() {
		if strings.HasPrefix(sc.Text(), "rules:") {
			return true
		}
	}
	return false
}

// Bundle copies allowed rule files from sources into outDir, writes the
// manifest and copies each source's license text. baseDir resolves Source.Dir.
func Bundle(baseDir, outDir string, sources []Source) (*Manifest, error) {
	m := &Manifest{Sources: sources}
	for _, src := range sources {
		if src.License != "per-file" && !allowed[src.License] {
			return nil, fmt.Errorf("%w: source %s declares %q", ErrForbidden, src.Name, src.License)
		}
		root := filepath.Join(baseDir, filepath.FromSlash(src.Dir))
		dirs := src.Include
		if len(dirs) == 0 {
			dirs = []string{"."}
		}
		for _, d := range dirs {
			if err := bundleDir(root, d, outDir, src, m); err != nil {
				return nil, err
			}
		}
		if src.LicenseFile != "" {
			if err := copyFile(filepath.Join(root, src.LicenseFile), filepath.Join(outDir, filepath.FromSlash(src.destName()), "LICENSE")); err != nil {
				return nil, fmt.Errorf("license file of %s: %w", src.Name, err)
			}
		}
	}
	sort.Slice(m.Rules, func(i, j int) bool { return m.Rules[i].File < m.Rules[j].File })
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(outDir, "RULES-LICENSES.json"), b, 0o644); err != nil { //nolint:gosec // public manifest
		return nil, err
	}
	return m, nil
}

func bundleDir(root, sub, outDir string, src Source, m *Manifest) error {
	start := filepath.Join(root, filepath.FromSlash(sub))
	return filepath.WalkDir(start, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if name := d.Name(); name == ".git" || name == ".github" {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Type()&fs.ModeSymlink != 0 {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		if strings.HasPrefix(strings.ToUpper(d.Name()), "LICENSE") || strings.HasPrefix(strings.ToUpper(d.Name()), "COPYING") {
			// Keep license texts that live next to the rules they cover.
			return copyFile(path, filepath.Join(outDir, filepath.FromSlash(src.destName()), filepath.FromSlash(rel)))
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".yml" && ext != ".yaml" {
			return nil
		}
		data, err := os.ReadFile(path) //nolint:gosec // walking a trusted, pinned checkout
		if err != nil {
			return err
		}
		if !isRuleFile(data) {
			return nil
		}
		lower := strings.ToLower(string(data))
		for _, f := range forbidden {
			if strings.Contains(lower, f) {
				return fmt.Errorf("%w: %s/%s contains %q", ErrForbidden, src.Name, rel, f)
			}
		}
		spdx := src.License
		if spdx == "per-file" {
			spdx = ""
			if mm := headerRe.FindSubmatch(data); mm != nil {
				spdx = headerSPDX(string(mm[1]))
			}
		}
		entry := Entry{File: src.destName() + "/" + rel, Source: src.Name, SPDX: spdx}
		if !allowed[spdx] {
			entry.SPDX = "unknown"
			m.Skipped = append(m.Skipped, entry)
			return nil
		}
		m.Rules = append(m.Rules, entry)
		return copyFile(path, filepath.Join(outDir, filepath.FromSlash(src.destName()), filepath.FromSlash(rel)))
	})
}

func copyFile(from, to string) error {
	data, err := os.ReadFile(from) //nolint:gosec // trusted build input
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(to), 0o755); err != nil { //nolint:gosec // world-readable rule bundle
		return err
	}
	return os.WriteFile(to, data, 0o644) //nolint:gosec // world-readable rule bundle
}

// LoadSources reads a sources JSON file.
func LoadSources(path string) ([]Source, error) {
	data, err := os.ReadFile(path) //nolint:gosec // operator-supplied build file
	if err != nil {
		return nil, err
	}
	var s []Source
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return s, nil
}
