package rules

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

const ruleBody = "rules:\n  - id: x\n    languages: [go]\n    severity: ERROR\n    message: m\n    pattern: foo()\n"

func write(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for name, body := range files {
		p := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestBundlePerFileAndRepoLicenses(t *testing.T) {
	base, out := t.TempDir(), t.TempDir()
	write(t, base, map[string]string{
		"gl/LICENSE":               "MIT Expat",
		"gl/go/a.yml":              "# License: MIT (c) GitLab Inc.\n" + ruleBody,
		"gl/go/b.yml":              "# License: Apache 2.0 (c) gosec\n" + ruleBody,
		"gl/c/c.yml":               "# License: GPL 2.0 (c) FSF\n" + ruleBody,
		"gl/go/noheader.yml":       ruleBody,
		"gl/go/test-target.yaml":   "apiVersion: v1\nkind: Pod\n",
		"gl/rules/gitlab/ee.yml":   "# License: GitLab EE\n" + ruleBody, // not included
		"tob/LICENSE":              "AGPL",
		"tob/python/r.yaml":        ruleBody,
		"tob/.github/workflow.yml": "rules:\n",
		"tob/python/sample.py":     "print(1)",
		"gl/go/double-header.yml":  "# License: License: MIT (c) GitLab Inc.\n" + ruleBody,
		"gl/c/lgpl.yml":            "# License: GNU Lesser General Public License v3.0\n" + ruleBody,
		"gl/c/LICENSE":             "LGPL text",
	})
	m, err := Bundle(base, out, []Source{
		{Name: "gitlab", Dir: "gl", Include: []string{"go", "c"}, License: "per-file", LicenseFile: "LICENSE"},
		{Name: "trailofbits", Dir: "tob", License: "AGPL-3.0-only", LicenseFile: "LICENSE"},
	})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, r := range m.Rules {
		got[r.File] = r.SPDX
	}
	want := map[string]string{
		"gitlab/go/a.yml": "MIT", "gitlab/go/b.yml": "Apache-2.0", "gitlab/c/c.yml": "GPL-2.0-only",
		"gitlab/go/double-header.yml": "MIT", "trailofbits/python/r.yaml": "AGPL-3.0-only",
		"gitlab/c/lgpl.yml": "LGPL-3.0-only",
	}
	if len(got) != len(want) {
		t.Fatalf("rules %v", got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q want %q", k, got[k], v)
		}
	}
	if len(m.Skipped) != 1 || m.Skipped[0].File != "gitlab/go/noheader.yml" {
		t.Fatalf("skipped %v", m.Skipped)
	}
	for _, f := range []string{"gitlab/go/a.yml", "gitlab/LICENSE", "gitlab/c/LICENSE", "trailofbits/LICENSE", "RULES-LICENSES.json"} {
		if _, err := os.Stat(filepath.Join(out, filepath.FromSlash(f))); err != nil {
			t.Errorf("missing %s", f)
		}
	}
	for _, f := range []string{"gitlab/go/noheader.yml", "gitlab/rules/gitlab/ee.yml", "trailofbits/.github/workflow.yml", "gitlab/go/test-target.yaml"} {
		if _, err := os.Stat(filepath.Join(out, filepath.FromSlash(f))); err == nil {
			t.Errorf("%s must not be bundled", f)
		}
	}
	raw, _ := os.ReadFile(filepath.Join(out, "RULES-LICENSES.json"))
	var back Manifest
	if err := json.Unmarshal(raw, &back); err != nil || len(back.Rules) != 6 {
		t.Fatalf("manifest: %v %d", err, len(back.Rules))
	}
}

func TestBundleRejectsForbidden(t *testing.T) {
	cases := map[string]string{
		"commons": "# License: LGPL-2.1 with Commons Clause\n" + ruleBody,
		"semgrep": "# Semgrep Rules License v1.0\n" + ruleBody,
		"nc":      "# CC-BY-NC-SA-4.0\n" + ruleBody,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			base := t.TempDir()
			write(t, base, map[string]string{"r/x.yml": body})
			_, err := Bundle(base, t.TempDir(), []Source{{Name: "r", Dir: "r", License: "MIT"}})
			if !errors.Is(err, ErrForbidden) {
				t.Fatalf("want ErrForbidden, got %v", err)
			}
		})
	}
	if _, err := Bundle(t.TempDir(), t.TempDir(), []Source{{Name: "x", Dir: ".", License: "Elastic-2.0"}}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("unknown repo license must be rejected: %v", err)
	}
}

func TestLoadSources(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "s.json")
	write(t, dir, map[string]string{"s.json": `[{"name":"a","dir":"a","license":"MIT"}]`})
	s, err := LoadSources(p)
	if err != nil || len(s) != 1 || s[0].Name != "a" {
		t.Fatalf("%v %v", s, err)
	}
	write(t, dir, map[string]string{"bad.json": `{`})
	if _, err := LoadSources(filepath.Join(dir, "bad.json")); err == nil {
		t.Fatal("expected parse error")
	}
	if _, err := LoadSources(filepath.Join(dir, "missing.json")); err == nil {
		t.Fatal("expected not found")
	}
}

func TestHeaderSPDX(t *testing.T) {
	cases := map[string]string{
		"MIT (c) GitLab Inc.":                    "MIT",
		"Apache 2.0 (c) gosec":                   "Apache-2.0",
		"GPL 2.0 (c) 1989, 1991 FSF":             "GPL-2.0-only",
		"GNU Lesser General Public License v3.0": "LGPL-3.0-only",
		"GNU General Public License v3.0":        "GPL-3.0-only",
		"GNU Affero General Public License v3.0": "AGPL-3.0-only",
		"LGPL-2.1":                               "LGPL-2.1-only",
		"Proprietary":                            "",
	}
	for in, want := range cases {
		if got := headerSPDX(in); got != want {
			t.Errorf("headerSPDX(%q)=%q want %q", in, got, want)
		}
	}
}

func TestBundleFullProfile(t *testing.T) {
	base, out := t.TempDir(), t.TempDir()
	write(t, base, map[string]string{"audit/LICENSE": "MIT", "audit/rules-audit/x.yml": ruleBody})
	m, err := Bundle(base, out, []Source{{Name: "elttam", Dir: "audit", License: "MIT", LicenseFile: "LICENSE", Profile: "full"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Rules) != 1 || m.Rules[0].File != "_full/elttam/rules-audit/x.yml" {
		t.Fatalf("%+v", m.Rules)
	}
	for _, f := range []string{"_full/elttam/rules-audit/x.yml", "_full/elttam/LICENSE"} {
		if _, err := os.Stat(filepath.Join(out, filepath.FromSlash(f))); err != nil {
			t.Errorf("missing %s", f)
		}
	}
}
