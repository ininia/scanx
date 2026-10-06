package detect

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestScanFixture(t *testing.T) {
	r, err := Scan(filepath.Join("..", "..", "testdata", "repos", "php-vuln"))
	if err != nil {
		t.Fatal(err)
	}
	if !r.HasLanguage("php") || r.Languages["php"] != 3 {
		t.Fatalf("php files: %v", r.Languages)
	}
	if !r.HasEcosystem("composer") || !r.HasIaC("dockerfile") {
		t.Fatalf("ecosystems %v iac %v", r.Ecosystems, r.IaC)
	}
	if strings.Join(r.Lockfiles, ",") != "composer.json,composer.lock" {
		t.Fatalf("lockfiles %v", r.Lockfiles)
	}
}

func TestScanSkipsVendorAndDetectsGit(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{
		"main.go":                 "package main",
		"go.mod":                  "module x",
		"vendor/lib/x.go":         "package lib",
		"node_modules/a/index.js": "x",
		".git/HEAD":               "ref: refs/heads/main",
		"infra/main.tf":           "resource {}",
		"charts/app/Chart.yaml":   "name: app",
		"build/Dockerfile.prod":   "FROM scratch",
		"src/App.csproj":          "<Project/>",
	} {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	r, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}
	if r.Languages["go"] != 1 || r.Languages["javascript"] != 0 {
		t.Fatalf("vendor/node_modules not skipped: %v", r.Languages)
	}
	if !r.HasGit {
		t.Fatal("git not detected")
	}
	for _, k := range []string{"terraform", "helm", "dockerfile", "yaml"} {
		if !r.HasIaC(k) {
			t.Errorf("iac %s missing: %v", k, r.IaC)
		}
	}
	if !r.HasEcosystem("go") || !r.HasEcosystem("nuget") {
		t.Fatalf("ecosystems %v", r.Ecosystems)
	}
}
