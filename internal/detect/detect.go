// Package detect inspects a source tree and reports languages, package
// ecosystems and infrastructure files so only relevant scanners run.
package detect

import (
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
)

// Result describes what a repository contains (stored as scans.detected).
type Result struct {
	Languages  map[string]int `json:"languages"`  // language → file count
	Ecosystems []string       `json:"ecosystems"` // npm, composer, go, pypi, maven, ...
	Lockfiles  []string       `json:"lockfiles"`  // relative paths of lock/manifest files
	IaC        []string       `json:"iac"`        // dockerfile, terraform, kubernetes, helm, cloudformation
	HasGit     bool           `json:"has_git"`
	Files      int            `json:"files"`
}

// HasLanguage reports whether at least one file of lang was found.
func (r *Result) HasLanguage(lang string) bool { return r.Languages[lang] > 0 }

// HasEcosystem reports whether eco was detected.
func (r *Result) HasEcosystem(eco string) bool { return contains(r.Ecosystems, eco) }

// HasIaC reports whether the IaC kind was detected.
func (r *Result) HasIaC(kind string) bool { return contains(r.IaC, kind) }

var extLang = map[string]string{
	".go": "go", ".php": "php", ".phtml": "php", ".py": "python", ".js": "javascript", ".mjs": "javascript",
	".cjs": "javascript", ".jsx": "javascript", ".ts": "typescript", ".tsx": "typescript", ".java": "java",
	".kt": "kotlin", ".kts": "kotlin", ".scala": "scala", ".rb": "ruby", ".cs": "csharp", ".c": "c", ".h": "c",
	".cc": "cpp", ".cpp": "cpp", ".cxx": "cpp", ".hpp": "cpp", ".rs": "rust", ".swift": "swift",
	".m": "objectivec", ".dart": "dart", ".sh": "shell", ".bash": "shell", ".tf": "terraform", ".hcl": "hcl",
	".sol": "solidity", ".ex": "elixir", ".exs": "elixir", ".lua": "lua", ".yaml": "yaml", ".yml": "yaml",
}

// manifest file name → ecosystem.
var manifests = map[string]string{
	"go.mod": "go", "go.sum": "go",
	"package.json": "npm", "package-lock.json": "npm", "yarn.lock": "npm", "pnpm-lock.yaml": "npm", "bun.lock": "npm",
	"composer.json": "composer", "composer.lock": "composer",
	"requirements.txt": "pypi", "pipfile.lock": "pypi", "poetry.lock": "pypi", "pyproject.toml": "pypi", "uv.lock": "pypi",
	"pom.xml": "maven", "build.gradle": "gradle", "build.gradle.kts": "gradle", "gradle.lockfile": "gradle",
	"gemfile": "rubygems", "gemfile.lock": "rubygems",
	"cargo.toml": "cargo", "cargo.lock": "cargo",
	"packages.lock.json": "nuget", "packages.config": "nuget",
	"pubspec.lock": "pub", "mix.lock": "hex", "conan.lock": "conan",
}

var skipDirs = map[string]bool{".git": true, "node_modules": true, "vendor": true, ".venv": true, "__pycache__": true}

// Scan walks root. Symlinks are not followed.
func Scan(root string) (*Result, error) {
	r := &Result{Languages: map[string]int{}}
	ecos, iac := map[string]bool{}, map[string]bool{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil //nolint:nilerr // unreadable entries are skipped, not fatal
		}
		name := d.Name()
		if d.IsDir() {
			if name == ".git" && path != root {
				r.HasGit = true
			}
			if skipDirs[name] && path != root {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		r.Files++
		lower := strings.ToLower(name)
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		if lang, ok := extLang[strings.ToLower(filepath.Ext(name))]; ok {
			r.Languages[lang]++
		}
		if eco, ok := manifests[lower]; ok {
			ecos[eco] = true
			r.Lockfiles = append(r.Lockfiles, rel)
		}
		if strings.HasSuffix(lower, ".csproj") {
			ecos["nuget"] = true
		}
		switch {
		case lower == "dockerfile" || strings.HasPrefix(lower, "dockerfile.") || strings.HasSuffix(lower, ".dockerfile") || lower == "containerfile":
			iac["dockerfile"] = true
		case strings.HasSuffix(lower, ".tf") || strings.HasSuffix(lower, ".tf.json"):
			iac["terraform"] = true
		case lower == "chart.yaml":
			iac["helm"] = true
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if r.Languages["yaml"] > 0 {
		// Kubernetes/CloudFormation detection by content is left to the IaC
		// scanners; flag YAML so they get a chance to run.
		iac["yaml"] = true
	}
	r.Ecosystems = sortedKeys(ecos)
	r.IaC = sortedKeys(iac)
	sort.Strings(r.Lockfiles)
	return r, nil
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
