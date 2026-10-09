package opengrep

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRuleLanguages(t *testing.T) {
	inline := "rules:\n- id: a\n  languages: [js, ts]\n  pattern: x\n"
	block := "rules:\n  - id: b\n    languages:\n      - csharp\n      - \"c#\"\n    pattern: y\n"
	if got := strings.Join(ruleLanguages([]byte(inline)), ","); got != "javascript,typescript" {
		t.Fatal(got)
	}
	if got := strings.Join(ruleLanguages([]byte(block)), ","); got != "csharp" {
		t.Fatal(got)
	}
	if ruleLanguages([]byte("rules: []\n")) != nil {
		t.Fatal("unknown must be nil")
	}
}

func TestSelectRuleFiles(t *testing.T) {
	dir := t.TempDir()
	files := map[string]string{
		"py.yml":      "rules:\n- id: p\n  languages: [python]\n",
		"cs.yaml":     "rules:\n- id: c\n  languages:\n    - csharp\n",
		"js.yml":      "rules:\n- id: j\n  languages: [javascript, typescript]\n",
		"generic.yml": "rules:\n- id: g\n  languages: [generic]\n",
		"weird.yml":   "rules:\n- id: w\n",
		"README.md":   "not a rule",
	}
	for n, c := range files {
		if err := os.WriteFile(filepath.Join(dir, n), []byte(c), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	got, kept, total := selectRuleFiles([]string{dir}, []string{"csharp", "javascript"})
	names := make([]string, 0, len(got))
	for _, g := range got {
		names = append(names, filepath.Base(g))
	}
	if strings.Join(names, ",") != "cs.yaml,generic.yml,js.yml,weird.yml" || kept != 4 || total != 5 {
		t.Fatalf("selected %v (%d/%d)", names, kept, total)
	}
	if d, _, _ := selectRuleFiles([]string{dir}, nil); len(d) != 1 || d[0] != dir {
		t.Fatal("no languages must keep the directories")
	}
}
