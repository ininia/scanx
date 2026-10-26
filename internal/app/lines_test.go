package app

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ininia/scanx/internal/engine"
	"github.com/ininia/scanx/internal/finding"
)

func TestScopeToLines(t *testing.T) {
	p := filepath.Join(t.TempDir(), "lines.json")
	if err := os.WriteFile(p, []byte(`{"a.php":[[10,12]],"img.png":null}`), 0o600); err != nil {
		t.Fatal(err)
	}
	res := &engine.Result{Findings: []finding.Finding{
		{File: "a.php", StartLine: 11, Fingerprint: "in"},
		{File: "a.php", StartLine: 3, Fingerprint: "old"},
		{File: "a.php", StartLine: 8, EndLine: 10, Fingerprint: "overlap"},
		{File: "composer.lock", Fingerprint: "dep"},
		{File: "img.png", StartLine: 1, Fingerprint: "binary"},
	}}
	seen, ok := scopeToLines(p, res)
	if !ok || len(seen) != 5 {
		t.Fatalf("%v %v", ok, seen)
	}
	got := map[string]bool{}
	for _, f := range res.Findings {
		got[f.Fingerprint] = true
	}
	if !got["in"] || !got["overlap"] || !got["dep"] || got["old"] || got["binary"] || len(got) != 3 {
		t.Fatalf("kept %v", got)
	}
	if _, ok := scopeToLines(filepath.Join(t.TempDir(), "missing.json"), res); ok {
		t.Fatal("missing file scoped")
	}
}
