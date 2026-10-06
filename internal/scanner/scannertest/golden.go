// Package scannertest provides golden-file helpers for scanner adapters.
// Inputs under testdata/scanner-outputs are REAL tool outputs produced by
// scripts/capture-golden.sh; expected files are regenerated with
//
//	go test ./internal/scanner/... -update
//
// and must be reviewed before committing.
package scannertest

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

var update = flag.Bool("update", false, "rewrite golden expected files")

// Root returns the repository root.
func Root() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "..", "..")
}

// Input reads a captured tool output.
func Input(t *testing.T, rel string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(Root(), "testdata", "scanner-outputs", filepath.FromSlash(rel)))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// Golden compares got (marshalled as indented JSON) with the expected file.
func Golden(t *testing.T, rel string, got any) {
	t.Helper()
	b, err := json.MarshalIndent(got, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	b = append(b, '\n')
	path := filepath.Join(Root(), "testdata", "scanner-outputs", filepath.FromSlash(rel))
	if *update {
		if err := os.WriteFile(path, b, 0o644); err != nil { //nolint:gosec // test fixture
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path) //nolint:gosec // test fixture path
	if err != nil {
		t.Fatalf("%v (run with -update to create)", err)
	}
	if !bytes.Equal(bytes.ReplaceAll(want, []byte("\r\n"), []byte("\n")), b) {
		t.Errorf("golden mismatch for %s; run with -update and review the diff.\ngot:\n%s", rel, b)
	}
}
