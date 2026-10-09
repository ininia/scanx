package app

import (
	"os"
	"path/filepath"
	"testing"
)

func TestScopeTreeCopiesOnlyListedFiles(t *testing.T) {
	src, tmp := t.TempDir(), t.TempDir()
	for _, f := range []string{"a/x.cs", "a/y.cs", "b/z.js"} {
		p := filepath.Join(src, f)
		_ = os.MkdirAll(filepath.Dir(p), 0o750)
		_ = os.WriteFile(p, []byte(f), 0o600)
	}
	_ = os.Symlink("/etc/passwd", filepath.Join(src, "link"))
	list := filepath.Join(tmp, "changed.txt")
	_ = os.WriteFile(list, []byte("a/x.cs\nb/z.js\n../../etc/passwd\nlink\nmissing.cs\n"), 0o600)
	dst, n, err := scopeTree(src, list, tmp)
	if err != nil || n != 2 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	for f, want := range map[string]bool{"a/x.cs": true, "b/z.js": true, "a/y.cs": false, "link": false} {
		_, err := os.Lstat(filepath.Join(dst, f))
		if (err == nil) != want {
			t.Errorf("%s present=%v", f, err == nil)
		}
	}
}
