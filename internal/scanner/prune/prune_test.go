package prune

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, root, rel, content string) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestBuild(t *testing.T) {
	src, dst := t.TempDir(), filepath.Join(t.TempDir(), "analysis")
	write(t, src, "index.php", "<?php echo 1;\n")
	write(t, src, "app/user.js", strings.Repeat("var a = 1;\n", 400))
	write(t, src, "app/lib.js", strings.Repeat("x", 9000)) // minified: one long line
	write(t, src, "vendor/pkg/a.php", "<?php\n")
	write(t, src, "big.php", strings.Repeat("// line\n", 200000))
	write(t, src, ".git/HEAD", "ref: x\n")
	for i := range 12 {
		write(t, src, "theme/page"+string(rune('a'+i))+".html", "<html></html>\n")
	}
	for _, d := range []string{"css", "js", "fonts"} {
		write(t, src, "theme/"+d+"/x.css", "a{}\n")
	}
	write(t, src, "ckeditor/ckeditor.js", "var c;\n")
	st, err := Build(src, dst, Options{Excludes: []string{"vendor", ".git"}, MaxFileBytes: 1 << 20, SkipMinified: true, SkipBundles: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, keep := range []string{"index.php", "app/user.js"} {
		if _, err := os.Stat(filepath.Join(dst, keep)); err != nil {
			t.Errorf("%s missing", keep)
		}
	}
	for _, gone := range []string{"app/lib.js", "vendor", "big.php", "theme", "ckeditor", ".git"} {
		if _, err := os.Stat(filepath.Join(dst, gone)); err == nil {
			t.Errorf("%s kept", gone)
		}
	}
	if st.Files != 2 {
		t.Errorf("files = %d", st.Files)
	}
	reasons := map[string]string{}
	for _, d := range st.Skipped {
		reasons[d.Path] = d.Reason
	}
	if reasons["theme"] != ReasonBundle || reasons["ckeditor"] != ReasonBundle || reasons["big.php"] != ReasonLarge ||
		reasons["app"] != ReasonMinified || reasons["vendor"] != ReasonExcluded {
		t.Errorf("reasons %v", reasons)
	}
}

func TestOwnAssetsAreNotABundle(t *testing.T) {
	src := t.TempDir()
	for _, d := range []string{"css", "js", "img"} {
		write(t, src, "assets/"+d+"/a.txt", "x")
	}
	write(t, src, "assets/index.php", "<?php\n")
	if IsBundle(filepath.Join(src, "assets")) {
		t.Fatal("application assets taken for a bundle")
	}
}
