package gitfetch

import "testing"

func TestParseChangedLines(t *testing.T) {
	diff := "diff --git a/a.php b/a.php\n--- a/a.php\n+++ b/a.php\n@@ -3 +3 @@\n-x\n+y\n@@ -10,0 +11,4 @@\n+a\n+b\n+c\n+d\n@@ -20,2 +24,0 @@\n-z\n-w\n" +
		"diff --git a/new.js b/new.js\n--- /dev/null\n+++ b/new.js\n@@ -0,0 +1,2 @@\n+1\n+2\n" +
		"diff --git a/img.png b/img.png\nBinary files a/img.png and b/img.png differ\n" +
		"--- a/\"d\303\274z.php\"\n+++ \"b/d\303\274z.php\"\n@@ -1 +1 @@\n-a\n+b\n"
	got := ParseChangedLines(diff)
	want := map[string][]LineRange{"a.php": {{3, 3}, {11, 14}}, "new.js": {{1, 2}}, "düz.php": {{1, 1}}}
	for f, rs := range want {
		if len(got[f]) != len(rs) {
			t.Fatalf("%s: %v", f, got[f])
		}
		for i := range rs {
			if got[f][i] != rs[i] {
				t.Fatalf("%s: %v", f, got[f])
			}
		}
	}
}
