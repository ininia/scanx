package osv

import (
	"strings"
	"testing"

	"github.com/ininia/scanx/internal/detect"
	"github.com/ininia/scanx/internal/finding"
	"github.com/ininia/scanx/internal/scanner"
	"github.com/ininia/scanx/internal/scanner/scannertest"
)

func TestParseGolden(t *testing.T) {
	fs, err := parse(scannertest.Input(t, "osv/php-vuln.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 19 { // 13 groups for guzzle + 6 for psr7
		t.Fatalf("findings %d", len(fs))
	}
	var g *finding.Finding
	for i := range fs {
		if strings.HasPrefix(fs[i].Title, "CVE-2022-31090") {
			g = &fs[i]
		}
	}
	if g == nil || g.Severity != finding.High || g.Package.FixedVersion != "7.4.5" ||
		g.Package.Ecosystem != "packagist" || !contains(g.CVE, "GHSA-25mq-v84q-4j7r") {
		t.Fatalf("CVE-2022-31090 mapping wrong: %+v %+v", g, g.Package)
	}
	finding.Normalize(fs, finding.NormalizeOptions{})
	scannertest.Golden(t, "osv/php-vuln.expected.json", fs)
}

func TestParseMissingOutputIsEmpty(t *testing.T) {
	fs, err := Scanner{}.Parse(scanner.Env{OutDir: t.TempDir()})
	if err != nil || fs != nil {
		t.Fatalf("exit 128 without output must yield no findings: %v %v", fs, err)
	}
	if _, err := parse([]byte("x")); err == nil {
		t.Fatal("expected error")
	}
}

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{{"7.4.5", "7.4.0", 1}, {"6.5.8", "7.4.0", -1}, {"1.8.4", "1.8.4", 0}, {"2.0", "2.0.1", -1}, {"10.0.0", "9.9.9", 1}}
	for _, c := range cases {
		if got := compareVersions(c.a, c.b); got != c.want {
			t.Errorf("compare(%s,%s)=%d want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestCommandAndApplies(t *testing.T) {
	c := Scanner{}.Command(scanner.Env{SourceDir: "/s", OutDir: "/o", DBDir: "/db"}, scanner.Settings{})
	if !strings.Contains(strings.Join(c.Args, " "), "--offline") || c.Env[0] != "OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY=/db/osv" {
		t.Fatalf("%+v", c)
	}
	if len(c.OKExitCodes) != 3 {
		t.Fatal("exit codes 0/1/128 are successful runs")
	}
	if (Scanner{}).Applies(&detect.Result{}, scanner.Settings{}) {
		t.Fatal("must not run without lock files")
	}
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
