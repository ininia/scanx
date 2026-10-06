package trivy

import (
	"strings"
	"testing"

	"github.com/ininia/scanx/internal/finding"
	"github.com/ininia/scanx/internal/scanner"
	"github.com/ininia/scanx/internal/scanner/scannertest"
)

func TestParseGolden(t *testing.T) {
	fs, err := parse(scannertest.Input(t, "trivy/php-vuln.json"))
	if err != nil {
		t.Fatal(err)
	}
	cats := map[finding.Category]int{}
	var guzzle *finding.Finding
	for i, f := range fs {
		cats[f.Category]++
		if f.RuleID == "CVE-2022-29248" {
			guzzle = &fs[i]
		}
	}
	if cats[finding.CategorySCA] < 10 || cats[finding.CategoryIaC] < 1 {
		t.Fatalf("categories %v", cats)
	}
	if guzzle == nil || guzzle.Package == nil || guzzle.Package.Name != "guzzlehttp/guzzle" ||
		guzzle.Package.Version != "7.4.0" || guzzle.File != "composer.lock" || !strings.Contains(guzzle.Remediation, "7.4.3") {
		t.Fatalf("guzzle CVE mapping wrong: %+v", guzzle)
	}
	finding.Normalize(fs, finding.NormalizeOptions{})
	scannertest.Golden(t, "trivy/php-vuln.expected.json", fs)

	empty, err := parse(scannertest.Input(t, "trivy/empty.json"))
	if err != nil || len(empty) != 0 {
		t.Fatalf("empty: %v %d", err, len(empty))
	}
	if _, err := parse([]byte("[")); err == nil {
		t.Fatal("expected error")
	}
}

func TestSecretsAndLicenses(t *testing.T) {
	fs, err := parse([]byte(`{"Results":[{"Target":"app/.env","Secrets":[{"RuleID":"aws-access-key-id","Severity":"CRITICAL","Title":"AWS Access Key ID","StartLine":2,"EndLine":2,"Match":"AWS_KEY=****************"}]},
		{"Target":"go.mod","Licenses":[{"Severity":"HIGH","Category":"restricted","PkgName":"x","Name":"GPL-3.0","FilePath":""}]},
		{"Target":"main.tf","Misconfigurations":[{"ID":"AVD-1","Title":"t","Severity":"LOW","Status":"PASS"}]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 2 {
		t.Fatalf("PASS misconfigurations must be skipped: %+v", fs)
	}
	if fs[0].Category != finding.CategorySecret || fs[0].Severity != finding.Critical {
		t.Fatalf("secret: %+v", fs[0])
	}
	if fs[1].Category != finding.CategoryLicense || fs[1].Severity != finding.Medium {
		t.Fatalf("license severity must be capped at medium: %+v", fs[1])
	}
}

func TestCommandIsOffline(t *testing.T) {
	c := Scanner{}.Command(scanner.Env{SourceDir: "/work/src", OutDir: "/out", DBDir: "/db"}, scanner.Settings{Exclude: []string{"*.min.css", "build"}})
	joined := strings.Join(c.Args, " ")
	for _, need := range []string{
		"--skip-db-update", "--offline-scan", "--skip-version-check", "--disable-telemetry",
		"--cache-backend memory", "--skip-dirs build", "--skip-files *.min.css", "--cache-dir /db/trivy",
	} {
		if !strings.Contains(joined, need) {
			t.Errorf("missing %q", need)
		}
	}
}
