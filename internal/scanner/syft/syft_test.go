package syft

import (
	"strings"
	"testing"

	"github.com/ininia/scanx/internal/scanner"
	"github.com/ininia/scanx/internal/scanner/scannertest"
)

func TestValidateGolden(t *testing.T) {
	if err := validate(scannertest.Input(t, "syft/php-vuln.cdx.json")); err != nil {
		t.Fatal(err)
	}
	if err := validate([]byte(`{"bomFormat":"SPDX"}`)); err == nil {
		t.Fatal("non-CycloneDX must fail")
	}
	if err := validate([]byte(`x`)); err == nil {
		t.Fatal("malformed must fail")
	}
}

func TestCommand(t *testing.T) {
	c := Scanner{}.Command(scanner.Env{SourceDir: "/s", OutDir: "/o"}, scanner.Settings{})
	joined := strings.Join(c.Args, " ")
	if !strings.Contains(joined, "dir:/s") || !strings.Contains(joined, "cyclonedx-json=/o/sbom.cdx.json") || c.Env[0] != "SYFT_CHECK_FOR_APP_UPDATE=false" {
		t.Fatalf("%+v", c)
	}
}
