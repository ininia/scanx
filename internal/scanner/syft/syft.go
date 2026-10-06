// Package syft adapts Syft to produce a CycloneDX SBOM. It reports no
// findings; the SBOM file is kept as a scan artifact.
package syft

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/ininia/scanx/internal/detect"
	"github.com/ininia/scanx/internal/finding"
	"github.com/ininia/scanx/internal/scanner"
)

// SBOMFile is the artifact name inside the output directory.
const SBOMFile = "sbom.cdx.json"

// Scanner is the Syft adapter.
type Scanner struct{}

func init() { scanner.Register(Scanner{}) }

// ID implements scanner.Scanner.
func (Scanner) ID() string { return "syft" }

// Name implements scanner.Scanner.
func (Scanner) Name() string { return "Syft (SBOM, CycloneDX)" }

// Tool implements scanner.Scanner.
func (Scanner) Tool() string { return "syft" }

// Category implements scanner.Scanner.
func (Scanner) Category() finding.Category { return "sbom" }

// Applies implements scanner.Scanner.
func (Scanner) Applies(*detect.Result, scanner.Settings) bool { return true }

// Timeout implements scanner.Scanner.
func (Scanner) Timeout(scanner.Settings) time.Duration { return 10 * time.Minute }

// VersionCmd implements scanner.VersionReporter.
func (Scanner) VersionCmd() scanner.Cmd {
	return scanner.Cmd{Path: "syft", Args: []string{"version"}, Env: []string{"SYFT_CHECK_FOR_APP_UPDATE=false"}}
}

// Command implements scanner.Scanner. Remote license lookups default to off
// in Syft and stay off.
func (Scanner) Command(env scanner.Env, s scanner.Settings) scanner.Cmd {
	args := []string{"dir:" + env.SourceDir, "-o", "cyclonedx-json=" + filepath.Join(env.OutDir, SBOMFile), "-q"}
	for _, ex := range append(append([]string{}, scanner.DefaultExcludes...), s.Exclude...) {
		args = append(args, "--exclude", "./**/"+ex+"/**")
	}
	return scanner.Cmd{Path: "syft", Args: args, Env: []string{"SYFT_CHECK_FOR_APP_UPDATE=false"}}
}

// Parse implements scanner.Scanner: validates the SBOM, reports no findings.
func (Scanner) Parse(env scanner.Env) ([]finding.Finding, error) {
	data, err := os.ReadFile(filepath.Join(env.OutDir, SBOMFile))
	if err != nil {
		return nil, err
	}
	return nil, validate(data)
}

func validate(data []byte) error {
	var bom struct {
		BOMFormat string `json:"bomFormat"`
	}
	if err := json.Unmarshal(data, &bom); err != nil {
		return fmt.Errorf("sbom json: %w", err)
	}
	if bom.BOMFormat != "CycloneDX" {
		return fmt.Errorf("unexpected SBOM format %q", bom.BOMFormat)
	}
	return nil
}
