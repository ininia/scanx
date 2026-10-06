package app

// Scanner adapters register themselves in init(); importing them here makes
// them available to every command that runs scans.
import (
	_ "github.com/ininia/scanx/internal/scanner/gitleaks"
	_ "github.com/ininia/scanx/internal/scanner/opengrep"
	_ "github.com/ininia/scanx/internal/scanner/osv"
	_ "github.com/ininia/scanx/internal/scanner/syft"
	_ "github.com/ininia/scanx/internal/scanner/trivy"
)
