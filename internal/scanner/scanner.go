// Package scanner defines the adapter interface every security tool
// implements, and a registry of the available adapters (spec §7.2).
package scanner

import (
	"sort"
	"sync"
	"time"

	"github.com/ininia/scanx/internal/detect"
	"github.com/ininia/scanx/internal/finding"
)

// Env holds the file system layout a scan runs with. Inside the scanner
// image these come from SCANX_* environment variables.
type Env struct {
	SourceDir string // read-only checkout
	OutDir    string // per-scan writable output directory
	RulesDir  string // SAST rule bundle
	DBDir     string // offline vulnerability databases
	ConfigDir string // scanX-owned tool configs
	ToolHome  string // HOME for tools (pre-populated caches, read-only)
	TmpDir    string // writable scratch (tmpfs)
}

// Settings are per-scan options (project settings / CLI flags).
type Settings struct {
	Profile  string          // fast | default | full
	History  bool            // scan git history for secrets
	Exclude  []string        // extra path globs to exclude
	Disabled map[string]bool // scanner IDs switched off
	Enabled  map[string]bool // scanner IDs switched on explicitly (opt-in tools)
	// SASTTimeout limits the SAST step (opengrep); 0 = DefaultSASTTimeout.
	SASTTimeout time.Duration
}

// DefaultSASTTimeout is the SAST time limit when a project sets none.
const DefaultSASTTimeout = 20 * time.Minute

// Cmd is a process invocation. No shell is ever involved.
type Cmd struct {
	Path string
	Args []string
	Env  []string // extra KEY=VALUE pairs
	// OKExitCodes lists exit codes that mean "ran successfully" (default {0}).
	OKExitCodes []int
}

// Scanner is one tool adapter.
type Scanner interface {
	// ID is the stable identifier, e.g. "gitleaks-dir".
	ID() string
	// Name is a human-readable name.
	Name() string
	// Tool is the binary name (used for version reporting).
	Tool() string
	// Category is the main category of the findings.
	Category() finding.Category
	// Applies reports whether the scanner is relevant for the repository.
	Applies(d *detect.Result, s Settings) bool
	// Command builds the invocation.
	Command(env Env, s Settings) Cmd
	// Timeout bounds one run.
	Timeout(s Settings) time.Duration
	// Parse reads the tool output from env.OutDir and returns findings.
	Parse(env Env) ([]finding.Finding, error)
}

// VersionReporter is implemented by scanners that can report their version.
type VersionReporter interface {
	VersionCmd() Cmd
}

// PostProcessor lets a scanner adjust the combined findings of a scan
// (e.g. downgrade git-history-only secrets).
type PostProcessor interface {
	PostProcess(all []finding.Finding) []finding.Finding
}

// OptIn marks scanners that only run when explicitly enabled.
type OptIn interface {
	OptIn() bool
}

var (
	mu       sync.RWMutex
	registry = map[string]Scanner{}
)

// Register adds a scanner; adapters call it from init(). Duplicate IDs panic
// because they are programmer errors.
func Register(s Scanner) {
	mu.Lock()
	defer mu.Unlock()
	if _, dup := registry[s.ID()]; dup {
		panic("scanner: duplicate id " + s.ID())
	}
	registry[s.ID()] = s
}

// All returns registered scanners sorted by ID.
func All() []Scanner {
	mu.RLock()
	defer mu.RUnlock()
	out := make([]Scanner, 0, len(registry))
	for _, s := range registry {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID() < out[j].ID() })
	return out
}

// Select returns the scanners that should run for d and s.
func Select(d *detect.Result, s Settings) []Scanner {
	var out []Scanner
	for _, sc := range All() {
		if s.Disabled[sc.ID()] {
			continue
		}
		if oi, ok := sc.(OptIn); ok && oi.OptIn() && !s.Enabled[sc.ID()] {
			continue
		}
		if sc.Applies(d, s) {
			out = append(out, sc)
		}
	}
	return out
}

// DefaultExcludes are third-party/vendored paths skipped by every tool.
var DefaultExcludes = []string{"node_modules", "vendor", ".git", "*.min.js"}

// SASTExcludes are additionally skipped by source-code analysis (opengrep):
// third-party libraries copied into the repository, build output, generated
// code and non-code assets. Analysing their source finds nothing actionable
// and costs most of the scan time; their *versions* are still checked for
// known vulnerabilities by the SCA tools (Trivy, OSV-Scanner) and the SBOM.
var SASTExcludes = []string{
	// vendored / package-manager directories
	"bower_components", "jspm_packages", "wwwroot/lib", "wwwroot/libs", "lib/bower",
	"third_party", "third-party", "thirdparty",
	"Pods", "Carthage", ".yarn", ".pnpm-store",
	// build output and caches
	"bin", "obj", "dist", "build", "out", "target", ".next", ".nuxt", "coverage", "__pycache__", ".venv", "venv",
	// bundled / minified / generated files
	"*.min.css", "*.bundle.js", "*.chunk.js", "*.map", "*.Designer.cs", "*.designer.cs", "*.g.cs", "*.g.i.cs",
	"*.generated.cs", "*ModelSnapshot.cs", "*.pb.go", "*_pb2.py", "*.pb.cs", "package-lock.json", "yarn.lock",
	// assets
	"*.svg", "*.png", "*.jpg", "*.jpeg", "*.gif", "*.ico", "*.webp", "*.bmp", "*.woff", "*.woff2", "*.ttf",
	"*.eot", "*.otf", "*.mp4", "*.mp3", "*.pdf", "*.zip",
}
