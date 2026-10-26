package service

import (
	"context"
	"encoding/json"
	"path"
	"slices"
	"strings"
	"time"

	"github.com/ininia/scanx/internal/auth"
	"github.com/ininia/scanx/internal/forecast"
	"github.com/ininia/scanx/internal/scanner"
	"github.com/ininia/scanx/internal/scanner/prune"
	"github.com/ininia/scanx/internal/store/db"
)

// ScanScope is what a project's repository scans cover (projects.settings).
// The zero value is the recommended default.
type ScanScope struct {
	// File groups that are scanned anyway (all tools see them unless
	// switched off). Media and fonts are off by default.
	SkipDocs     bool `json:"skip_docs,omitempty"`
	SkipArchives bool `json:"skip_archives,omitempty"`
	ScanMedia    bool `json:"scan_media,omitempty"`
	ScanFonts    bool `json:"scan_fonts,omitempty"`
	// Code analysis: minified files and third-party bundles are left out
	// unless kept; MaxFileMB 0 = default, -1 = no limit.
	KeepMinified bool `json:"keep_minified,omitempty"`
	KeepBundles  bool `json:"keep_bundles,omitempty"`
	MaxFileMB    int  `json:"max_file_mb,omitempty"`
	// Exclude are extra path patterns, Disabled scanner IDs switched off.
	Exclude  []string `json:"exclude,omitempty"`
	Disabled []string `json:"disabled,omitempty"`
}

// DefaultMaxFileMB is the per-file analysis limit when a project sets none.
const DefaultMaxFileMB = 2

// File groups that can be left out of every scanner.
var (
	docPatterns     = []string{"*.pdf", "*.doc", "*.docx", "*.xls", "*.xlsx", "*.ppt", "*.pptx", "*.odt", "*.ods", "*.odp", "*.rtf"}
	archivePatterns = []string{"*.zip", "*.rar", "*.7z", "*.tar", "*.gz", "*.tgz", "*.bz2", "*.xz"}
	mediaPatterns   = []string{"*.png", "*.jpg", "*.jpeg", "*.gif", "*.bmp", "*.ico", "*.webp", "*.tif", "*.tiff", "*.psd", "*.svg", "*.mp4", "*.webm", "*.mov", "*.avi", "*.mp3", "*.wav", "*.ogg"}
	fontPatterns    = []string{"*.ttf", "*.otf", "*.woff", "*.woff2", "*.eot"}
)

// Patterns are the exclude patterns passed to every scanner.
func (s ScanScope) Patterns() []string {
	var out []string
	if s.SkipDocs {
		out = append(out, docPatterns...)
	}
	if s.SkipArchives {
		out = append(out, archivePatterns...)
	}
	if !s.ScanMedia {
		out = append(out, mediaPatterns...)
	}
	if !s.ScanFonts {
		out = append(out, fontPatterns...)
	}
	return append(out, s.Exclude...)
}

// FileLimitMB is the per-file analysis limit (0 = none).
func (s ScanScope) FileLimitMB() int {
	switch {
	case s.MaxFileMB < 0:
		return 0
	case s.MaxFileMB == 0:
		return DefaultMaxFileMB
	}
	return s.MaxFileMB
}

// ParseScanScope reads projects.settings (unknown or broken = default).
func ParseScanScope(raw []byte) ScanScope {
	var s ScanScope
	_ = json.Unmarshal(raw, &s)
	return s
}

// ScannerInfo is a scanner a project can switch off.
type ScannerInfo struct {
	ID       string
	Name     string
	Category string
}

// Scanners lists every registered scanner (for the settings page).
func Scanners() []ScannerInfo {
	var out []ScannerInfo
	for _, sc := range scanner.All() {
		out = append(out, ScannerInfo{ID: sc.ID(), Name: sc.Name(), Category: string(sc.Category())})
	}
	return out
}

// cleanPattern validates one exclude pattern: a repository-relative path
// or glob, no absolute paths or parent references.
func cleanPattern(p string) (string, bool) {
	p = strings.Trim(strings.TrimSpace(strings.ReplaceAll(p, `\`, "/")), "/")
	p = strings.TrimPrefix(p, "./")
	if p == "" || len(p) > 200 || strings.Contains(p, "..") || strings.ContainsAny(p, "\x00\n\r") {
		return "", false
	}
	if _, err := path.Match(p, ""); err != nil {
		return "", false
	}
	return p, true
}

// UpdateScanScope saves what the project's scans cover.
func (s *Service) UpdateScanScope(ctx context.Context, o *OrgCtx, slug string, in ScanScope, m Meta) error {
	p, err := s.GetProject(ctx, o, slug)
	if err != nil {
		return err
	}
	if err := o.Require(auth.ActProjectWrite, "write"); err != nil {
		return err
	}
	var ex []string
	for _, raw := range in.Exclude {
		if raw = strings.TrimSpace(raw); raw == "" {
			continue
		}
		c, ok := cleanPattern(raw)
		if !ok {
			return invalid("exclude", "invalid")
		}
		if !slices.Contains(ex, c) {
			ex = append(ex, c)
		}
	}
	if len(ex) > 100 {
		return invalid("exclude", "invalid")
	}
	in.Exclude = ex
	known := map[string]bool{}
	for _, sc := range scanner.All() {
		known[sc.ID()] = true
	}
	var dis []string
	for _, id := range in.Disabled {
		if known[id] && !slices.Contains(dis, id) {
			dis = append(dis, id)
		}
	}
	in.Disabled = dis
	if in.MaxFileMB < -1 || in.MaxFileMB > 100 {
		return invalid("max_file_mb", "invalid")
	}
	raw, err := json.Marshal(in)
	if err != nil {
		return err
	}
	return wrap("scan scope", s.db.Tx(ctx, o.Scope(), func(q *db.Queries) error {
		if err := q.UpdateProjectSettings(ctx, db.UpdateProjectSettingsParams{OrgID: o.Org.ID, ID: p.ID, Settings: raw}); err != nil {
			return err
		}
		return audit(ctx, q, &o.Org.ID, &o.P.UserID, "project.scan_scope_updated", "project", p.ID.String(), m,
			map[string]any{"exclude": len(ex), "disabled": dis})
	}))
}

// LastScanStats is what the worker keeps about a project's latest scan
// (projects.scan_stats): the analysis tree, the forecast and the outcome.
type LastScanStats = forecast.Stats

// ScanForecast is the expected duration of the project's next full scan.
type ScanForecast struct {
	Known    bool          // there was a scan to learn from
	Estimate time.Duration // corrected by the last complete scan
	Limit    time.Duration // the scan's time limit
	Last     *LastScanStats
	// Suggestions are the largest analysed folders (exclusion candidates)
	// when the forecast does not fit the limit.
	Suggestions []prune.Dir
}

// TooLong reports whether the scan is expected to exceed its limit.
func (f *ScanForecast) TooLong() bool { return f.Known && f.Estimate > f.Limit }

// ScanTimeLimit is the time a full scan of p may take (worker rule: the
// instance limit, but at least the code-analysis limit plus 15 minutes).
func (s *Service) ScanTimeLimit(p *db.Project) time.Duration {
	sast := time.Duration(p.SastTimeoutMinutes) * time.Minute
	if sast <= 0 {
		sast = scanner.DefaultSASTTimeout
	}
	return max(s.cfg.ScanTimeout, sast+15*time.Minute)
}

// ForecastScan predicts the next full scan from the last one.
func (s *Service) ForecastScan(p *db.Project) *ScanForecast {
	f := &ScanForecast{Limit: s.ScanTimeLimit(p)}
	var last LastScanStats
	if json.Unmarshal(p.ScanStats, &last) != nil || last.Analysis == nil || last.At.IsZero() {
		return f
	}
	f.Known, f.Last = true, &last
	scope := ParseScanScope(p.Settings)
	tools := slices.DeleteFunc(append([]string(nil), last.Tools...), func(id string) bool { return slices.Contains(scope.Disabled, id) })
	est := forecast.Estimate(forecast.Input{Tools: tools, AnalysisBytes: last.Analysis.Bytes, FullBytes: last.FullBytes, Parallelism: last.Parallelism})
	if last.Complete && last.ActualS > 0 {
		est = forecast.Correct(est, time.Duration(last.EstimateS)*time.Second, time.Duration(last.ActualS)*time.Second)
	}
	f.Estimate = est
	if f.TooLong() {
		for _, d := range last.Analysis.Largest {
			if d.Path != "/" && d.Bytes >= 1<<20 && !slices.Contains(scope.Exclude, d.Path) {
				f.Suggestions = append(f.Suggestions, d)
			}
		}
	}
	return f
}

// AddScanExclude appends one path to the project's exclude list (the
// "exclude" buttons next to the forecast).
func (s *Service) AddScanExclude(ctx context.Context, o *OrgCtx, slug, pattern string, m Meta) error {
	p, err := s.GetProject(ctx, o, slug)
	if err != nil {
		return err
	}
	scope := ParseScanScope(p.Settings)
	scope.Exclude = append(scope.Exclude, pattern)
	return s.UpdateScanScope(ctx, o, slug, scope, m)
}
