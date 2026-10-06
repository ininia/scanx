// Package finding defines the normalized finding model shared by every
// scanner adapter, plus severity normalization, secret masking, snippet
// extraction, fingerprinting and cross-tool de-duplication.
package finding

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Severity is an ordered severity level.
type Severity int

// Severity levels, lowest first.
const (
	Info Severity = iota
	Low
	Medium
	High
	Critical
)

var severityNames = [...]string{"info", "low", "medium", "high", "critical"}

// String returns the lower-case name.
func (s Severity) String() string {
	if s < Info || s > Critical {
		return "info"
	}
	return severityNames[s]
}

// MarshalText implements encoding.TextMarshaler.
func (s Severity) MarshalText() ([]byte, error) { return []byte(s.String()), nil }

// UnmarshalText implements encoding.TextUnmarshaler.
func (s *Severity) UnmarshalText(b []byte) error {
	v, err := ParseSeverity(string(b))
	if err != nil {
		return err
	}
	*s = v
	return nil
}

// ParseSeverity parses a scanX severity name (case-insensitive).
func ParseSeverity(s string) (Severity, error) {
	for i, n := range severityNames {
		if strings.EqualFold(s, n) {
			return Severity(i), nil
		}
	}
	return Info, fmt.Errorf("unknown severity %q", s)
}

// Category groups findings by kind of analysis.
type Category string

// Categories (spec §7.2).
const (
	CategorySAST      Category = "sast"
	CategorySecret    Category = "secret"
	CategorySCA       Category = "sca"
	CategoryIaC       Category = "iac"
	CategoryContainer Category = "container"
	CategoryLicense   Category = "license"
	CategoryQuality   Category = "quality"
	CategoryDAST      Category = "dast"
)

// PackageRef identifies a dependency for SCA findings.
type PackageRef struct {
	Name         string `json:"name"`
	Version      string `json:"version,omitempty"`
	FixedVersion string `json:"fixed_version,omitempty"`
	Ecosystem    string `json:"ecosystem,omitempty"`
	PURL         string `json:"purl,omitempty"`
}

// Finding is one normalized result reported by one tool (spec §7.3).
type Finding struct {
	Tool        string          `json:"tool"`
	RuleID      string          `json:"rule_id"`
	Category    Category        `json:"category"`
	Severity    Severity        `json:"severity"`
	Confidence  string          `json:"confidence,omitempty"`
	Title       string          `json:"title"`
	Description string          `json:"description,omitempty"`
	CWE         []string        `json:"cwe,omitempty"`
	OWASP       []string        `json:"owasp,omitempty"`
	CVE         []string        `json:"cve,omitempty"`
	Package     *PackageRef     `json:"package,omitempty"`
	File        string          `json:"file,omitempty"`
	StartLine   int             `json:"start_line,omitempty"`
	EndLine     int             `json:"end_line,omitempty"`
	Snippet     string          `json:"snippet,omitempty"`
	Fingerprint string          `json:"fingerprint"`
	Remediation string          `json:"remediation,omitempty"`
	References  []string        `json:"references,omitempty"`
	Raw         json.RawMessage `json:"raw,omitempty"`

	// matchLines holds the matched source lines (without context) used for
	// fingerprinting; never serialized.
	matchLines string
}

// SetMatchLines records the exact matched lines used for fingerprinting.
func (f *Finding) SetMatchLines(s string) { f.matchLines = s }
