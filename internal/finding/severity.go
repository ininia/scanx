package finding

import (
	"regexp"
	"strings"
)

// FromSARIFLevel maps a SARIF result level (spec §7.5).
func FromSARIFLevel(level string) Severity {
	switch strings.ToLower(level) {
	case "error":
		return High
	case "warning":
		return Medium
	case "note":
		return Low
	default:
		return Info
	}
}

// FromCVSS maps a CVSS base score (spec §7.5).
func FromCVSS(score float64) Severity {
	switch {
	case score >= 9.0:
		return Critical
	case score >= 7.0:
		return High
	case score >= 4.0:
		return Medium
	case score > 0:
		return Low
	default:
		return Info
	}
}

// FromVendor maps a tool's own severity word. ok is false for unknown words
// so callers can fall back to another signal.
func FromVendor(s string) (sev Severity, ok bool) {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "CRITICAL":
		return Critical, true
	case "HIGH", "ERROR":
		return High, true
	case "MEDIUM", "MODERATE", "WARNING":
		return Medium, true
	case "LOW", "NOTE":
		return Low, true
	case "INFO", "INFORMATIONAL", "NEGLIGIBLE", "NONE":
		return Info, true
	default:
		return Info, false
	}
}

// criticalSecretRule matches secret rule ids that grant direct access to
// cloud accounts or contain private keys (spec §7.5: such secrets are critical).
var criticalSecretRule = regexp.MustCompile(`(?i)(private[-_]?key|aws|gcp|google[-_]cloud|azure|alibaba|digitalocean|github[-_](pat|app|oauth|fine)|gitlab[-_]pat|age[-_]secret)`)

// SecretSeverity applies the secret policy: critical for cloud credentials
// and private keys, high otherwise, medium if only present in git history.
func SecretSeverity(ruleID string, historyOnly bool) Severity {
	if historyOnly {
		return Medium
	}
	if criticalSecretRule.MatchString(ruleID) {
		return Critical
	}
	return High
}

var cweRe = regexp.MustCompile(`(?i)\bCWE[-_ ]?(\d{1,5})\b`)

// NormalizeCWEs extracts "CWE-<n>" identifiers from free-form strings such
// as "CWE-89: Improper Neutralization..." and returns them de-duplicated in
// first-seen order.
func NormalizeCWEs(values ...string) []string {
	var out []string
	seen := map[string]bool{}
	for _, v := range values {
		for _, m := range cweRe.FindAllStringSubmatch(v, -1) {
			id := "CWE-" + strings.TrimLeft(m[1], "0")
			if id == "CWE-" || seen[id] {
				continue
			}
			seen[id] = true
			out = append(out, id)
		}
	}
	return out
}

var owaspRe = regexp.MustCompile(`\bA\d{2}:20\d{2}\b`)

// NormalizeOWASP extracts OWASP Top 10 ids such as "A03:2021".
func NormalizeOWASP(values ...string) []string {
	var out []string
	seen := map[string]bool{}
	for _, v := range values {
		for _, m := range owaspRe.FindAllString(v, -1) {
			if !seen[m] {
				seen[m] = true
				out = append(out, m)
			}
		}
	}
	return out
}
