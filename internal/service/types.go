package service

import (
	"encoding/json"

	"github.com/ininia/scanx/internal/report"
)

// ScanSummary is stored in scans.summary by the worker.
type ScanSummary struct {
	Counts      report.Summary         `json:"counts"`
	Gate        report.Gate            `json:"gate"`
	Warnings    []string               `json:"warnings,omitempty"`
	DurationSec float64                `json:"duration_seconds"`
	SizeMB      int                    `json:"size_mb,omitempty"`
	Languages   map[string]int         `json:"languages,omitempty"`
	FailureCode string                 `json:"failure_code,omitempty"` // failed scans: fail.<code> in the UI
	Grade       string                 `json:"grade,omitempty"`
	Categories  []report.CategoryScore `json:"categories,omitempty"`
}

// ParseSummary decodes scans.summary (zero value if empty or invalid).
func ParseSummary(raw []byte) ScanSummary {
	var s ScanSummary
	_ = json.Unmarshal(raw, &s)
	return s
}

// ConnectionResult is stored on test_connection jobs.
type ConnectionResult struct {
	OK       bool     `json:"ok"`
	Code     string   `json:"code,omitempty"`
	Message  string   `json:"message,omitempty"`
	Branches []string `json:"branches,omitempty"`
	Default  string   `json:"default_branch,omitempty"`
}

// ParseConnectionResult decodes a test_connection job result.
func ParseConnectionResult(raw []byte) ConnectionResult {
	var c ConnectionResult
	_ = json.Unmarshal(raw, &c)
	return c
}
