package ui

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/ininia/scanx/internal/finding"
	"github.com/ininia/scanx/internal/gitutil"
	"github.com/ininia/scanx/internal/service"
	"github.com/ininia/scanx/internal/store/db"
)

// ProjectView is the project page.
type ProjectView struct {
	Project       *db.Project
	Repo          *gitutil.RepoURL
	DeployKey     *service.DeployKey
	WebhookURL    string
	WebhookSecret string // only for users who may change the project
	Scans         []db.Scan
	Open          map[string]int
	TestJob       *db.Job
	HostTrusted   bool
}

// SSH reports whether the repository is cloned over SSH (deploy key needed).
func (v *ProjectView) SSH() bool { return v.Repo != nil && v.Repo.Scheme == "ssh" }

// ProviderSettingsURL links to the provider page where keys/hooks are added.
func (v *ProjectView) ProviderSettingsURL(what string) string {
	if v.Repo == nil {
		return ""
	}
	base := "https://" + v.Repo.Host + "/" + v.Repo.Path
	switch v.Project.Provider {
	case "github":
		if what == "keys" {
			return base + "/settings/keys/new"
		}
		return base + "/settings/hooks/new"
	case "gitlab":
		if what == "keys" {
			return base + "/-/settings/repository#js-deploy-keys-settings"
		}
		return base + "/-/hooks"
	case "gitea":
		if what == "keys" {
			return base + "/settings/keys"
		}
		return base + "/settings/hooks"
	case "bitbucket":
		if what == "keys" {
			return "https://bitbucket.org/" + v.Repo.Path + "/admin/access-keys/"
		}
		return "https://bitbucket.org/" + v.Repo.Path + "/admin/webhooks"
	}
	return ""
}

// ScanPage is the scan detail page.
type ScanPage struct {
	View    *service.ScanView
	Summary service.ScanSummary
	Browser *IssueBrowser
}

// SevSummary reads a severity count from the scan summary.
func SevSummary(s service.ScanSummary, sev string) int {
	switch sev {
	case "critical":
		return s.Counts.Critical
	case "high":
		return s.Counts.High
	case "medium":
		return s.Counts.Medium
	case "low":
		return s.Counts.Low
	}
	return s.Counts.Info
}

// ScoreClass colours a score bar.
func ScoreClass(score int) string {
	switch {
	case score >= 75:
		return "good"
	case score >= 40:
		return "mid"
	}
	return "bad"
}

// BarClass sizes a score bar in 5% steps (w0…w100 in app.css; the CSP
// forbids inline styles).
func BarClass(score int, analysed bool) string {
	if !analysed {
		return "w0"
	}
	return "w" + strconv.Itoa((min(max(score, 0), 100)+2)/5*5)
}

// IssuePage is the issue detail page.
type IssuePage struct {
	View   *service.IssueView
	Detail finding.Issue
}

// ParseIssueDetail decodes issues.detail.
func ParseIssueDetail(raw []byte) finding.Issue {
	var is finding.Issue
	_ = json.Unmarshal(raw, &is)
	return is
}

// ConnTest is the connection-test result fragment.
type ConnTest struct {
	Job     *db.Job
	Result  service.ConnectionResult
	PollURL string
}

// Done reports whether the test finished.
func (c *ConnTest) Done() bool { return c.Job.Status == "done" || c.Job.Status == "failed" }

// NotificationsView is the notifications page.
type NotificationsView struct {
	Channels       []service.Channel
	SMTPConfigured bool
	TestError      string
}

// ShortSHA abbreviates a commit.
func ShortSHA(s string) string {
	if len(s) > 10 {
		return s[:10]
	}
	if s == "" {
		return "—"
	}
	return s
}

// Ago formats a time relative to now ("3 min").
func Ago(t time.Time) string {
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return strconv.Itoa(int(d.Seconds())) + "s"
	case d < time.Hour:
		return strconv.Itoa(int(d.Minutes())) + "m"
	case d < 48*time.Hour:
		return strconv.Itoa(int(d.Hours())) + "h"
	default:
		return Date(t)
	}
}

// Duration formats the run time of a scan.
func Duration(start, end *time.Time) string {
	if start == nil {
		return "—"
	}
	e := time.Now()
	if end != nil {
		e = *end
	}
	d := e.Sub(*start).Round(time.Second)
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	return fmt.Sprintf("%dm %02ds", int(d.Minutes()), int(d.Seconds())%60)
}

// Ms formats milliseconds as seconds.
func Ms(ms int64) string { return fmt.Sprintf("%.1fs", float64(ms)/1000) }

// Itoa32 formats an int32.
func Itoa32(n int32) string { return strconv.Itoa(int(n)) }

// ScoreText formats a nullable score.
func ScoreText(s *int32) string {
	if s == nil {
		return "—"
	}
	return strconv.Itoa(int(*s))
}

// Gate returns the gate result or "".
func Gate(g *string) string {
	if g == nil {
		return ""
	}
	return *g
}

// Loc formats file:line.
func Loc(file string, line int32) string {
	if file == "" {
		return "—"
	}
	if line > 0 {
		return file + ":" + strconv.Itoa(int(line))
	}
	return file
}

// SafeRef reports whether a reference link may be rendered as a link.
func SafeRef(u string) bool {
	return strings.HasPrefix(u, "https://") || strings.HasPrefix(u, "http://")
}

// ScanSteps are the visible phases of a scan.
var ScanSteps = []string{"queued", "cloning", "scanning", "reporting", "completed"}

// StepState returns done | current | todo for a step given the scan status.
func StepState(status, step string) string {
	idx := func(s string) int {
		for i, x := range ScanSteps {
			if x == s {
				return i
			}
		}
		return -1
	}
	cur, st := idx(status), idx(step)
	switch {
	case status == "completed" || (cur >= 0 && st < cur):
		return "done"
	case st == cur:
		return "current"
	default:
		return "todo"
	}
}

// SevCount reads a severity count from a map.
func SevCount(m map[string]int, sev string) string { return strconv.Itoa(m[sev]) }
