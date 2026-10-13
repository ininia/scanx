package ui

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/google/uuid"

	"github.com/ininia/scanx/internal/gitutil"
	"github.com/ininia/scanx/internal/service"
	"github.com/ininia/scanx/internal/store/db"
)

// DashboardView holds the overview page data.
type DashboardView struct {
	Data     *service.Dashboard
	Stats    *service.OrgStats
	Projects []db.Project
	Total    int64
}

// LastScan returns the latest scan of a project (nil if never scanned).
func (v *DashboardView) LastScan(id uuid.UUID) *db.LastScanPerProjectRow {
	if v.Stats == nil {
		return nil
	}
	if r, ok := v.Stats.LastScan[id]; ok {
		return &r
	}
	return nil
}

// Bar is one bar of a bar sparkline (viewBox 0 0 100 36).
type Bar struct{ X, Y, W, H string }

// SparkBars scales values into bars; empty series give a flat baseline.
func SparkBars(vals []int64) []Bar {
	if len(vals) == 0 {
		return nil
	}
	maxV := int64(1)
	for _, v := range vals {
		maxV = max(maxV, v)
	}
	step := 100.0 / float64(len(vals))
	w := step * 0.55
	out := make([]Bar, 0, len(vals))
	for i, v := range vals {
		h := 2 + 32*float64(v)/float64(maxV)
		out = append(out, Bar{
			X: f(float64(i)*step + (step-w)/2), Y: f(36 - h), W: f(w), H: f(h),
		})
	}
	return out
}

// SparkLine returns the line and the filled area paths (viewBox 0 0 100 36).
func SparkLine(vals []int64) (line, area string) {
	if len(vals) < 2 {
		return "M0 34 L100 34", "M0 34 L100 34 L100 36 L0 36 Z"
	}
	maxV, minV := vals[0], vals[0]
	for _, v := range vals {
		maxV, minV = max(maxV, v), min(minV, v)
	}
	span := float64(maxV - minV)
	if span == 0 {
		span = 1
	}
	var b strings.Builder
	for i, v := range vals {
		x := 100 * float64(i) / float64(len(vals)-1)
		y := 33 - 28*float64(v-minV)/span
		if i == 0 {
			fmt.Fprintf(&b, "M%s %s", f(x), f(y))
		} else {
			fmt.Fprintf(&b, " L%s %s", f(x), f(y))
		}
	}
	line = b.String()
	return line, line + " L100 36 L0 36 Z"
}

func f(v float64) string { return strconv.FormatFloat(v, 'f', 1, 64) }

// TrendText is "+%50" / "-%8" / "%0" (Turkish style) or "+50%" (English).
func (p *Page) TrendText(t service.Trend) string {
	pct := t.Percent()
	sign := ""
	if pct > 0 {
		sign = "+"
	}
	if p.Lang == "tr" {
		if pct < 0 {
			return "-%" + strconv.Itoa(-pct)
		}
		return sign + "%" + strconv.Itoa(pct)
	}
	return sign + strconv.Itoa(pct) + "%"
}

// TrendClass colours a trend: for issues "up" is bad.
func TrendClass(t service.Trend, upIsBad bool) string {
	switch t.Direction() {
	case "up":
		if upIsBad {
			return "trend bad"
		}
		return "trend good"
	case "down":
		if upIsBad {
			return "trend good"
		}
		return "trend bad"
	}
	return "trend flat"
}

// TrendIcon picks the arrow icon.
func TrendIcon(t service.Trend) string {
	switch t.Direction() {
	case "up":
		return "arrow-up"
	case "down":
		return "arrow-down"
	}
	return "arrow-right"
}

// RepoWebURL turns a clone URL into the repository's web page ("" if unknown).
func RepoWebURL(raw string) string {
	r, err := gitutil.ParseRepoURL(raw)
	if err != nil {
		return ""
	}
	return "https://" + r.Host + "/" + r.Path
}

// RepoShort is host/path for display.
func RepoShort(raw string) string {
	r, err := gitutil.ParseRepoURL(raw)
	if err != nil {
		return raw
	}
	return r.Host + "/" + r.Path
}

// ProviderName is the display name of a provider.
func ProviderName(p string) string {
	switch p {
	case "github":
		return "GitHub"
	case "gitlab":
		return "GitLab"
	case "bitbucket":
		return "Bitbucket"
	case "gitea":
		return "Gitea"
	}
	return "Git"
}

// ScanDot classifies a scan for the status dot.
func ScanDot(status string, gate *string) string {
	switch {
	case status == "completed" && gate != nil && *gate == "fail":
		return "dot bad"
	case status == "completed":
		return "dot ok"
	case status == "failed":
		return "dot bad"
	case status == "canceled":
		return "dot off"
	}
	return "dot run"
}

// ScoreBar is the class pair for a score progress bar.
func ScoreBar(score *int32) string {
	if score == nil {
		return "w0"
	}
	return ScoreClass(int(*score)) + " " + BarClass(int(*score), true)
}

func sparkStroke(vals []int64) string { l, _ := SparkLine(vals); return l }
func sparkArea(vals []int64) string   { _, a := SparkLine(vals); return a }

func projectState(p *db.Project) string {
	if p.ArchivedAt != nil {
		return "archived"
	}
	return "active"
}

func lastScan(st *service.OrgStats, p *db.Project) *db.LastScanPerProjectRow {
	if st == nil {
		return nil
	}
	if r, ok := st.LastScan[p.ID]; ok {
		return &r
	}
	return nil
}

func searchSub(p *Page, q string) string {
	if q == "" {
		return ""
	}
	return p.T("search.for", q)
}

// PolicyText translates the simple "fail on X or higher" gate policy;
// anything more complex is shown as is.
func (p *Page) PolicyText(policy string) string {
	sev, ok := strings.CutPrefix(policy, "fail on ")
	if !ok {
		return policy
	}
	sev, ok = strings.CutSuffix(sev, " or higher")
	if !ok || strings.ContainsAny(sev, " ,>") {
		return policy
	}
	text, _, _ := strings.Cut(p.T("failon."+sev), " (")
	return text
}
