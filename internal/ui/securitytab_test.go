package ui

import (
	"net/url"
	"testing"

	"github.com/ininia/scanx/internal/finding"
)

func TestSecurityTab(t *testing.T) {
	rows := []IssueRow{
		{Title: "sqli", Severity: "high", Category: "sast", Security: finding.IsSecurity("sast", "high", nil, nil)},
		{Title: "complex", Severity: "low", Category: "quality", Security: finding.IsSecurity("quality", "low", nil, nil)},
		{Title: "secret", Severity: "critical", Category: "secret", Security: finding.IsSecurity("secret", "critical", nil, nil)},
		{Title: "style", Severity: "low", Category: "sast", Security: finding.IsSecurity("sast", "low", nil, nil)},
	}
	all := BuildIssueBrowser(rows, ParseIssueFilter("/x", url.Values{}))
	if all.TabAll != 4 || all.TabSec != 2 || all.Shown == 0 {
		t.Fatalf("all tab: %d/%d", all.TabAll, all.TabSec)
	}
	f := ParseIssueFilter("/x", url.Values{"tab": {"security"}})
	sec := BuildIssueBrowser(rows, f)
	n := 0
	for _, g := range sec.Groups {
		n += len(g.Items)
	}
	if n != 2 || sec.TabSec != 2 || f.WithTab(false) != "/x" || f.URL() != "/x?tab=security" {
		t.Fatalf("security tab: %d items, %s", n, f.URL())
	}
}
