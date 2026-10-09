package ui

import (
	"net/url"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func row(sev, rule, file string, line int32, tool string, isNew bool) IssueRow {
	return IssueRow{
		ID: uuid.New(), Severity: sev, Title: rule, RuleID: rule, File: file, Line: line,
		Category: "secret", Sources: []string{tool}, Status: "open", IsNew: isNew,
	}
}

func TestIssueBrowserGroupsAndFilters(t *testing.T) {
	rows := []IssueRow{
		row("high", "generic-api-key", "a.cs", 10, "gitleaks", true),
		row("high", "generic-api-key", "a.cs", 20, "gitleaks", false),
		row("high", "generic-api-key", "b.cs", 5, "gitleaks", false),
		row("critical", "private-key", "k.key", 1, "trivy", false),
		row("medium", "sqli", "c.cs", 3, "opengrep", false),
	}
	b := BuildIssueBrowser(rows, ParseIssueFilter("/s", url.Values{}))
	if len(b.Groups) != 4 || b.Groups[0].RuleID != "private-key" || len(b.Groups[1].Items) != 2 || b.Groups[1].Lines() != "10, 20" {
		t.Fatalf("file grouping: %+v", b.Groups)
	}
	b = BuildIssueBrowser(rows, ParseIssueFilter("/s", url.Values{"group": {"rule"}}))
	if len(b.Groups) != 3 || b.Groups[1].Files != 2 || b.Groups[1].File != "" {
		t.Fatalf("rule grouping: %+v", b.Groups)
	}
	f := ParseIssueFilter("/s", url.Values{"sev": {"high,critical"}, "tool": {"gitleaks"}})
	b = BuildIssueBrowser(rows, f)
	if b.Shown != 3 {
		t.Fatalf("filter: shown %d", b.Shown)
	}
	// Facet counts ignore their own dimension: the severity chips still
	// count every severity among gitleaks findings.
	for _, fc := range b.Facets["sev"] {
		if fc.Value == "high" && (fc.Count != 3 || !fc.Active) {
			t.Fatalf("sev facet %+v", fc)
		}
	}
	if u := f.Toggle("sev", "high"); !strings.Contains(u, "sev=critical") || strings.Contains(u, "high") {
		t.Fatalf("toggle %s", u)
	}
	if b := BuildIssueBrowser(rows, ParseIssueFilter("/s", url.Values{"new": {"1"}})); b.Shown != 1 {
		t.Fatal("new filter")
	}
	if b := BuildIssueBrowser(rows, ParseIssueFilter("/s", url.Values{"q": {"C.CS"}})); b.Shown != 1 {
		t.Fatal("search")
	}
}
