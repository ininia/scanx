package ui

import (
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/google/uuid"

	"github.com/ininia/scanx/internal/store/db"
)

// IssueRow is one issue as listed on scan and project pages.
type IssueRow struct {
	ID       uuid.UUID
	Severity string
	Title    string
	RuleID   string
	File     string
	Line     int32
	Category string
	Sources  []string
	Status   string
	IsNew    bool
}

// RowsFromScan converts scan issues.
func RowsFromScan(in []db.ListScanIssuesRow) []IssueRow {
	out := make([]IssueRow, 0, len(in))
	for _, i := range in {
		out = append(out, IssueRow{
			ID: i.ID, Severity: i.Severity, Title: i.Title, RuleID: i.RuleID, File: i.File,
			Line: i.StartLine, Category: i.Category, Sources: i.Sources, Status: i.Status, IsNew: i.IsNew,
		})
	}
	return out
}

// RowsFromIssues converts project issues.
func RowsFromIssues(in []db.Issue) []IssueRow {
	out := make([]IssueRow, 0, len(in))
	for _, i := range in {
		out = append(out, IssueRow{
			ID: i.ID, Severity: i.Severity, Title: i.Title, RuleID: i.RuleID, File: i.File,
			Line: i.StartLine, Category: i.Category, Sources: i.Sources, Status: i.Status,
		})
	}
	return out
}

// Facet values in display order.
var (
	FacetSeverities = []string{"critical", "high", "medium", "low", "info"}
	FacetCategories = []string{"sast", "secret", "sca", "iac", "container", "license", "quality"}
	FacetStatuses   = []string{"open", "fixed", "false_positive", "accepted_risk", "wont_fix"}
	GroupModes      = []string{"file", "rule", "none"}
)

var sevRank = map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

// IssueFilter is parsed from the query string so filtered views are
// shareable links and survive the live refresh of the scan page.
type IssueFilter struct {
	Base   string // page path without query
	Sev    map[string]bool
	Tool   map[string]bool
	Cat    map[string]bool
	Status map[string]bool
	New    bool
	Q      string
	Group  string // file | rule | none
}

func set(vs []string) map[string]bool {
	m := map[string]bool{}
	for _, v := range vs {
		for _, p := range strings.Split(v, ",") {
			if p = strings.TrimSpace(p); p != "" && len(p) <= 64 {
				m[p] = true
			}
		}
	}
	return m
}

// ParseIssueFilter reads sev, tool, cat, status, new, q and group.
func ParseIssueFilter(base string, q url.Values) IssueFilter {
	f := IssueFilter{
		Base: base, Sev: set(q["sev"]), Tool: set(q["tool"]), Cat: set(q["cat"]), Status: set(q["status"]),
		New: q.Get("new") == "1", Q: strings.TrimSpace(q.Get("q")), Group: q.Get("group"),
	}
	if len(f.Q) > 200 {
		f.Q = f.Q[:200]
	}
	switch f.Group {
	case "file", "rule", "none":
	default:
		f.Group = "file"
	}
	return f
}

func (f IssueFilter) values() url.Values {
	v := url.Values{}
	add := func(k string, m map[string]bool) {
		keys := make([]string, 0, len(m))
		for x := range m {
			keys = append(keys, x)
		}
		sort.Strings(keys)
		if len(keys) > 0 {
			v.Set(k, strings.Join(keys, ","))
		}
	}
	add("sev", f.Sev)
	add("tool", f.Tool)
	add("cat", f.Cat)
	add("status", f.Status)
	if f.New {
		v.Set("new", "1")
	}
	if f.Q != "" {
		v.Set("q", f.Q)
	}
	if f.Group != "file" {
		v.Set("group", f.Group)
	}
	return v
}

// URL is the page URL for this filter.
func (f IssueFilter) URL() string {
	if q := f.values().Encode(); q != "" {
		return f.Base + "?" + q
	}
	return f.Base
}

func clone(m map[string]bool) map[string]bool {
	c := make(map[string]bool, len(m))
	for k, v := range m {
		c[k] = v
	}
	return c
}

// Toggle returns the URL with one facet value switched on/off.
func (f IssueFilter) Toggle(dim, val string) string {
	g := f
	g.Sev, g.Tool, g.Cat, g.Status = clone(f.Sev), clone(f.Tool), clone(f.Cat), clone(f.Status)
	var m map[string]bool
	switch dim {
	case "sev":
		m = g.Sev
	case "tool":
		m = g.Tool
	case "cat":
		m = g.Cat
	case "status":
		m = g.Status
	case "new":
		g.New = !g.New
		return g.URL()
	}
	if m[val] {
		delete(m, val)
	} else {
		m[val] = true
	}
	return g.URL()
}

// WithGroup returns the URL with another grouping.
func (f IssueFilter) WithGroup(mode string) string {
	g := f
	g.Group = mode
	return g.URL()
}

// Active reports whether a facet value is selected.
func (f IssueFilter) Active(dim, val string) bool {
	switch dim {
	case "sev":
		return f.Sev[val]
	case "tool":
		return f.Tool[val]
	case "cat":
		return f.Cat[val]
	case "status":
		return f.Status[val]
	case "new":
		return f.New
	}
	return false
}

// Any reports whether any filter is set.
func (f IssueFilter) Any() bool {
	return len(f.Sev)+len(f.Tool)+len(f.Cat)+len(f.Status) > 0 || f.New || f.Q != ""
}

// Clear returns the URL without filters (grouping kept).
func (f IssueFilter) Clear() string {
	return IssueFilter{Base: f.Base, Group: f.Group}.URL()
}

func (f IssueFilter) match(r IssueRow, skip string) bool {
	if skip != "sev" && len(f.Sev) > 0 && !f.Sev[r.Severity] {
		return false
	}
	if skip != "cat" && len(f.Cat) > 0 && !f.Cat[r.Category] {
		return false
	}
	if skip != "status" && len(f.Status) > 0 && !f.Status[r.Status] {
		return false
	}
	if skip != "tool" && len(f.Tool) > 0 {
		ok := false
		for _, s := range r.Sources {
			ok = ok || f.Tool[s]
		}
		if !ok {
			return false
		}
	}
	if skip != "new" && f.New && !r.IsNew {
		return false
	}
	if f.Q != "" {
		q := strings.ToLower(f.Q)
		if !strings.Contains(strings.ToLower(r.Title+" "+r.RuleID+" "+r.File), q) {
			return false
		}
	}
	return true
}

// Facet is one clickable filter chip.
type Facet struct {
	Dim, Value string
	Count      int
	Active     bool
	URL        string
}

// IssueGroup is a set of issues shown as one row.
type IssueGroup struct {
	Severity string // worst in the group
	Title    string
	RuleID   string
	File     string // "" when the group spans files
	Category string
	Sources  []string
	Status   string // common status, "" if mixed
	Items    []IssueRow
	Files    int
	NewCount int
}

// Lines lists the line numbers of a single-file group.
func (g IssueGroup) Lines() string {
	var ls []string
	for i, it := range g.Items {
		if i == 12 {
			ls = append(ls, "…")
			break
		}
		if it.Line > 0 {
			ls = append(ls, strconv.Itoa(int(it.Line)))
		}
	}
	return strings.Join(ls, ", ")
}

// IssueBrowser is the filtered, grouped issue list.
type IssueBrowser struct {
	Filter  IssueFilter
	Total   int
	Shown   int
	Groups  []IssueGroup
	Facets  map[string][]Facet
	Tools   []string
	Limited bool
}

const maxGroups = 500

// BuildIssueBrowser filters, groups and counts facets.
func BuildIssueBrowser(rows []IssueRow, f IssueFilter) *IssueBrowser {
	b := &IssueBrowser{Filter: f, Total: len(rows), Facets: map[string][]Facet{}}
	tools := map[string]bool{}
	for _, r := range rows {
		for _, s := range r.Sources {
			tools[s] = true
		}
	}
	for t := range tools {
		b.Tools = append(b.Tools, t)
	}
	sort.Strings(b.Tools)
	// Facet counts honour every other active filter (classic faceting).
	count := func(dim string, vals []string, get func(IssueRow) []string) {
		c := map[string]int{}
		for _, r := range rows {
			if !f.match(r, dim) {
				continue
			}
			for _, v := range get(r) {
				c[v]++
			}
		}
		for _, v := range vals {
			if c[v] == 0 && !f.Active(dim, v) {
				continue
			}
			b.Facets[dim] = append(b.Facets[dim], Facet{Dim: dim, Value: v, Count: c[v], Active: f.Active(dim, v), URL: f.Toggle(dim, v)})
		}
	}
	count("sev", FacetSeverities, func(r IssueRow) []string { return []string{r.Severity} })
	count("cat", FacetCategories, func(r IssueRow) []string { return []string{r.Category} })
	count("tool", b.Tools, func(r IssueRow) []string { return r.Sources })
	count("status", FacetStatuses, func(r IssueRow) []string { return []string{r.Status} })

	var matched []IssueRow
	newCount := 0
	for _, r := range rows {
		if r.IsNew && f.match(r, "new") {
			newCount++
		}
		if f.match(r, "") {
			matched = append(matched, r)
		}
	}
	if newCount > 0 || f.New {
		b.Facets["new"] = []Facet{{Dim: "new", Value: "1", Count: newCount, Active: f.New, URL: f.Toggle("new", "")}}
	}
	b.Shown = len(matched)

	type gk struct{ rule, file string }
	idx := map[gk]int{}
	for _, r := range matched {
		rule := r.RuleID
		if rule == "" {
			rule = r.Title
		}
		k := gk{rule: rule}
		switch f.Group {
		case "file":
			k.file = r.File
		case "none":
			k = gk{rule: r.ID.String()}
		}
		i, ok := idx[k]
		if !ok {
			i = len(b.Groups)
			idx[k] = i
			b.Groups = append(b.Groups, IssueGroup{
				Severity: r.Severity, Title: r.Title, RuleID: r.RuleID, File: r.File,
				Category: r.Category, Sources: append([]string{}, r.Sources...), Status: r.Status,
			})
		}
		g := &b.Groups[i]
		g.Items = append(g.Items, r)
		if sevRank[r.Severity] < sevRank[g.Severity] {
			g.Severity = r.Severity
		}
		if g.Status != r.Status {
			g.Status = ""
		}
		if r.IsNew {
			g.NewCount++
		}
		for _, src := range r.Sources {
			if !slices.Contains(g.Sources, src) {
				g.Sources = append(g.Sources, src)
			}
		}
	}
	for i := range b.Groups {
		g := &b.Groups[i]
		files := map[string]bool{}
		for _, it := range g.Items {
			files[it.File] = true
		}
		g.Files = len(files)
		if g.Files > 1 {
			g.File = ""
		}
		sort.SliceStable(g.Items, func(a, c int) bool {
			if g.Items[a].File != g.Items[c].File {
				return g.Items[a].File < g.Items[c].File
			}
			return g.Items[a].Line < g.Items[c].Line
		})
	}
	sort.SliceStable(b.Groups, func(i, j int) bool {
		a, c := b.Groups[i], b.Groups[j]
		if sevRank[a.Severity] != sevRank[c.Severity] {
			return sevRank[a.Severity] < sevRank[c.Severity]
		}
		if len(a.Items) != len(c.Items) {
			return len(a.Items) > len(c.Items)
		}
		return a.File < c.File
	})
	if len(b.Groups) > maxGroups {
		b.Groups, b.Limited = b.Groups[:maxGroups], true
	}
	return b
}

// KV is a hidden form field.
type KV struct{ K, V string }

// Hidden returns the current filter as hidden fields, except the search box.
func (f IssueFilter) Hidden() []KV {
	var out []KV
	for k, vs := range f.values() {
		if k == "q" {
			continue
		}
		for _, v := range vs {
			out = append(out, KV{k, v})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].K < out[j].K })
	return out
}

// FacetDims is the order facets are shown in.
var FacetDims = []string{"sev", "cat", "tool", "status", "new"}

// FacetLabel translates a facet value.
func (p *Page) FacetLabel(dim, v string) string {
	switch dim {
	case "sev":
		return p.T("sev." + v)
	case "cat":
		return p.T("cat." + v)
	case "status":
		return p.T("issue.status." + v)
	case "new":
		return p.T("issues.new")
	}
	return v
}

func joinSources(s []string) string { return strings.Join(s, ", ") }
