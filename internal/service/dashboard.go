package service

import (
	"context"
	"strings"

	"github.com/ininia/scanx/internal/auth"
	"github.com/ininia/scanx/internal/store/db"
)

// Trend compares a value with the same value one period earlier.
type Trend struct {
	Now, Before int64
}

// Percent is the relative change (0 when there was nothing before).
func (t Trend) Percent() int {
	if t.Before == 0 {
		if t.Now == 0 {
			return 0
		}
		return 100
	}
	return int((t.Now - t.Before) * 100 / t.Before)
}

// Direction is "up", "down" or "flat".
func (t Trend) Direction() string {
	switch {
	case t.Now > t.Before:
		return "up"
	case t.Now < t.Before:
		return "down"
	}
	return "flat"
}

// Dashboard holds everything the overview page shows.
type Dashboard struct {
	Projects, Members, Critical, High Trend
	// 14 daily values for the sparklines.
	ScansPerDay, MembersPerDay, NewCritical, NewHigh []int64
}

// DashboardData computes trends and sparklines from the org's data.
func (s *Service) DashboardData(ctx context.Context, o *OrgCtx) (*Dashboard, error) {
	if err := o.Require(auth.ActProjectRead, "read"); err != nil {
		return nil, err
	}
	d := &Dashboard{}
	err := s.db.Tx(ctx, o.Scope(), func(q *db.Queries) error {
		c, err := q.DashboardCounts(ctx, o.Org.ID)
		if err != nil {
			return err
		}
		d.Projects = Trend{c.ProjectsNow, c.ProjectsBefore}
		d.Members = Trend{c.MembersNow, c.MembersBefore}
		d.Critical = Trend{c.CriticalNow, c.CriticalBefore}
		d.High = Trend{c.HighNow, c.HighBefore}
		days, err := q.DashboardDaily(ctx, o.Org.ID)
		if err != nil {
			return err
		}
		for _, r := range days {
			d.ScansPerDay = append(d.ScansPerDay, r.Scans)
			d.MembersPerDay = append(d.MembersPerDay, r.Members)
			d.NewCritical = append(d.NewCritical, r.NewCritical)
			d.NewHigh = append(d.NewHigh, r.NewHigh)
		}
		return nil
	})
	return d, wrap("dashboard", err)
}

// ProblemScans lists failed scans and failed gates of the last week.
func (s *Service) ProblemScans(ctx context.Context, o *OrgCtx) ([]db.RecentProblemScansRow, error) {
	if err := o.Require(auth.ActProjectRead, "read"); err != nil {
		return nil, err
	}
	var out []db.RecentProblemScansRow
	err := s.db.Tx(ctx, o.Scope(), func(q *db.Queries) error {
		var err error
		out, err = q.RecentProblemScans(ctx, o.Org.ID)
		return err
	})
	return out, wrap("problem scans", err)
}

// SearchResult is what the global search finds.
type SearchResult struct {
	Query    string
	Projects []db.Project
	Issues   []db.SearchIssuesRow
	Scans    []db.SearchScansRow
}

// Search looks for projects, issues and scans of the org.
func (s *Service) Search(ctx context.Context, o *OrgCtx, query string) (*SearchResult, error) {
	if err := o.Require(auth.ActProjectRead, "read"); err != nil {
		return nil, err
	}
	query = strings.TrimSpace(query)
	if len([]rune(query)) > 100 {
		query = string([]rune(query)[:100])
	}
	res := &SearchResult{Query: query}
	if len([]rune(query)) < 2 {
		return res, nil
	}
	esc := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(query)
	like := "%" + esc + "%"
	err := s.db.Tx(ctx, o.Scope(), func(q *db.Queries) error {
		var err error
		if res.Projects, err = q.SearchProjects(ctx, db.SearchProjectsParams{OrgID: o.Org.ID, Q: like}); err != nil {
			return err
		}
		if res.Issues, err = q.SearchIssues(ctx, db.SearchIssuesParams{OrgID: o.Org.ID, Q: like}); err != nil {
			return err
		}
		res.Scans, err = q.SearchScans(ctx, db.SearchScansParams{OrgID: o.Org.ID, Prefix: strings.ToLower(esc) + "%", Q: like})
		return err
	})
	return res, wrap("search", err)
}
