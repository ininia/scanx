package service

import (
	"context"
	"strings"

	"github.com/ininia/scanx/internal/auth"
	"github.com/ininia/scanx/internal/store"
	"github.com/ininia/scanx/internal/store/db"
)

// SBOMOverview is the inventory page.
type SBOMOverview struct {
	Stats    db.InventoryStatsRow
	Counts   map[string]int64
	Open     []db.ListOpenMatchesRow
	Resolved []db.RecentlyResolvedRow
	Top      []db.TopPackagesRow
	Licenses []db.LicenseCountsRow
	Search   []db.SearchComponentsRow
	LastRun  *db.VulnmonRun
	Query    string
}

// SBOMOverview returns the inventory, open advisories and licenses.
func (s *Service) SBOMOverview(ctx context.Context, o *OrgCtx, query string) (*SBOMOverview, error) {
	if err := o.Require(auth.ActProjectRead, "read"); err != nil {
		return nil, err
	}
	if err := s.RequireModule(ctx, o, ModuleSBOM); err != nil {
		return nil, err
	}
	query = strings.TrimSpace(query)
	if len(query) > 100 {
		query = query[:100]
	}
	out := &SBOMOverview{Counts: map[string]int64{}, Query: query}
	err := s.db.Tx(ctx, o.Scope(), func(q *db.Queries) error {
		var err error
		if out.Stats, err = q.InventoryStats(ctx, o.Org.ID); err != nil {
			return err
		}
		counts, err := q.MatchCounts(ctx, o.Org.ID)
		if err != nil {
			return err
		}
		for _, c := range counts {
			out.Counts[c.Severity] = c.N
		}
		if out.Open, err = q.ListOpenMatches(ctx, o.Org.ID); err != nil {
			return err
		}
		if out.Resolved, err = q.RecentlyResolved(ctx, o.Org.ID); err != nil {
			return err
		}
		if out.Top, err = q.TopPackages(ctx, o.Org.ID); err != nil {
			return err
		}
		if out.Licenses, err = q.LicenseCounts(ctx, o.Org.ID); err != nil {
			return err
		}
		if query != "" {
			p := db.SearchComponentsParams{OrgID: o.Org.ID}
			if lic, ok := strings.CutPrefix(query, "license:"); ok {
				p.Lic = strings.TrimSpace(lic) // exact license, from the licenses tab
			} else {
				p.Q = "%" + strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(query) + "%"
			}
			if out.Search, err = q.SearchComponents(ctx, p); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, wrap("sbom overview", err)
	}
	// Run state is instance-wide (not tenant data).
	_ = s.db.Tx(ctx, store.Scope{Superadmin: true}, func(q *db.Queries) error {
		if r, err := q.LastVulnRun(ctx); err == nil {
			out.LastRun = &r
		}
		return nil
	})
	return out, nil
}

// RequestVulnCheck queues a monitor run now (one at a time, instance-wide).
func (s *Service) RequestVulnCheck(ctx context.Context, o *OrgCtx) error {
	if err := o.Require(auth.ActScanTrigger, "write"); err != nil {
		return err
	}
	if err := s.RequireModule(ctx, o, ModuleSBOM); err != nil {
		return err
	}
	return wrap("request vuln check", s.db.Tx(ctx, store.Scope{Superadmin: true}, func(q *db.Queries) error {
		return q.RequestVulnRun(ctx, newID())
	}))
}

// SBOMInventory returns every component of the org (export).
func (s *Service) SBOMInventory(ctx context.Context, o *OrgCtx) ([]db.AllInventoryRow, error) {
	if err := o.Require(auth.ActProjectRead, "read"); err != nil {
		return nil, err
	}
	if err := s.RequireModule(ctx, o, ModuleSBOM); err != nil {
		return nil, err
	}
	var out []db.AllInventoryRow
	err := s.db.Tx(ctx, o.Scope(), func(q *db.Queries) error {
		var err error
		out, err = q.AllInventory(ctx, o.Org.ID)
		return err
	})
	return out, wrap("sbom inventory", err)
}
