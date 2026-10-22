package worker

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/ininia/scanx/internal/i18n"
	"github.com/ininia/scanx/internal/notify"
	"github.com/ininia/scanx/internal/service"
	"github.com/ininia/scanx/internal/store"
	"github.com/ininia/scanx/internal/store/db"
	"github.com/ininia/scanx/internal/vulnmon"
)

// SBOM inventory and continuous vulnerability monitoring.

// updateInventory replaces a project's component list with the one of a
// complete scan. Errors are logged only: the scan itself is already saved.
func (w *Worker) updateInventory(ctx context.Context, orgID, projectID, scanID uuid.UUID, sbom []byte) {
	comps, err := vulnmon.FromCycloneDX(sbom)
	if err != nil {
		w.log.Warn("sbom inventory: parse", "scan", scanID, "err", err)
		return
	}
	fctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Minute)
	defer cancel()
	err = w.db.Tx(fctx, store.Scope{OrgID: orgID}, func(q *db.Queries) error {
		if err := q.DeleteProjectComponents(fctx, projectID); err != nil {
			return err
		}
		for _, c := range comps {
			if err := q.InsertComponent(fctx, db.InsertComponentParams{
				ID: newID(), OrgID: orgID, ProjectID: projectID, ScanID: scanID, Ecosystem: c.Ecosystem, Name: trunc(c.Name, 500),
				Version: trunc(c.Version, 200), Purl: trunc(c.PURL, 1000), Licenses: nonNil(c.Licenses),
			}); err != nil {
				return err
			}
		}
		return q.SetProjectInventoryScan(fctx, db.SetProjectInventoryScanParams{ID: projectID, InventoryScanID: &scanID})
	})
	if err != nil {
		w.log.Warn("sbom inventory: store", "scan", scanID, "err", err)
		return
	}
	w.log.Info("sbom inventory updated", "project", projectID, "components", len(comps))
}

// backfillInventory builds the inventory of projects scanned before the
// module existed (from their latest complete scan).
func (w *Worker) backfillInventory(ctx context.Context) {
	var rows []db.ProjectsWithoutInventoryRow
	_ = w.db.Tx(ctx, superadmin, func(q *db.Queries) error {
		var err error
		rows, err = q.ProjectsWithoutInventory(ctx)
		return err
	})
	for _, r := range rows {
		var gz []byte
		_ = w.db.Tx(ctx, superadmin, func(q *db.Queries) error {
			var err error
			gz, err = q.GetSBOMReport(ctx, r.ScanID)
			return err
		})
		zr, err := gzip.NewReader(bytes.NewReader(gz))
		if err != nil {
			continue
		}
		raw, err := io.ReadAll(io.LimitReader(zr, 256<<20))
		if err != nil {
			continue
		}
		w.updateInventory(ctx, r.OrgID, r.ProjectID, r.ScanID, raw)
	}
}

func (w *Worker) vulnLoop(ctx context.Context) {
	w.backfillInventory(ctx)
	tick := time.NewTicker(time.Minute)
	defer tick.Stop()
	for {
		_ = w.db.Tx(ctx, superadmin, func(q *db.Queries) error {
			if err := q.FailStaleVulnRuns(ctx); err != nil {
				return err
			}
			// Daily: queue a run when the last completed one is a day old.
			last, err := q.LastCompletedVulnRun(ctx)
			if err != nil || last.FinishedAt == nil || time.Since(*last.FinishedAt) > 24*time.Hour {
				return q.RequestVulnRun(ctx, newID())
			}
			return nil
		})
		var run *db.VulnmonRun
		_ = w.db.Tx(ctx, superadmin, func(q *db.Queries) error {
			r, err := q.ClaimVulnRun(ctx)
			if err == nil {
				run = &r
			}
			return nil
		})
		if run != nil {
			w.backfillInventory(ctx)
			w.vulnRun(ctx, run)
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

type owner struct{ org, project uuid.UUID }

func (w *Worker) vulnRun(ctx context.Context, run *db.VulnmonRun) {
	started := time.Now()
	var logb strings.Builder
	logf := func(format string, a ...any) {
		fmt.Fprintf(&logb, time.Now().Format("15:04:05")+" "+format+"\n", a...)
	}
	var comps []db.AllComponentsRow
	err := w.db.Tx(ctx, superadmin, func(q *db.Queries) error {
		var err error
		comps, err = q.AllComponents(ctx)
		return err
	})
	if err != nil {
		w.finishVulnRun(ctx, run, "failed", 0, 0, 0, err.Error())
		return
	}
	ix := vulnmon.Index{}
	owners := map[string][]owner{}
	ecos := map[string]bool{}
	for _, c := range comps {
		comp := vulnmon.Component{Ecosystem: c.Ecosystem, Name: c.Name, Version: c.Version}
		ix.Add(comp)
		ecos[c.Ecosystem] = true
		k := vulnmon.Key(c.Ecosystem, c.Name, c.Version)
		owners[k] = append(owners[k], owner{c.OrgID, c.ProjectID})
	}
	logf("inventory: %d components in %d ecosystems", len(comps), len(ecos))

	client := &http.Client{Timeout: 20 * time.Minute}
	var matches []vulnmon.Match
	advisories, complete := 0, true
	for _, eco := range vulnmon.Ecosystems {
		if !ecos[eco] {
			continue
		}
		dctx, cancel := context.WithTimeout(ctx, 20*time.Minute)
		changed, derr := vulnmon.Download(dctx, client, w.cfg.VulnDBDir, eco)
		cancel()
		switch {
		case derr != nil && vulnmon.Age(w.cfg.VulnDBDir, eco) == 0:
			logf("%s: download failed and no local copy: %v", eco, derr)
			complete = false
			continue
		case derr != nil:
			logf("%s: download failed, using the copy from %s ago: %v", eco, vulnmon.Age(w.cfg.VulnDBDir, eco).Round(time.Hour), derr)
		case changed:
			logf("%s: database updated", eco)
		}
		ms, n, merr := vulnmon.MatchZip(vulnmon.ZipPath(w.cfg.VulnDBDir, eco), ix)
		if merr != nil {
			logf("%s: read failed: %v", eco, merr)
			complete = false
			continue
		}
		advisories += n
		matches = append(matches, ms...)
		logf("%s: %d advisories, %d affected package versions", eco, n, len(ms))
	}

	newCount, total := 0, 0
	err = w.db.Tx(ctx, superadmin, func(q *db.Queries) error {
		for _, m := range matches {
			for _, o := range owners[vulnmon.Key(m.Ecosystem, m.Name, m.Version)] {
				row, err := q.UpsertVulnMatch(ctx, db.UpsertVulnMatchParams{
					ID: newID(), OrgID: o.org, ProjectID: o.project, Ecosystem: m.Ecosystem, Name: trunc(m.Name, 500),
					Version: trunc(m.Version, 200), VulnID: m.VulnID, Cve: vulnmon.CVE(m.VulnID, m.Aliases), Aliases: nonNil(m.Aliases),
					Severity: m.Severity, Summary: m.Summary, FixedVersion: m.Fixed, Published: m.Published,
				})
				if err != nil {
					return err
				}
				total++
				if row.Inserted {
					newCount++
				}
			}
		}
		// Only a run that read every ecosystem may declare matches resolved.
		if complete {
			n, err := q.ResolveStaleMatches(ctx, started)
			if err != nil {
				return err
			}
			if n > 0 {
				logf("%d matches resolved (package upgraded or removed)", n)
			}
		}
		return nil
	})
	if err != nil {
		w.finishVulnRun(ctx, run, "failed", advisories, total, newCount, logb.String()+"\n"+err.Error())
		return
	}
	logf("done: %d affected project packages, %d new", total, newCount)
	w.vulnNotify(ctx)
	w.finishVulnRun(ctx, run, "completed", advisories, total, newCount, logb.String())
}

func (w *Worker) finishVulnRun(ctx context.Context, run *db.VulnmonRun, status string, adv, total, fresh int, log string) {
	fctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
	defer cancel()
	_ = w.db.Tx(fctx, superadmin, func(q *db.Queries) error {
		return q.FinishVulnRun(fctx, db.FinishVulnRunParams{
			ID: run.ID, Status: status, Advisories: int32(adv), Matches: int32(total), NewMatches: int32(fresh), Log: trunc(log, 20000), //nolint:gosec // counts
		})
	})
	w.log.Info("vulnerability monitor run", "status", status, "advisories", adv, "matches", total, "new", fresh)
}

// vulnNotify sends one summary per organization for matches not reported
// yet (the first run of an organization summarises its backlog once).
func (w *Worker) vulnNotify(ctx context.Context) {
	var rows []db.UnnotifiedMatchesRow
	_ = w.db.Tx(ctx, superadmin, func(q *db.Queries) error {
		var err error
		rows, err = q.UnnotifiedMatches(ctx)
		return err
	})
	byOrg := map[uuid.UUID][]db.UnnotifiedMatchesRow{}
	var orgs []uuid.UUID
	for _, r := range rows {
		if _, ok := byOrg[r.OrgID]; !ok {
			orgs = append(orgs, r.OrgID)
		}
		byOrg[r.OrgID] = append(byOrg[r.OrgID], r)
	}
	lang, _ := w.instanceSettings(ctx)
	for _, orgID := range orgs {
		ms := byOrg[orgID]
		var ids []uuid.UUID
		for _, m := range ms {
			ids = append(ids, m.ID)
		}
		var org db.Organization
		var mod service.OrgModule
		var chans []db.NotificationChannel
		_ = w.db.Tx(ctx, superadmin, func(q *db.Queries) error {
			org, _ = q.GetOrgByID(ctx, orgID)
			mod = w.dbModuleOf(ctx, q, orgID, service.ModuleSBOM)
			chans, _ = q.ListNotificationChannels(ctx, orgID)
			return q.MarkMatchesNotified(ctx, ids)
		})
		if !mod.Enabled || mod.Settings.NoNotifications || w.notifier == nil {
			continue
		}
		sort.SliceStable(ms, func(i, j int) bool { return sevRank(ms[i].Severity) > sevRank(ms[j].Severity) })
		counts := map[string]int{}
		projects := map[string]bool{}
		for _, m := range ms {
			counts[m.Severity]++
			projects[m.ProjectName] = true
		}
		var top []string
		for i, m := range ms {
			if i == 5 {
				break
			}
			id := m.VulnID
			if m.Cve != "" {
				id = m.Cve
			}
			top = append(top, fmt.Sprintf("%s %s@%s (%s)", id, m.Name, m.Version, m.ProjectName))
		}
		msg := notify.Message{
			Event: notify.EventSBOMVuln, Org: org.Name, Project: i18n.T(lang, "sbom.notify.project"),
			Branch: i18n.T(lang, "sbom.notify.branch", len(projects)), Critical: counts["critical"], High: counts["high"],
			Medium: counts["medium"], Low: counts["low"], BaseURL: w.cfg.BaseURL, Lang: lang, Gate: "pass",
			Note: i18n.T(lang, "sbom.notify.note", len(ms)), Objects: strings.Join(top, " · "),
		}
		if counts["critical"]+counts["high"] > 0 {
			msg.Gate = "fail"
		}
		if w.cfg.BaseURL != "" {
			msg.URL = strings.TrimRight(w.cfg.BaseURL, "/") + "/o/" + org.Slug + "/sbom"
		}
		for _, ch := range chans {
			subscribed := false
			for _, e := range ch.Events {
				subscribed = subscribed || e == notify.EventSBOMVuln
			}
			if !subscribed {
				continue
			}
			target, err := w.box.Open(ch.TargetEnc, ch.Nonce, service.ChannelAAD(ch.ID))
			if err != nil {
				continue
			}
			sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
			if err := w.notifier.Send(sctx, ch.Kind, string(target), msg); err != nil {
				w.log.Warn("notification failed", "channel", ch.ID, "err", err)
			}
			cancel()
		}
	}
}

func sevRank(s string) int {
	return map[string]int{"critical": 4, "high": 3, "medium": 2, "low": 1}[s]
}
