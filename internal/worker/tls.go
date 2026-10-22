package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/ininia/scanx/internal/i18n"
	"github.com/ininia/scanx/internal/notify"
	"github.com/ininia/scanx/internal/service"
	"github.com/ininia/scanx/internal/store/db"
	"github.com/ininia/scanx/internal/tlscheck"
)

// Certificate and TLS monitoring: due endpoints are checked from the
// worker process (public addresses only), results kept for a year.

// expiryThresholds alert once each as a certificate approaches expiry.
var expiryThresholds = []int{30, 14, 7, 1, 0}

func (w *Worker) tlsLoop(ctx context.Context) {
	tick := time.NewTicker(time.Minute)
	defer tick.Stop()
	lastPrune := time.Time{}
	for {
		w.tlsRound(ctx)
		if time.Since(lastPrune) > 24*time.Hour {
			_ = w.db.Tx(ctx, superadmin, func(q *db.Queries) error {
				_, err := q.PruneDomainChecks(ctx)
				return err
			})
			lastPrune = time.Now()
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

func (w *Worker) tlsRound(ctx context.Context) {
	var due []db.MonitoredDomain
	_ = w.db.Tx(ctx, superadmin, func(q *db.Queries) error {
		var err error
		due, err = q.ClaimDueDomains(ctx)
		return err
	})
	for i := range due {
		if ctx.Err() != nil {
			return
		}
		w.checkDomain(ctx, &due[i])
	}
}

func (w *Worker) checkDomain(ctx context.Context, d *db.MonitoredDomain) {
	cctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	res := tlscheck.Check(cctx, d.Host, int(d.Port), tlscheck.Options{AllowPrivate: w.cfg.AllowPrivateTargets})
	cancel()

	var prev *tlscheck.Result
	var org db.Organization
	var mod service.OrgModule
	next := time.Now().Add(24 * time.Hour)
	if d.Schedule == "hourly" {
		next = time.Now().Add(time.Hour)
	}
	checkID := newID()
	raw, _ := json.Marshal(res)
	counts, _ := json.Marshal(res.Counts())
	var notAfter *time.Time
	issuer := ""
	if res.Cert != nil {
		t := res.Cert.NotAfter
		notAfter, issuer = &t, res.Cert.Issuer
	}
	// Expiry alert: the smallest threshold reached, once per certificate.
	alerted := d.AlertedDays
	expiryAlert := -1
	if res.Cert != nil {
		days := res.Cert.DaysLeft
		reached := -1
		for _, t := range expiryThresholds {
			if days <= t {
				reached = t
			}
		}
		switch {
		case reached < 0:
			alerted = nil // renewed (or far from expiry)
		case alerted == nil || int32(reached) < *alerted:
			expiryAlert = reached
			v := int32(reached)
			alerted = &v
		}
	}
	score := int32(res.Score) //nolint:gosec // 0..100
	err := w.db.Tx(ctx, superadmin, func(q *db.Queries) error {
		if last, err := q.LastDomainCheck(ctx, d.ID); err == nil {
			var p tlscheck.Result
			if json.Unmarshal(last.Result, &p) == nil {
				prev = &p
			}
		}
		if err := q.InsertDomainCheck(ctx, db.InsertDomainCheckParams{
			ID: checkID, OrgID: d.OrgID, DomainID: d.ID, Score: score, Grade: res.Grade, Counts: counts, Result: raw,
		}); err != nil {
			return err
		}
		if err := q.FinishDomainCheck(ctx, db.FinishDomainCheckParams{
			ID: d.ID, NextCheckAt: next, CheckID: &checkID, Score: &score, Grade: res.Grade, LastError: res.Error,
			CertNotAfter: notAfter, CertIssuer: issuer, AlertedDays: alerted,
		}); err != nil {
			return err
		}
		org, _ = q.GetOrgByID(ctx, d.OrgID)
		mod = w.dbModuleOf(ctx, q, d.OrgID, service.ModuleTLS)
		return nil
	})
	if err != nil {
		w.log.Error("store domain check", "domain", d.ID, "err", err)
		return
	}
	if mod.Settings.NoNotifications || !mod.Enabled {
		return
	}
	if expiryAlert >= 0 {
		w.tlsNotify(ctx, d, &org, res, notify.EventTLSExpiring, func(lang string) string {
			if res.Cert.DaysLeft < 0 {
				return i18n.T(lang, "tls.notify.expired", res.Cert.NotAfter.Format("2006-01-02"))
			}
			return i18n.T(lang, "tls.notify.expiring", res.Cert.DaysLeft, res.Cert.NotAfter.Format("2006-01-02"))
		})
	}
	if fresh := newSerious(prev, res); len(fresh) > 0 || (res.Error != "" && (prev == nil || prev.Error == "")) {
		w.tlsNotify(ctx, d, &org, res, notify.EventTLSAlert, func(lang string) string {
			if res.Error != "" {
				return i18n.T(lang, "tls.notify.unreachable", res.Error)
			}
			var titles []string
			for _, id := range fresh {
				titles = append(titles, i18n.T(lang, "tlsrule."+id+".title"))
			}
			return i18n.T(lang, "tls.notify.new_problems", strings.Join(titles, ", "))
		})
	}
}

// newSerious lists high/critical rules that the previous check did not
// have (expiry is handled by its own thresholds).
func newSerious(prev, cur *tlscheck.Result) []string {
	had := map[string]bool{}
	if prev != nil {
		for _, f := range prev.Findings {
			had[f.RuleID] = true
		}
	}
	var out []string
	for _, f := range cur.Findings {
		if (f.Severity == "high" || f.Severity == "critical") && f.RuleID != "TLS002" && !had[f.RuleID] {
			out = append(out, f.RuleID)
		}
	}
	return out
}

func (w *Worker) dbModuleOf(ctx context.Context, q *db.Queries, orgID uuid.UUID, module string) service.OrgModule {
	m := service.OrgModule{Module: module, Enabled: true}
	rows, err := q.ListOrgModules(ctx, orgID)
	if err != nil {
		return m
	}
	for _, r := range rows {
		if r.Module == module {
			m.Enabled = r.Enabled
			_ = json.Unmarshal(r.Settings, &m.Settings)
		}
	}
	return m
}

func (w *Worker) tlsNotify(ctx context.Context, d *db.MonitoredDomain, org *db.Organization, res *tlscheck.Result, event string, note func(lang string) string) {
	if w.notifier == nil {
		return
	}
	lang, _ := w.instanceSettings(ctx)
	name := d.Host
	if d.Label != "" {
		name = d.Label
	}
	c := res.Counts()
	m := notify.Message{
		Event: event, Org: org.Name, Project: name, Branch: d.Host + ":" + strconv.Itoa(int(d.Port)),
		Score: res.Score, Grade: res.Grade, Critical: c["critical"], High: c["high"], Medium: c["medium"], Low: c["low"],
		BaseURL: w.cfg.BaseURL, Lang: lang, Note: note(lang), Gate: "pass",
	}
	if c["critical"]+c["high"] > 0 || res.Error != "" {
		m.Gate = "fail"
	}
	if res.Cert != nil {
		m.Objects = i18n.T(lang, "tls.notify.objects", res.Cert.DaysLeft, res.Cert.NotAfter.Format("2006-01-02"), res.Cert.Issuer)
	}
	if w.cfg.BaseURL != "" {
		m.URL = strings.TrimRight(w.cfg.BaseURL, "/") + "/o/" + org.Slug + "/domains/" + d.ID.String()
	}
	var chans []db.NotificationChannel
	_ = w.db.Tx(ctx, superadmin, func(q *db.Queries) error {
		var err error
		chans, err = q.ListNotificationChannels(ctx, d.OrgID)
		return err
	})
	for _, ch := range chans {
		subscribed := false
		for _, e := range ch.Events {
			subscribed = subscribed || e == event
		}
		if !subscribed {
			continue
		}
		target, err := w.box.Open(ch.TargetEnc, ch.Nonce, service.ChannelAAD(ch.ID))
		if err != nil {
			continue
		}
		sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		if err := w.notifier.Send(sctx, ch.Kind, string(target), m); err != nil {
			w.log.Warn("notification failed", "channel", ch.ID, "err", fmt.Sprint(err))
		}
		cancel()
	}
}
