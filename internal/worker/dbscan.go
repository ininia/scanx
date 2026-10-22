package worker

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/ininia/scanx/internal/dbscan"
	"github.com/ininia/scanx/internal/dbscan/inspect"
	"github.com/ininia/scanx/internal/notify"
	"github.com/ininia/scanx/internal/sandbox"
	"github.com/ininia/scanx/internal/service"
	"github.com/ininia/scanx/internal/store"
	"github.com/ininia/scanx/internal/store/db"
)

// Database module: read-only checks, structure scans and schedules. One
// loop, independent of the repository scan workers.

const (
	dbVerifyTimeout  = 3 * time.Minute
	dbInspectTimeout = 15 * time.Minute
)

func (w *Worker) dbLoop(ctx context.Context) {
	tick := time.NewTicker(w.cfg.PollInterval)
	defer tick.Stop()
	lastSchedule, lastHousekeeping := time.Time{}, time.Now()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		if time.Since(lastSchedule) >= time.Minute {
			w.dbSchedule(ctx)
			lastSchedule = time.Now()
		}
		if time.Since(lastHousekeeping) >= 5*time.Minute {
			_ = w.db.Tx(ctx, superadmin, func(q *db.Queries) error {
				_, err := q.FailStaleDBScans(ctx)
				return err
			})
			lastHousekeeping = time.Now()
		}
		for ctx.Err() == nil {
			if c := w.claimDBVerify(ctx); c != nil {
				w.dbVerify(ctx, c)
				continue
			}
			if sc := w.claimDBScan(ctx); sc != nil {
				w.dbScan(ctx, sc)
				continue
			}
			break
		}
	}
}

func (w *Worker) claimDBVerify(ctx context.Context) *db.DbConnection {
	var c *db.DbConnection
	_ = w.db.Tx(ctx, superadmin, func(q *db.Queries) error {
		until := time.Now().Add(dbVerifyTimeout + time.Minute)
		r, err := q.ClaimDBVerify(ctx, db.ClaimDBVerifyParams{Worker: w.id, LockedUntil: &until})
		if err == nil {
			c = &r
		}
		return nil
	})
	return c
}

func (w *Worker) claimDBScan(ctx context.Context) *db.DbScan {
	var s *db.DbScan
	_ = w.db.Tx(ctx, superadmin, func(q *db.Queries) error {
		until := time.Now().Add(lockFor)
		r, err := q.ClaimDBScan(ctx, db.ClaimDBScanParams{Worker: w.id, LockedUntil: &until})
		if err == nil {
			s = &r
		}
		return nil
	})
	return s
}

// dbSchedule queues the scans whose schedule is due.
func (w *Worker) dbSchedule(ctx context.Context) {
	loc := w.instanceLocation(ctx)
	_ = w.db.Tx(ctx, superadmin, func(q *db.Queries) error {
		due, err := q.DueDBSchedules(ctx)
		if err != nil {
			return err
		}
		for _, c := range due {
			next := dbscan.NextRun(c.Schedule, int(c.ScheduleHour), int(c.ScheduleWeekday), time.Now(), loc)
			if err := q.SetDBNextRun(ctx, db.SetDBNextRunParams{ID: c.ID, NextRunAt: next}); err != nil {
				return err
			}
			if mod := w.dbModule(ctx, q, c.OrgID); !mod.Enabled || mod.Settings.NoSchedule {
				continue
			}
			if _, err := q.CreateDBScan(ctx, db.CreateDBScanParams{ID: newID(), OrgID: c.OrgID, ConnectionID: c.ID, Trigger: "schedule"}); err != nil && !store.IsNoRows(err) {
				return err
			}
			w.log.Info("scheduled database scan queued", "connection", c.ID, "next", next)
		}
		return nil
	})
}

func (w *Worker) dbModule(ctx context.Context, q *db.Queries, orgID uuid.UUID) service.OrgModule {
	m := service.OrgModule{Module: service.ModuleDB, Enabled: true}
	rows, err := q.ListOrgModules(ctx, orgID)
	if err != nil {
		return m
	}
	for _, r := range rows {
		if r.Module == service.ModuleDB {
			m.Enabled = r.Enabled
			_ = json.Unmarshal(r.Settings, &m.Settings)
		}
	}
	return m
}

func (w *Worker) instanceSettings(ctx context.Context) (lang, tz string) {
	_ = w.db.Tx(ctx, superadmin, func(q *db.Queries) error {
		v, err := q.GetSetting(ctx, "instance")
		if err != nil {
			return nil
		}
		var inst struct {
			DefaultLocale string `json:"default_locale"`
			Timezone      string `json:"timezone"`
		}
		if json.Unmarshal(v, &inst) == nil {
			lang, tz = inst.DefaultLocale, inst.Timezone
		}
		return nil
	})
	return lang, tz
}

func (w *Worker) instanceLocation(ctx context.Context) *time.Location {
	if _, tz := w.instanceSettings(ctx); tz != "" {
		if loc, err := time.LoadLocation(tz); err == nil {
			return loc
		}
	}
	return time.UTC
}

// runInspect starts the inspector container for one connection.
func (w *Worker) runInspect(ctx context.Context, c *db.DbConnection, mode, label string) (*inspect.Result, error) {
	if c.PasswordEnc == nil {
		return &inspect.Result{Code: "request", Error: "No stored password: enter the read-only account's password again."}, nil
	}
	pw, err := w.box.Open(c.PasswordEnc, c.PasswordNonce, service.DBConnAAD(c.ID))
	if err != nil {
		return nil, fmt.Errorf("decrypt database password: %w", err)
	}
	timeout := dbVerifyTimeout
	if mode == inspect.ModeInspect {
		timeout = dbInspectTimeout
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	spec := sandbox.ContainerSpec{
		Image: w.cfg.DBImage, Cmd: []string{"db-inspect"}, User: "65532:65532",
		Env: []string{
			"SCANX_DB_MODE=" + mode, "SCANX_DB_ENGINE=" + c.Engine, "SCANX_DB_HOST=" + c.Host,
			"SCANX_DB_PORT=" + strconv.Itoa(int(c.Port)), "SCANX_DB_NAME=" + c.DatabaseName, "SCANX_DB_USER=" + c.Username,
			"SCANX_DB_PASSWORD_B64=" + base64.StdEncoding.EncodeToString(pw), "SCANX_DB_TLS=" + c.TlsMode,
		},
		Labels:  map[string]string{"scanx.scan": label, "scanx.org": c.OrgID.String(), "scanx.step": "db-" + mode},
		Network: w.cfg.EgressNetwork, Tmpfs: map[string]string{"/tmp": "rw,noexec,nosuid,size=16m"},
		MemoryBytes: 512 << 20, NanoCPUs: 1e9, PidsLimit: 64, Runtime: w.cfg.Runtime,
	}
	id, err := w.docker.CreateContainer(cctx, spec)
	if err != nil {
		return nil, err
	}
	defer func() {
		rctx, rcancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer rcancel()
		_ = w.docker.RemoveContainer(rctx, id)
	}()
	if err := w.docker.StartContainer(cctx, id); err != nil {
		return nil, err
	}
	if _, err := w.docker.Wait(cctx, id, time.Second); err != nil {
		kctx, kcancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		_ = w.docker.KillContainer(kctx, id)
		kcancel()
		if cctx.Err() != nil {
			return &inspect.Result{Code: "connect", Error: fmt.Sprintf("The database did not answer within %s.", timeout)}, nil
		}
		return nil, err
	}
	lctx, lcancel := context.WithTimeout(context.WithoutCancel(ctx), time.Minute)
	defer lcancel()
	stdout, stderr, err := w.docker.Logs(lctx, id, 64<<20)
	if err != nil {
		return nil, err
	}
	res, err := inspect.Decode(stdout)
	if err != nil {
		return nil, fmt.Errorf("inspector output: %w (%s)", err, trunc(strings.TrimSpace(string(stderr)), 300))
	}
	return res, nil
}

func verifyJSON(res *inspect.Result) json.RawMessage {
	v := service.VerifyResult{Code: res.Code, Error: res.Error, ReadOnly: res.ReadOnly}
	if res.Snapshot != nil {
		v.Server = res.Snapshot.ServerVersion
	}
	b, _ := json.Marshal(v)
	return b
}

// dbVerify checks a new or edited connection right away. A write-capable
// account is rejected and its password deleted; a successful check queues
// the first scan.
func (w *Worker) dbVerify(ctx context.Context, c *db.DbConnection) {
	log := w.log.With("db_connection", c.ID)
	res, err := w.runInspect(ctx, c, inspect.ModeVerify, "verify-"+c.ID.String())
	if err != nil {
		log.Warn("database verify failed", "err", err)
		res = &inspect.Result{Code: "internal", Error: "The check could not run: " + trunc(err.Error(), 300)}
	}
	status, wipe := "ready", false
	switch {
	case res.OK:
	case res.Code == "not_readonly":
		status, wipe = "rejected", true
	default:
		status = "error"
	}
	fctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
	defer cancel()
	_ = w.db.Tx(fctx, superadmin, func(q *db.Queries) error {
		if err := q.FinishDBVerify(fctx, db.FinishDBVerifyParams{ID: c.ID, Status: status, VerifyResult: verifyJSON(res), Wipe: wipe}); err != nil {
			return err
		}
		if status != "ready" {
			return nil
		}
		scans, err := q.ListDBScans(fctx, db.ListDBScansParams{OrgID: c.OrgID, ConnectionID: c.ID, Limit: 1})
		if err == nil && len(scans) == 0 {
			_, err = q.CreateDBScan(fctx, db.CreateDBScanParams{ID: newID(), OrgID: c.OrgID, ConnectionID: c.ID, Trigger: "manual", TriggeredBy: c.CreatedBy})
			if err != nil && !store.IsNoRows(err) {
				return err
			}
		}
		return nil
	})
	log.Info("database account checked", "status", status, "code", res.Code)
}

func (w *Worker) dbScan(ctx context.Context, sc *db.DbScan) {
	log := w.log.With("db_scan", sc.ID)
	hbCtx, stopHB := context.WithCancel(ctx)
	defer stopHB()
	go func() {
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-hbCtx.Done():
				return
			case <-t.C:
				until := time.Now().Add(lockFor)
				_ = w.db.Tx(hbCtx, superadmin, func(q *db.Queries) error {
					return q.ExtendDBScanLock(hbCtx, db.ExtendDBScanLockParams{ID: sc.ID, LockedUntil: &until})
				})
			}
		}
	}()

	var c db.DbConnection
	var prof dbscan.Profile
	err := w.db.Tx(ctx, superadmin, func(q *db.Queries) error {
		var err error
		if c, err = q.GetDBConnection(ctx, db.GetDBConnectionParams{OrgID: sc.OrgID, ID: sc.ConnectionID}); err != nil {
			return err
		}
		if row, err := q.GetDBProfile(ctx, sc.OrgID); err == nil {
			_ = json.Unmarshal(row.Profile, &prof)
		}
		return nil
	})
	if err != nil {
		w.finishDBScan(ctx, sc, &c, nil, nil, "The connection no longer exists.", "")
		return
	}
	if c.Status != "ready" {
		w.finishDBScan(ctx, sc, &c, nil, nil, "The connection's account has not passed the read-only check.", "")
		return
	}
	var logb strings.Builder
	fmt.Fprintf(&logb, "%s connecting to %s %s:%d/%s as %s (read-only check first)\n",
		time.Now().Format("15:04:05"), engineName(c.Engine), c.Host, c.Port, c.DatabaseName, c.Username)
	_ = w.db.Tx(ctx, superadmin, func(q *db.Queries) error {
		return q.SetDBScanLog(ctx, db.SetDBScanLogParams{ID: sc.ID, Log: logb.String()})
	})

	res, err := w.runInspect(ctx, &c, inspect.ModeInspect, sc.ID.String())
	if err != nil {
		log.Warn("database inspect failed", "err", err)
		w.finishDBScan(ctx, sc, &c, nil, nil, "The inspection could not run: "+trunc(err.Error(), 300), logb.String())
		return
	}
	if res.Code == "not_readonly" {
		// Privileges changed since the account was checked: stop using it.
		_ = w.db.Tx(ctx, superadmin, func(q *db.Queries) error {
			return q.FinishDBVerify(ctx, db.FinishDBVerifyParams{ID: c.ID, Status: "rejected", VerifyResult: verifyJSON(res), Wipe: true})
		})
		reason := "The account is no longer read-only; scanX deleted the stored password. " + strings.Join(res.ReadOnly.Violations, " ")
		w.finishDBScan(ctx, sc, &c, res, nil, reason, logb.String(), reason)
		return
	}
	if !res.OK {
		w.finishDBScan(ctx, sc, &c, res, nil, res.Error, logb.String())
		return
	}
	fmt.Fprintf(&logb, "%s account is read-only: %s\n", time.Now().Format("15:04:05"), strings.Join(res.ReadOnly.Allowed, ", "))
	fmt.Fprintf(&logb, "%s read %d tables, %d views, %d routines (%s) in %.1fs\n", time.Now().Format("15:04:05"),
		len(res.Snapshot.Tables), len(res.Snapshot.Views), len(res.Snapshot.Routines), res.Snapshot.ServerVersion, float64(res.Duration)/1000)
	prof.Exclude = append(prof.Exclude, c.Exclude...)
	rep := dbscan.Evaluate(res.Snapshot, prof)
	fmt.Fprintf(&logb, "%s %d findings, score %d (%s), gate %s\n", time.Now().Format("15:04:05"), len(rep.Findings), rep.Score, rep.Grade, rep.Gate)
	w.finishDBScan(ctx, sc, &c, res, rep, "", logb.String())
}

func engineName(e string) string {
	switch e {
	case dbscan.EngineMySQL:
		return "MySQL"
	case dbscan.EngineMSSQL:
		return "SQL Server"
	}
	return "PostgreSQL"
}

// finishDBScan stores the outcome (rep nil = failed) and notifies.
func (w *Worker) finishDBScan(ctx context.Context, sc *db.DbScan, c *db.DbConnection, res *inspect.Result, rep *dbscan.Report, reason, logText string, alarm ...string) {
	fctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Minute)
	defer cancel()
	status := "completed"
	if rep == nil {
		status = "failed"
	}
	params := db.FinishDBScanParams{
		ID: sc.ID, Status: status, StatusReason: trunc(reason, 2000), Log: logText,
		Counts: json.RawMessage(`{}`), Summary: json.RawMessage(`{}`), ReadOnly: json.RawMessage(`{}`),
	}
	if res != nil && res.ReadOnly != nil {
		params.ReadOnly, _ = json.Marshal(res.ReadOnly)
	}
	var newCount, fixedCount int
	err := w.db.Tx(fctx, superadmin, func(q *db.Queries) error {
		if rep != nil {
			prev, err := q.PreviousDBScanFingerprints(fctx, db.PreviousDBScanFingerprintsParams{ConnectionID: c.ID, ID: sc.ID})
			if err != nil {
				return err
			}
			old := map[string]bool{}
			for _, f := range prev {
				old[f] = true
			}
			hadPrev := len(prev) > 0
			current := map[string]bool{}
			rows := make([]db.InsertDBFindingsParams, 0, len(rep.Findings))
			for _, f := range rep.Findings {
				isNew := hadPrev && !old[f.Fingerprint]
				if isNew {
					newCount++
				}
				current[f.Fingerprint] = true
				rows = append(rows, db.InsertDBFindingsParams{
					ID: newID(), OrgID: sc.OrgID, ScanID: sc.ID, ConnectionID: c.ID, RuleID: f.RuleID, Category: f.Category,
					Severity: f.Severity, ObjectType: f.ObjectType, Object: f.Object, Params: nonNil(f.Params),
					Details: nonNil(f.Details), Fingerprint: f.Fingerprint, IsNew: isNew,
				})
			}
			for f := range old {
				if !current[f] {
					fixedCount++
				}
			}
			if len(rows) > 0 {
				if _, err := q.InsertDBFindings(fctx, rows); err != nil {
					return err
				}
			}
			score := int32(rep.Score) //nolint:gosec // 0..100
			gate := rep.Gate
			params.Score, params.Grade, params.GateResult = &score, rep.Grade, &gate
			params.Counts, _ = json.Marshal(rep.Counts)
			params.Summary, _ = json.Marshal(service.DBScanSummary{
				Stats: rep.Stats, Categories: rep.Categories, Checked: rep.Checked, Server: res.Snapshot.ServerVersion,
				Database: res.Snapshot.Database, Duration: res.Duration, FailOn: rep.FailOn,
			})
			params.SnapshotGz = gzJSON(res.Snapshot)
			params.NewFindings, params.FixedFindings = int32(newCount), int32(fixedCount) //nolint:gosec // counts
		}
		return q.FinishDBScan(fctx, params)
	})
	if err != nil {
		w.log.Error("store database scan", "db_scan", sc.ID, "err", err)
		return
	}
	w.dbNotify(fctx, sc, c, rep, reason, newCount, fixedCount, alarm...)
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func gzJSON(v any) []byte {
	var b bytes.Buffer
	zw := gzip.NewWriter(&b)
	if json.NewEncoder(zw).Encode(v) != nil || zw.Close() != nil {
		return nil
	}
	return b.Bytes()
}

// dbNotify sends the scan outcome to the org's subscribed channels.
func (w *Worker) dbNotify(ctx context.Context, sc *db.DbScan, c *db.DbConnection, rep *dbscan.Report, reason string, newCount, fixedCount int, alarm ...string) {
	if w.notifier == nil || c == nil || c.Name == "" {
		return
	}
	lang, _ := w.instanceSettings(ctx)
	m := notify.Message{
		Event: notify.EventDBScanCompleted, Project: c.Name, Branch: engineName(c.Engine) + " · " + c.DatabaseName,
		BaseURL: w.cfg.BaseURL, Lang: lang, New: newCount, Fixed: fixedCount,
	}
	var chans []db.NotificationChannel
	_ = w.db.Tx(ctx, superadmin, func(q *db.Queries) error {
		if mod := w.dbModule(ctx, q, c.OrgID); mod.Settings.NoNotifications {
			return nil
		}
		o, err := q.GetOrgByID(ctx, c.OrgID)
		if err != nil {
			return err
		}
		m.Org = o.Name
		if w.cfg.BaseURL != "" {
			m.URL = strings.TrimRight(w.cfg.BaseURL, "/") + "/o/" + o.Slug + "/databases/scans/" + sc.ID.String()
		}
		chans, err = q.ListNotificationChannels(ctx, c.OrgID)
		return err
	})
	if rep == nil {
		m.Event, m.Reason = notify.EventDBScanFailed, reason
	} else {
		m.Score, m.Grade, m.Gate = rep.Score, rep.Grade, rep.Gate
		m.Critical, m.High, m.Medium, m.Low = rep.Counts["critical"], rep.Counts["high"], rep.Counts["medium"], rep.Counts["low"]
		m.Objects = fmt.Sprintf("%d tables · %d columns", rep.Stats.Tables, rep.Stats.Columns)
		if lang == "tr" {
			m.Objects = fmt.Sprintf("%d tablo · %d kolon", rep.Stats.Tables, rep.Stats.Columns)
		}
	}
	if len(alarm) > 0 {
		m.Alarm = alarm[0]
	}
	for _, ch := range chans {
		send, event := false, m.Event
		for _, e := range ch.Events {
			if e == m.Event {
				send = true
			}
			if rep != nil && rep.Gate == "fail" && e == notify.EventDBGateFailed {
				send, event = true, notify.EventDBGateFailed
			}
			if m.Alarm != "" && (e == notify.EventDBScanFailed || e == notify.EventDBGateFailed) {
				send = true
			}
		}
		if !send {
			continue
		}
		target, err := w.box.Open(ch.TargetEnc, ch.Nonce, service.ChannelAAD(ch.ID))
		if err != nil {
			continue
		}
		msg := m
		msg.Event = event
		sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		if err := w.notifier.Send(sctx, ch.Kind, string(target), msg); err != nil {
			w.log.Warn("notification failed", "channel", ch.ID, "kind", ch.Kind, "err", err)
		}
		cancel()
	}
}
