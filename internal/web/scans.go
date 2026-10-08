package web

import (
	"errors"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/ininia/scanx/internal/api"
	"github.com/ininia/scanx/internal/auth"
	"github.com/ininia/scanx/internal/gitutil"
	"github.com/ininia/scanx/internal/server"
	"github.com/ininia/scanx/internal/service"
	"github.com/ininia/scanx/internal/sshkeys"
	"github.com/ininia/scanx/internal/ui"
)

// mountScans adds the Faz 3–4 pages inside /o/{org}.
func (h *Handler) mountScans(r chi.Router) {
	r.Post("/projects/{project}/scan", h.scanNow)
	r.Post("/projects/{project}/test", h.testConnection)
	r.Post("/projects/{project}/deploy-key/rotate", h.rotateDeployKey)
	r.Post("/projects/{project}/webhook/rotate", h.rotateWebhookSecret)
	r.Post("/projects/{project}/settings", h.projectSettings)
	r.Get("/projects/{project}/issues", h.projectIssues)
	r.Get("/scans/{scan}", h.scanDetail)
	r.Post("/scans/{scan}/cancel", h.scanCancel)
	r.Get("/scans/{scan}/report/{format}", h.scanReport)
	r.Get("/issues/{issue}", h.issueDetail)
	r.Post("/issues/{issue}/status", h.issueStatus)
	r.Get("/jobs/{job}", h.jobStatus)
	r.Get("/notifications", h.notifications)
	r.Post("/notifications", h.notificationCreate)
	r.Post("/notifications/{id}/test", h.notificationTest)
	r.Post("/notifications/{id}/delete", h.notificationDelete)
}

func (h *Handler) baseURL(r *http.Request) string {
	inst, _ := h.Svc.Instance(r.Context())
	if b := strings.TrimRight(inst.BaseURL, "/"); b != "" {
		return b
	}
	return requestScheme(r) + "://" + r.Host
}

func (h *Handler) projectDetail(w http.ResponseWriter, r *http.Request) {
	o := orgFrom(r)
	ctx := r.Context()
	p, err := h.Svc.GetProject(ctx, o, chi.URLParam(r, "project"))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	v := &ui.ProjectView{Project: p, Open: map[string]int{}}
	v.Repo, _ = gitutil.ParseRepoURL(p.RepoUrl)
	if v.Repo != nil {
		v.HostTrusted = sshkeys.KnownHosts(v.Repo.Host, h.KnownHostsExtra) != ""
	}
	if v.DeployKey, err = h.Svc.ProjectDeployKey(ctx, o, p.Slug); err != nil {
		h.fail(w, r, err)
		return
	}
	provider := p.Provider
	if !service.WebhookProviders[provider] {
		provider = "generic"
	}
	v.WebhookURL = h.baseURL(r) + "/api/v1/hooks/" + provider + "/" + p.ID.String()
	if o.Require(auth.ActProjectWrite, "write") == nil {
		if v.WebhookSecret, err = h.Svc.WebhookSecret(ctx, o, p.Slug); err != nil {
			h.fail(w, r, err)
			return
		}
	}
	if v.Scans, err = h.Svc.ListProjectScans(ctx, o, p, 20); err != nil {
		h.fail(w, r, err)
		return
	}
	if st, err := h.Svc.Stats(ctx, o); err == nil {
		for sev, n := range st.ByProject[p.ID] {
			v.Open[sev] = n
		}
	}
	if id := r.URL.Query().Get("test"); id != "" {
		v.TestJob, _ = h.Svc.GetJob(ctx, o, id)
	}
	pg := h.page(r, "", "projects")
	pg.Title = p.Name
	render(w, r, http.StatusOK, ui.ProjectDetail(pg, v))
}

func (h *Handler) projectURL(r *http.Request) string {
	return "/o/" + orgFrom(r).Org.Slug + "/projects/" + chi.URLParam(r, "project")
}

func (h *Handler) scanNow(w http.ResponseWriter, r *http.Request) {
	o := orgFrom(r)
	sc, err := h.Svc.TriggerScan(r.Context(), o, chi.URLParam(r, "project"), r.PostFormValue("branch"), service.TriggerManual, server.MetaFrom(r))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	redirect(w, r, "/o/"+o.Org.Slug+"/scans/"+sc.ID.String(), "flash.scan_queued")
}

func (h *Handler) testConnection(w http.ResponseWriter, r *http.Request) {
	id, err := h.Svc.TestConnection(r.Context(), orgFrom(r), chi.URLParam(r, "project"))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	redirect(w, r, h.projectURL(r)+"?test="+id.String(), "")
}

func (h *Handler) jobStatus(w http.ResponseWriter, r *http.Request) {
	o := orgFrom(r)
	j, err := h.Svc.GetJob(r.Context(), o, chi.URLParam(r, "job"))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	c := &ui.ConnTest{Job: j, Result: service.ParseConnectionResult(j.Result), PollURL: "/o/" + o.Org.Slug + "/jobs/" + j.ID.String()}
	render(w, r, http.StatusOK, ui.ConnTestResult(h.page(r, "", ""), c))
}

func (h *Handler) rotateDeployKey(w http.ResponseWriter, r *http.Request) {
	if _, err := h.Svc.RotateDeployKey(r.Context(), orgFrom(r), chi.URLParam(r, "project"), server.MetaFrom(r)); err != nil {
		h.fail(w, r, err)
		return
	}
	redirect(w, r, h.projectURL(r), "flash.key_rotated")
}

func (h *Handler) rotateWebhookSecret(w http.ResponseWriter, r *http.Request) {
	if _, err := h.Svc.RotateWebhookSecret(r.Context(), orgFrom(r), chi.URLParam(r, "project"), server.MetaFrom(r)); err != nil {
		h.fail(w, r, err)
		return
	}
	redirect(w, r, h.projectURL(r), "flash.secret_rotated")
}

func (h *Handler) projectSettings(w http.ResponseWriter, r *http.Request) {
	err := h.Svc.UpdateScanSettings(r.Context(), orgFrom(r), chi.URLParam(r, "project"),
		r.PostFormValue("fail_on"), r.PostFormValue("history") == "1", server.MetaFrom(r))
	var ve *service.ValidationError
	if errors.As(err, &ve) {
		h.errorPage(w, r, http.StatusUnprocessableEntity)
		return
	}
	if err != nil {
		h.fail(w, r, err)
		return
	}
	redirect(w, r, h.projectURL(r), "flash.saved")
}

func (h *Handler) projectIssues(w http.ResponseWriter, r *http.Request) {
	o := orgFrom(r)
	p, err := h.Svc.GetProject(r.Context(), o, chi.URLParam(r, "project"))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	status := r.URL.Query().Get("status")
	if _, set := r.URL.Query()["status"]; !set {
		status = "open"
	}
	issues, err := h.Svc.ProjectIssues(r.Context(), o, p, status)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	pg := h.page(r, "issues.title", "projects")
	render(w, r, http.StatusOK, ui.ProjectIssues(pg, p, issues, status))
}

func (h *Handler) scanDetail(w http.ResponseWriter, r *http.Request) {
	v, err := h.Svc.GetScan(r.Context(), orgFrom(r), chi.URLParam(r, "scan"), true)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	pg := h.page(r, "scan.title", "projects")
	pg.Title = v.Project.Name + " · " + pg.Title
	render(w, r, http.StatusOK, ui.ScanDetail(pg, &ui.ScanPage{View: v, Summary: service.ParseSummary(v.Scan.Summary)}))
}

func (h *Handler) scanCancel(w http.ResponseWriter, r *http.Request) {
	o := orgFrom(r)
	err := h.Svc.CancelScan(r.Context(), o, chi.URLParam(r, "scan"), server.MetaFrom(r))
	if err != nil && !errors.Is(err, service.ErrConflict) {
		h.fail(w, r, err)
		return
	}
	redirect(w, r, "/o/"+o.Org.Slug+"/scans/"+chi.URLParam(r, "scan"), "flash.scan_canceled")
}

func (h *Handler) scanReport(w http.ResponseWriter, r *http.Request) {
	format := chi.URLParam(r, "format")
	gz, err := h.Svc.ScanReport(r.Context(), orgFrom(r), chi.URLParam(r, "scan"), format)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	api.WriteReport(w, r, gz, format, format != "html" || r.URL.Query().Get("download") == "1")
}

func (h *Handler) renderIssue(w http.ResponseWriter, r *http.Request, f *ui.Form, status int) {
	v, err := h.Svc.GetIssue(r.Context(), orgFrom(r), chi.URLParam(r, "issue"))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	pg := h.page(r, "", "projects")
	pg.Title = v.Issue.Title
	render(w, r, status, ui.IssueDetail(pg, f, &ui.IssuePage{View: v, Detail: ui.ParseIssueDetail(v.Issue.Detail)}))
}

func (h *Handler) issueDetail(w http.ResponseWriter, r *http.Request) {
	h.renderIssue(w, r, ui.NewForm(), http.StatusOK)
}

func (h *Handler) issueStatus(w http.ResponseWriter, r *http.Request) {
	f := formFrom(r, "status", "reason")
	err := h.Svc.SetIssueStatus(r.Context(), orgFrom(r), chi.URLParam(r, "issue"), f.V("status"), f.V("reason"), server.MetaFrom(r))
	if err != nil {
		if !formErr(f, err) {
			h.fail(w, r, err)
			return
		}
		h.renderIssue(w, r, f, http.StatusUnprocessableEntity)
		return
	}
	redirect(w, r, "/o/"+orgFrom(r).Org.Slug+"/issues/"+chi.URLParam(r, "issue"), "flash.saved")
}

func (h *Handler) renderNotifications(w http.ResponseWriter, r *http.Request, f *ui.Form, testErr string, status int) {
	chans, err := h.Svc.ListChannels(r.Context(), orgFrom(r))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	v := &ui.NotificationsView{Channels: chans, SMTPConfigured: h.SMTPConfigured, TestError: testErr}
	render(w, r, status, ui.Notifications(h.page(r, "nav.notifications", "notifications"), f, v))
}

func (h *Handler) notifications(w http.ResponseWriter, r *http.Request) {
	h.renderNotifications(w, r, ui.NewForm(), "", http.StatusOK)
}

func (h *Handler) notificationCreate(w http.ResponseWriter, r *http.Request) {
	f := formFrom(r, "kind", "name", "target")
	_ = r.ParseForm()
	_, err := h.Svc.CreateChannel(r.Context(), orgFrom(r), f.V("kind"), f.V("name"), f.V("target"), r.PostForm["events"], server.MetaFrom(r))
	if err != nil {
		if !formErr(f, err) {
			h.fail(w, r, err)
			return
		}
		h.renderNotifications(w, r, f, "", http.StatusUnprocessableEntity)
		return
	}
	redirect(w, r, "/o/"+orgFrom(r).Org.Slug+"/notifications", "flash.created")
}

func (h *Handler) notificationTest(w http.ResponseWriter, r *http.Request) {
	err := h.Svc.TestChannel(r.Context(), orgFrom(r), chi.URLParam(r, "id"))
	var de *service.DeliveryError
	if errors.As(err, &de) {
		h.renderNotifications(w, r, ui.NewForm(), de.Msg, http.StatusOK)
		return
	}
	if err != nil {
		h.fail(w, r, err)
		return
	}
	redirect(w, r, "/o/"+orgFrom(r).Org.Slug+"/notifications", "flash.test_sent")
}

func (h *Handler) notificationDelete(w http.ResponseWriter, r *http.Request) {
	if err := h.Svc.DeleteChannel(r.Context(), orgFrom(r), chi.URLParam(r, "id"), server.MetaFrom(r)); err != nil {
		h.fail(w, r, err)
		return
	}
	redirect(w, r, "/o/"+orgFrom(r).Org.Slug+"/notifications", "flash.deleted")
}
