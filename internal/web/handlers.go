package web

import (
	"crypto/subtle"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/ininia/scanx/internal/auth"
	"github.com/ininia/scanx/internal/server"
	"github.com/ininia/scanx/internal/service"
	"github.com/ininia/scanx/internal/ui"
)

// ---------- setup wizard ----------

func (h *Handler) mountSetup(r chi.Router) {
	r.Get("/", h.setup)
	r.Post("/token", h.setupToken)
	r.Post("/admin", h.setupAdmin)
	r.Post("/2fa", h.setup2FA)
	r.Post("/instance", h.setupInstance)
	r.Post("/org", h.setupOrg)
	r.Post("/complete", h.setupComplete)
}

// hasSetupProof reports whether this browser entered the setup token.
func (h *Handler) hasSetupProof(r *http.Request) bool {
	c, err := r.Cookie(h.Cookies.Setup)
	if err != nil {
		return false
	}
	want := service.SetupProof(h.SessionKey, h.Svc.SetupTokenValue())
	return subtle.ConstantTimeCompare([]byte(c.Value), []byte(want)) == 1
}

// setup renders the step the wizard is at.
func (h *Handler) setup(w http.ResponseWriter, r *http.Request) {
	h.renderSetup(w, r, ui.NewForm(), http.StatusOK)
}

func (h *Handler) renderSetup(w http.ResponseWriter, r *http.Request, f *ui.Form, status int) {
	ctx := r.Context()
	p := h.page(r, "setup.welcome", "")
	st, err := h.Svc.SetupState(ctx)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	sess := server.SessionFrom(ctx)
	admin := sess != nil && !sess.MFAPending && sess.Principal.IsSuperadmin
	switch {
	case !h.hasSetupProof(r):
		render(w, r, status, ui.SetupToken(p, f))
	case !st.HasAdmin:
		render(w, r, status, ui.SetupAdmin(p, f))
	case !admin:
		http.Redirect(w, r, "/login?next=/setup", http.StatusSeeOther)
	case sess.NeedsTOTPEnrollment(h.Require2FA):
		enr, err := h.Svc.PendingTOTP(ctx, sess.Principal)
		if err != nil {
			if enr, err = h.Svc.BeginTOTP(ctx, sess.Principal); err != nil {
				h.fail(w, r, err)
				return
			}
		}
		render(w, r, status, ui.Setup2FA(p, f, &ui.TOTPView{QR: qrDataURI(enr.URI), Secret: enr.Secret}))
	case !st.HasSettings:
		if len(f.Values) == 0 {
			f.Values["name"] = "scanX"
			f.Values["base_url"] = requestScheme(r) + "://" + r.Host
			f.Values["default_locale"] = p.Lang
			f.Values["timezone"] = "Europe/Istanbul"
		}
		render(w, r, status, ui.SetupInstance(p, f))
	case !st.HasOrg:
		render(w, r, status, ui.SetupOrg(p, f))
	default:
		inst, _ := h.Svc.Instance(ctx)
		orgs, _ := h.Svc.ListMyOrgs(ctx, sess.Principal)
		org := ""
		if len(orgs) > 0 {
			org = orgs[0].Name
		}
		render(w, r, status, ui.SetupDone(p, f, inst.Name, sess.Principal.Email, org))
	}
}

func (h *Handler) setupToken(w http.ResponseWriter, r *http.Request) {
	tok := r.PostFormValue("token")
	if err := h.Svc.CheckSetupToken(r.Context(), tok); err != nil {
		f := ui.NewForm()
		f.Error = "err.setup_token"
		h.renderSetup(w, r, f, http.StatusUnauthorized)
		return
	}
	h.Cookies.Set(w, h.Cookies.Setup, service.SetupProof(h.SessionKey, tok), 2*time.Hour)
	http.Redirect(w, r, "/setup", http.StatusSeeOther)
}

func (h *Handler) setupAdmin(w http.ResponseWriter, r *http.Request) {
	if !h.hasSetupProof(r) {
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
		return
	}
	f := formFrom(r, "name", "email")
	if r.PostFormValue("password") != r.PostFormValue("password2") {
		f.Errors["password2"] = "err.passwords_mismatch"
		h.renderSetup(w, r, f, http.StatusUnprocessableEntity)
		return
	}
	res, err := h.Svc.CreateFirstAdmin(r.Context(), f.V("email"), f.V("name"), r.PostFormValue("password"), server.MetaFrom(r))
	if err != nil {
		if !formErr(f, err) {
			h.fail(w, r, err)
			return
		}
		h.renderSetup(w, r, f, http.StatusUnprocessableEntity)
		return
	}
	h.setSession(w, res)
	http.Redirect(w, r, "/setup", http.StatusSeeOther)
}

func (h *Handler) setupSession(w http.ResponseWriter, r *http.Request) *service.Session {
	s := server.SessionFrom(r.Context())
	if !h.hasSetupProof(r) || s == nil || s.MFAPending || !s.Principal.IsSuperadmin {
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
		return nil
	}
	return s
}

func (h *Handler) setup2FA(w http.ResponseWriter, r *http.Request) {
	s := h.setupSession(w, r)
	if s == nil {
		return
	}
	if err := h.Svc.ConfirmTOTP(r.Context(), s.Principal, r.PostFormValue("code"), server.MetaFrom(r)); err != nil {
		f := ui.NewForm()
		f.Error = "err.invalid_code"
		h.renderSetup(w, r, f, http.StatusUnprocessableEntity)
		return
	}
	http.Redirect(w, r, "/setup", http.StatusSeeOther)
}

func (h *Handler) setupInstance(w http.ResponseWriter, r *http.Request) {
	s := h.setupSession(w, r)
	if s == nil {
		return
	}
	f := formFrom(r, "name", "base_url", "default_locale", "timezone")
	in := service.InstanceSettings{Name: f.V("name"), BaseURL: f.V("base_url"), DefaultLocale: f.V("default_locale"), Timezone: f.V("timezone")}
	if err := h.Svc.SaveInstanceSettings(r.Context(), s.Principal, in, server.MetaFrom(r)); err != nil {
		if !formErr(f, err) {
			h.fail(w, r, err)
			return
		}
		h.renderSetup(w, r, f, http.StatusUnprocessableEntity)
		return
	}
	http.Redirect(w, r, "/setup", http.StatusSeeOther)
}

func (h *Handler) setupOrg(w http.ResponseWriter, r *http.Request) {
	s := h.setupSession(w, r)
	if s == nil {
		return
	}
	f := formFrom(r, "name")
	if _, err := h.Svc.CreateOrg(r.Context(), s.Principal, f.V("name"), "", server.MetaFrom(r)); err != nil {
		if !formErr(f, err) {
			h.fail(w, r, err)
			return
		}
		h.renderSetup(w, r, f, http.StatusUnprocessableEntity)
		return
	}
	http.Redirect(w, r, "/setup", http.StatusSeeOther)
}

func (h *Handler) setupComplete(w http.ResponseWriter, r *http.Request) {
	s := h.setupSession(w, r)
	if s == nil {
		return
	}
	if err := h.Svc.CompleteSetup(r.Context(), s, server.MetaFrom(r)); err != nil {
		f := ui.NewForm()
		if !formErr(f, err) {
			h.fail(w, r, err)
			return
		}
		h.renderSetup(w, r, f, http.StatusUnprocessableEntity)
		return
	}
	h.setupDone.Store(true)
	h.Cookies.Clear(w, h.Cookies.Setup)
	redirect(w, r, "/", "flash.setup_done")
}

// ---------- login ----------

func (h *Handler) loginForm(w http.ResponseWriter, r *http.Request) {
	if auth.PrincipalFrom(r.Context()) != nil {
		http.Redirect(w, r, safeNext(r.URL.Query().Get("next")), http.StatusSeeOther) //nolint:gosec // safeNext allows only same-site relative paths
		return
	}
	render(w, r, http.StatusOK, ui.LoginPage(h.page(r, "login.title", ""), ui.NewForm(), safeNext(r.URL.Query().Get("next"))))
}

func (h *Handler) login(w http.ResponseWriter, r *http.Request) {
	f := formFrom(r, "email")
	next := safeNext(r.PostFormValue("next"))
	res, err := h.Svc.Login(r.Context(), f.V("email"), r.PostFormValue("password"), server.MetaFrom(r))
	if err != nil {
		if !formErr(f, err) {
			h.fail(w, r, err)
			return
		}
		render(w, r, http.StatusUnauthorized, ui.LoginPage(h.page(r, "login.title", ""), f, next))
		return
	}
	h.setSession(w, res)
	if res.MFAPending {
		http.Redirect(w, r, "/login/2fa?next="+url.QueryEscape(next), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, next, http.StatusSeeOther) //nolint:gosec // next validated by safeNext
}

func (h *Handler) mfaForm(w http.ResponseWriter, r *http.Request) {
	if s := server.SessionFrom(r.Context()); s == nil || !s.MFAPending {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	render(w, r, http.StatusOK, ui.MFAPage(h.page(r, "mfa.title", ""), ui.NewForm()))
}

func (h *Handler) mfa(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie(h.Cookies.Session)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	res, err := h.Svc.VerifyMFA(r.Context(), c.Value, r.PostFormValue("code"), server.MetaFrom(r))
	if err != nil {
		f := ui.NewForm()
		f.Error = "err.invalid_code"
		if err == service.ErrRateLimited || err == service.ErrUnauthorized { //nolint:errorlint // sentinel identity
			h.Cookies.Clear(w, h.Cookies.Session)
			redirect(w, r, "/login", "")
			return
		}
		render(w, r, http.StatusUnauthorized, ui.MFAPage(h.page(r, "mfa.title", ""), f))
		return
	}
	h.setSession(w, res)
	http.Redirect(w, r, safeNext(r.URL.Query().Get("next")), http.StatusSeeOther) //nolint:gosec // safeNext allows only same-site relative paths
}

func (h *Handler) logout(w http.ResponseWriter, r *http.Request) {
	if s := server.SessionFrom(r.Context()); s != nil {
		_ = h.Svc.Logout(r.Context(), s, server.MetaFrom(r))
	}
	h.Cookies.Clear(w, h.Cookies.Session)
	redirect(w, r, "/login", "flash.logged_out")
}

// ---------- invitations ----------

func (h *Handler) inviteView(r *http.Request, token string) (*ui.InviteView, error) {
	info, err := h.Svc.LookupInvitation(r.Context(), token)
	if err != nil {
		return nil, err
	}
	p := auth.PrincipalFrom(r.Context())
	return &ui.InviteView{
		Token: token, OrgName: info.OrgName, Email: info.Email, Role: info.Role,
		LoggedIn:   p != nil && strings.EqualFold(p.Email, info.Email),
		NeedsLogin: p == nil && info.UserExists,
	}, nil
}

func (h *Handler) inviteForm(w http.ResponseWriter, r *http.Request) {
	v, err := h.inviteView(r, chi.URLParam(r, "token"))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	render(w, r, http.StatusOK, ui.InvitePage(h.page(r, "", ""), ui.NewForm(), v))
}

func (h *Handler) invite(w http.ResponseWriter, r *http.Request) {
	token := chi.URLParam(r, "token")
	v, err := h.inviteView(r, token)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	f := formFrom(r, "name")
	res, err := h.Svc.AcceptInvitation(r.Context(), token, auth.PrincipalFrom(r.Context()), f.V("name"), r.PostFormValue("password"), server.MetaFrom(r))
	if err != nil {
		if !formErr(f, err) {
			h.fail(w, r, err)
			return
		}
		render(w, r, http.StatusUnprocessableEntity, ui.InvitePage(h.page(r, "", ""), f, v))
		return
	}
	if res != nil {
		h.setSession(w, res)
	}
	redirect(w, r, "/", "flash.joined")
}

// ---------- home / dashboard ----------

func (h *Handler) home(w http.ResponseWriter, r *http.Request) {
	p := h.page(r, "nav.dashboard", "dashboard")
	if len(p.Orgs) == 0 {
		render(w, r, http.StatusOK, ui.NoOrg(p))
		return
	}
	target := p.Orgs[0].Slug
	if s := server.SessionFrom(r.Context()); s != nil && s.ActiveOrgID != nil {
		for _, o := range p.Orgs {
			if o.ID == *s.ActiveOrgID {
				target = o.Slug
			}
		}
	}
	to := "/o/" + target
	if m := r.URL.Query().Get("msg"); m != "" {
		redirect(w, r, to, m)
		return
	}
	http.Redirect(w, r, to, http.StatusSeeOther) //nolint:gosec // slug of an org from the caller's own membership list
}

func (h *Handler) dashboard(w http.ResponseWriter, r *http.Request) {
	o := orgFrom(r)
	ps, total, err := h.Svc.ListProjects(r.Context(), o, 1, 8)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	members, _ := h.Svc.ListMembers(r.Context(), o)
	stats, err := h.Svc.Stats(r.Context(), o)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	render(w, r, http.StatusOK, ui.Dashboard(h.page(r, "nav.dashboard", "dashboard"), &ui.DashboardView{Projects: total, Members: len(members), Recent: ps, Stats: stats}))
}

// ---------- projects ----------

func (h *Handler) projects(w http.ResponseWriter, r *http.Request) {
	ps, total, err := h.Svc.ListProjects(r.Context(), orgFrom(r), atoi(r.URL.Query().Get("page"), 1), 50)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	render(w, r, http.StatusOK, ui.Projects(h.page(r, "nav.projects", "projects"), ps, total))
}

func (h *Handler) projectNewForm(w http.ResponseWriter, r *http.Request) {
	if err := orgFrom(r).Require(auth.ActProjectWrite, "write"); err != nil {
		h.fail(w, r, err)
		return
	}
	render(w, r, http.StatusOK, ui.ProjectNew(h.page(r, "projects.new", "projects"), ui.NewForm()))
}

func (h *Handler) projectNew(w http.ResponseWriter, r *http.Request) {
	o := orgFrom(r)
	f := formFrom(r, "repo_url", "name", "branches")
	var branches []string
	for _, b := range strings.Split(f.V("branches"), ",") {
		if b = strings.TrimSpace(b); b != "" {
			branches = append(branches, b)
		}
	}
	p, err := h.Svc.CreateProject(r.Context(), o, service.ProjectInput{Name: f.V("name"), RepoURL: f.V("repo_url"), Branches: branches}, server.MetaFrom(r))
	if err != nil {
		if !formErr(f, err) {
			h.fail(w, r, err)
			return
		}
		render(w, r, http.StatusUnprocessableEntity, ui.ProjectNew(h.page(r, "projects.new", "projects"), f))
		return
	}
	redirect(w, r, "/o/"+o.Org.Slug+"/projects/"+p.Slug, "flash.created")
}

func (h *Handler) projectDelete(w http.ResponseWriter, r *http.Request) {
	o := orgFrom(r)
	if err := h.Svc.DeleteProject(r.Context(), o, chi.URLParam(r, "project"), server.MetaFrom(r)); err != nil {
		h.fail(w, r, err)
		return
	}
	redirect(w, r, "/o/"+o.Org.Slug+"/projects", "flash.deleted")
}

// ---------- members ----------

func (h *Handler) renderMembers(w http.ResponseWriter, r *http.Request, f *ui.Form, newInvite string, status int) {
	o := orgFrom(r)
	ms, err := h.Svc.ListMembers(r.Context(), o)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	v := &ui.MembersView{Members: ms, NewInvite: newInvite}
	if auth.Can(o.Role, auth.ActMembersManage) {
		v.Invitations, _ = h.Svc.ListInvitations(r.Context(), o)
	}
	render(w, r, status, ui.Members(h.page(r, "nav.members", "members"), f, v))
}

func (h *Handler) members(w http.ResponseWriter, r *http.Request) {
	h.renderMembers(w, r, ui.NewForm(), "", http.StatusOK)
}

func (h *Handler) memberInvite(w http.ResponseWriter, r *http.Request) {
	f := formFrom(r, "email")
	inv, err := h.Svc.Invite(r.Context(), orgFrom(r), f.V("email"), r.PostFormValue("role"), server.MetaFrom(r))
	if err != nil {
		if !formErr(f, err) {
			h.fail(w, r, err)
			return
		}
		h.renderMembers(w, r, f, "", http.StatusUnprocessableEntity)
		return
	}
	inst, _ := h.Svc.Instance(r.Context())
	base := strings.TrimRight(inst.BaseURL, "/")
	if base == "" {
		base = requestScheme(r) + "://" + r.Host
	}
	h.renderMembers(w, r, ui.NewForm(), base+"/invite/"+inv.Token, http.StatusOK)
}

func (h *Handler) memberRole(w http.ResponseWriter, r *http.Request) {
	o := orgFrom(r)
	id, ok := pathID(r, "user")
	if !ok {
		h.errorPage(w, r, http.StatusNotFound)
		return
	}
	if err := h.Svc.UpdateMemberRole(r.Context(), o, id, r.PostFormValue("role"), server.MetaFrom(r)); err != nil {
		f := ui.NewForm()
		if !formErr(f, err) {
			h.fail(w, r, err)
			return
		}
		h.renderMembers(w, r, f, "", http.StatusUnprocessableEntity)
		return
	}
	redirect(w, r, "/o/"+o.Org.Slug+"/members", "flash.member_updated")
}

func (h *Handler) memberRemove(w http.ResponseWriter, r *http.Request) {
	o := orgFrom(r)
	id, ok := pathID(r, "user")
	if !ok {
		h.errorPage(w, r, http.StatusNotFound)
		return
	}
	if err := h.Svc.RemoveMember(r.Context(), o, id, server.MetaFrom(r)); err != nil {
		f := ui.NewForm()
		if !formErr(f, err) {
			h.fail(w, r, err)
			return
		}
		h.renderMembers(w, r, f, "", http.StatusUnprocessableEntity)
		return
	}
	if id == o.P.UserID {
		redirect(w, r, "/", "flash.deleted")
		return
	}
	redirect(w, r, "/o/"+o.Org.Slug+"/members", "flash.member_updated")
}

func (h *Handler) invitationRevoke(w http.ResponseWriter, r *http.Request) {
	o := orgFrom(r)
	id, ok := pathID(r, "id")
	if !ok {
		h.errorPage(w, r, http.StatusNotFound)
		return
	}
	if err := h.Svc.RevokeInvitation(r.Context(), o, id, server.MetaFrom(r)); err != nil {
		h.fail(w, r, err)
		return
	}
	redirect(w, r, "/o/"+o.Org.Slug+"/members", "flash.revoked")
}

// ---------- tokens ----------

func (h *Handler) renderTokens(w http.ResponseWriter, r *http.Request, f *ui.Form, created string, status int) {
	rows, err := h.Svc.ListAPITokens(r.Context(), orgFrom(r))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	render(w, r, status, ui.Tokens(h.page(r, "nav.tokens", "tokens"), f, rows, created))
}

func (h *Handler) tokens(w http.ResponseWriter, r *http.Request) {
	h.renderTokens(w, r, ui.NewForm(), "", http.StatusOK)
}

func (h *Handler) tokenCreate(w http.ResponseWriter, r *http.Request) {
	f := formFrom(r, "name")
	scope := r.PostFormValue("scope")
	t, err := h.Svc.CreateAPIToken(r.Context(), orgFrom(r), f.V("name"), []string{scope}, atoi(r.PostFormValue("days"), 90), server.MetaFrom(r))
	if err != nil {
		if !formErr(f, err) {
			h.fail(w, r, err)
			return
		}
		h.renderTokens(w, r, f, "", http.StatusUnprocessableEntity)
		return
	}
	h.renderTokens(w, r, ui.NewForm(), t.Token, http.StatusOK)
}

func (h *Handler) tokenRevoke(w http.ResponseWriter, r *http.Request) {
	o := orgFrom(r)
	id, ok := pathID(r, "id")
	if !ok {
		h.errorPage(w, r, http.StatusNotFound)
		return
	}
	if err := h.Svc.RevokeAPIToken(r.Context(), o, id, server.MetaFrom(r)); err != nil {
		h.fail(w, r, err)
		return
	}
	redirect(w, r, "/o/"+o.Org.Slug+"/tokens", "flash.revoked")
}

func (h *Handler) audit(w http.ResponseWriter, r *http.Request) {
	rows, err := h.Svc.ListAudit(r.Context(), orgFrom(r), 200, 0)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	render(w, r, http.StatusOK, ui.Audit(h.page(r, "nav.audit", "audit"), rows))
}

// ---------- account ----------

func (h *Handler) accountView(r *http.Request) *ui.AccountView {
	s := server.SessionFrom(r.Context())
	sessions, _ := h.Svc.ListSessions(r.Context(), s)
	v := &ui.AccountView{
		TOTPEnabled: s.TOTPEnabled, Sessions: sessions, ForceTOTP: s.NeedsTOTPEnrollment(h.Require2FA),
		ProfileForm: ui.NewForm(), PassForm: ui.NewForm(), TOTPForm: ui.NewForm(),
	}
	if !s.TOTPEnabled {
		if enr, err := h.Svc.PendingTOTP(r.Context(), s.Principal); err == nil {
			v.Enroll = &ui.TOTPView{QR: qrDataURI(enr.URI), Secret: enr.Secret}
		}
	}
	return v
}

func (h *Handler) account(w http.ResponseWriter, r *http.Request) {
	render(w, r, http.StatusOK, ui.Account(h.page(r, "nav.account", "account"), h.accountView(r)))
}

func (h *Handler) accountProfile(w http.ResponseWriter, r *http.Request) {
	p := auth.PrincipalFrom(r.Context())
	if err := h.Svc.UpdateProfile(r.Context(), p, r.PostFormValue("name"), r.PostFormValue("locale")); err != nil {
		v := h.accountView(r)
		if !formErr(v.ProfileForm, err) {
			h.fail(w, r, err)
			return
		}
		render(w, r, http.StatusUnprocessableEntity, ui.Account(h.page(r, "nav.account", "account"), v))
		return
	}
	redirect(w, r, "/account", "flash.saved")
}

func (h *Handler) accountPassword(w http.ResponseWriter, r *http.Request) {
	s := server.SessionFrom(r.Context())
	if err := h.Svc.ChangePassword(r.Context(), s, r.PostFormValue("current"), r.PostFormValue("new"), server.MetaFrom(r)); err != nil {
		v := h.accountView(r)
		if !formErr(v.PassForm, err) {
			h.fail(w, r, err)
			return
		}
		render(w, r, http.StatusUnprocessableEntity, ui.Account(h.page(r, "nav.account", "account"), v))
		return
	}
	redirect(w, r, "/account", "flash.password_changed")
}

func (h *Handler) totpBegin(w http.ResponseWriter, r *http.Request) {
	if _, err := h.Svc.BeginTOTP(r.Context(), auth.PrincipalFrom(r.Context())); err != nil && err != service.ErrConflict { //nolint:errorlint // sentinel identity
		h.fail(w, r, err)
		return
	}
	http.Redirect(w, r, "/account", http.StatusSeeOther)
}

func (h *Handler) totpConfirm(w http.ResponseWriter, r *http.Request) {
	if err := h.Svc.ConfirmTOTP(r.Context(), auth.PrincipalFrom(r.Context()), r.PostFormValue("code"), server.MetaFrom(r)); err != nil {
		v := h.accountView(r)
		v.TOTPForm.Error = "err.invalid_code"
		render(w, r, http.StatusUnprocessableEntity, ui.Account(h.page(r, "nav.account", "account"), v))
		return
	}
	redirect(w, r, "/account", "flash.totp_enabled")
}

func (h *Handler) totpDisable(w http.ResponseWriter, r *http.Request) {
	if err := h.Svc.DisableTOTP(r.Context(), auth.PrincipalFrom(r.Context()), r.PostFormValue("password"), server.MetaFrom(r)); err != nil {
		v := h.accountView(r)
		if !formErr(v.TOTPForm, err) {
			h.fail(w, r, err)
			return
		}
		render(w, r, http.StatusUnprocessableEntity, ui.Account(h.page(r, "nav.account", "account"), v))
		return
	}
	redirect(w, r, "/account", "flash.totp_disabled")
}

func (h *Handler) sessionRevoke(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r, "id")
	if !ok {
		h.errorPage(w, r, http.StatusNotFound)
		return
	}
	if err := h.Svc.RevokeSession(r.Context(), server.SessionFrom(r.Context()), id, server.MetaFrom(r)); err != nil {
		h.fail(w, r, err)
		return
	}
	redirect(w, r, "/account", "flash.revoked")
}

// ---------- admin ----------

func (h *Handler) admin(w http.ResponseWriter, r *http.Request) {
	h.renderAdmin(w, r, ui.NewForm(), http.StatusOK)
}

func (h *Handler) renderAdmin(w http.ResponseWriter, r *http.Request, f *ui.Form, status int) {
	orgs, err := h.Svc.ListAllOrgs(r.Context(), auth.PrincipalFrom(r.Context()))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	render(w, r, status, ui.Admin(h.page(r, "nav.admin", "admin"), f, orgs))
}

func (h *Handler) adminCreateOrg(w http.ResponseWriter, r *http.Request) {
	f := formFrom(r, "name")
	org, err := h.Svc.CreateOrg(r.Context(), auth.PrincipalFrom(r.Context()), f.V("name"), "", server.MetaFrom(r))
	if err != nil {
		if !formErr(f, err) {
			h.fail(w, r, err)
			return
		}
		h.renderAdmin(w, r, f, http.StatusUnprocessableEntity)
		return
	}
	redirect(w, r, "/o/"+org.Slug, "flash.created")
}

// requestScheme is https behind the TLS proxy (X-Forwarded-Proto) or with
// direct TLS, http otherwise.
func requestScheme(r *http.Request) string {
	if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
		return "https"
	}
	return "http"
}
