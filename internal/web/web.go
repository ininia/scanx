// Package web serves the HTML user interface (templ + htmx).
package web

import (
	"context"
	"encoding/base64"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/a-h/templ"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"rsc.io/qr"

	"github.com/ininia/scanx/internal/auth"
	"github.com/ininia/scanx/internal/i18n"
	"github.com/ininia/scanx/internal/server"
	"github.com/ininia/scanx/internal/service"
	"github.com/ininia/scanx/internal/ui"
	"github.com/ininia/scanx/internal/version"
)

// Handler serves the UI.
type Handler struct {
	Svc        *service.Service
	Cookies    server.Cookies
	SessionKey []byte // binds the setup proof cookie
	Require2FA bool

	setupDone atomic.Bool
}

const langCookie = "scanx_lang"

// Mount registers UI routes.
func (h *Handler) Mount(r chi.Router) {
	static := http.StripPrefix("/static/", http.FileServerFS(ui.Static()))
	r.Get("/static/*", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("v") == ui.AssetVersion {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		} else {
			w.Header().Set("Cache-Control", "no-cache")
		}
		static.ServeHTTP(w, r)
	})
	r.Get("/lang/{lang}", h.setLang)
	r.NotFound(func(w http.ResponseWriter, r *http.Request) { h.errorPage(w, r, http.StatusNotFound) })
	r.MethodNotAllowed(func(w http.ResponseWriter, r *http.Request) { h.errorPage(w, r, http.StatusNotFound) })

	r.Group(func(r chi.Router) {
		r.Use(h.setupGate)
		r.Route("/setup", h.mountSetup)
		r.Get("/login", h.loginForm)
		r.Post("/login", h.login)
		r.Get("/login/2fa", h.mfaForm)
		r.Post("/login/2fa", h.mfa)
		r.Post("/logout", h.logout)
		r.Get("/invite/{token}", h.inviteForm)
		r.Post("/invite/{token}", h.invite)

		r.Group(func(r chi.Router) {
			r.Use(h.requireLogin, h.enforce2FA)
			r.Get("/", h.home)
			r.Get("/account", h.account)
			r.Post("/account/profile", h.accountProfile)
			r.Post("/account/password", h.accountPassword)
			r.Post("/account/2fa/begin", h.totpBegin)
			r.Post("/account/2fa/confirm", h.totpConfirm)
			r.Post("/account/2fa/disable", h.totpDisable)
			r.Post("/account/sessions/{id}/revoke", h.sessionRevoke)
			r.Get("/admin", h.admin)
			r.Post("/admin/orgs", h.adminCreateOrg)
			r.Route("/o/{org}", func(r chi.Router) {
				r.Use(h.resolveOrg)
				r.Get("/", h.dashboard)
				r.Get("/projects", h.projects)
				r.Get("/projects/new", h.projectNewForm)
				r.Post("/projects/new", h.projectNew)
				r.Get("/projects/{project}", h.projectDetail)
				r.Post("/projects/{project}/delete", h.projectDelete)
				r.Get("/members", h.members)
				r.Post("/members/invite", h.memberInvite)
				r.Post("/members/{user}/role", h.memberRole)
				r.Post("/members/{user}/remove", h.memberRemove)
				r.Post("/invitations/{id}/revoke", h.invitationRevoke)
				r.Get("/tokens", h.tokens)
				r.Post("/tokens", h.tokenCreate)
				r.Post("/tokens/{id}/revoke", h.tokenRevoke)
				r.Get("/audit", h.audit)
			})
		})
	})
}

// --- rendering helpers ---

func (h *Handler) page(r *http.Request, titleKey, nav string) *ui.Page {
	ctx := r.Context()
	p := &ui.Page{Nav: nav, CSRF: server.CSRFTokenFrom(ctx), Path: safeNext(r.URL.RequestURI()), Version: version.Version}
	inst, _ := h.Svc.Instance(ctx)
	p.Instance = inst.Name
	if p.Instance == "" {
		p.Instance = "scanX"
	}
	p.User = auth.PrincipalFrom(ctx)
	userLocale := ""
	if p.User != nil {
		userLocale = p.User.Locale
		p.Orgs, _ = h.Svc.ListMyOrgs(ctx, p.User)
	}
	p.Lang = i18n.Detect(r, userLocale, langCookie, inst.DefaultLocale)
	if titleKey != "" {
		p.Title = p.T(titleKey)
	}
	if o, ok := ctx.Value(orgKey{}).(*service.OrgCtx); ok {
		p.Org = o
	}
	if msg := r.URL.Query().Get("msg"); msg != "" && i18n.Has(msg) && strings.HasPrefix(msg, "flash.") {
		p.Flash, p.FlashKind = msg, "ok"
	}
	return p
}

func render(w http.ResponseWriter, r *http.Request, status int, c templ.Component) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if err := c.Render(r.Context(), w); err != nil {
		slog.ErrorContext(r.Context(), "render", "err", err)
	}
}

func (h *Handler) errorPage(w http.ResponseWriter, r *http.Request, status int) {
	p := h.page(r, "", "")
	switch status {
	case http.StatusForbidden:
		render(w, r, status, ui.ErrorPage(p, status, "err.forbidden_title", "err.forbidden"))
	case http.StatusNotFound:
		render(w, r, status, ui.ErrorPage(p, status, "err.not_found_title", "err.not_found"))
	default:
		render(w, r, status, ui.ErrorPage(p, status, "err.internal_title", "err.internal"))
	}
}

// fail maps a service error to an error page (for non-form actions).
func (h *Handler) fail(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, service.ErrNotFound):
		h.errorPage(w, r, http.StatusNotFound)
	case errors.Is(err, service.ErrForbidden):
		h.errorPage(w, r, http.StatusForbidden)
	default:
		slog.ErrorContext(r.Context(), "web error", "err", err)
		h.errorPage(w, r, http.StatusInternalServerError)
	}
}

// formErr turns a service error into form errors. It returns false for
// unexpected errors, which the caller should pass to fail().
func formErr(f *ui.Form, err error) bool {
	var ve *service.ValidationError
	switch {
	case errors.As(err, &ve):
		f.Errors[ve.Field] = "val." + ve.Code
		f.Error = "err.check_fields"
	case errors.Is(err, service.ErrInvalidCredentials), errors.Is(err, service.ErrUnauthorized):
		f.Error = "err.invalid_credentials"
	case errors.Is(err, service.ErrRateLimited):
		f.Error = "err.rate_limited"
	case errors.Is(err, service.ErrConflict):
		f.Error = "err.conflict"
	case errors.Is(err, service.ErrLastOwner):
		f.Error = "err.last_owner"
	case errors.Is(err, service.ErrForbidden):
		f.Error = "err.forbidden_action"
	case errors.Is(err, service.ErrNotFound):
		f.Error = "err.user_not_found"
	default:
		return false
	}
	return true
}

func formFrom(r *http.Request, keys ...string) *ui.Form {
	f := ui.NewForm()
	for _, k := range keys {
		f.Values[k] = strings.TrimSpace(r.PostFormValue(k))
	}
	return f
}

// redirect issues a See Other with an optional flash key.
func redirect(w http.ResponseWriter, r *http.Request, to, flash string) {
	if flash != "" {
		sep := "?"
		if strings.Contains(to, "?") {
			sep = "&"
		}
		to += sep + "msg=" + url.QueryEscape(flash)
	}
	http.Redirect(w, r, safeNext(to), http.StatusSeeOther) //nolint:gosec // safeNext allows only same-site relative paths
}

// safeNext allows only same-site relative paths (open-redirect protection).
func safeNext(next string) string {
	if next == "" || !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") || strings.HasPrefix(next, "/\\") || strings.ContainsAny(next, "\r\n") {
		return "/"
	}
	return next
}

func qrDataURI(content string) string {
	code, err := qr.Encode(content, qr.M)
	if err != nil {
		return ""
	}
	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(code.PNG())
}

func (h *Handler) setLang(w http.ResponseWriter, r *http.Request) {
	lang := chi.URLParam(r, "lang")
	if i18n.Valid(lang) {
		http.SetCookie(w, &http.Cookie{ //nolint:gosec // Secure follows the deployment (HTTPS in production)
			Name: langCookie, Value: lang, Path: "/", MaxAge: 365 * 24 * 3600, SameSite: http.SameSiteLaxMode, Secure: h.Cookies.Secure, HttpOnly: true})
	}
	http.Redirect(w, r, safeNext(r.URL.Query().Get("next")), http.StatusSeeOther) //nolint:gosec // safeNext allows only same-site relative paths
}

// --- gates ---

func (h *Handler) isSetupDone(ctx context.Context) bool {
	if h.setupDone.Load() {
		return true
	}
	st, err := h.Svc.SetupState(ctx)
	if err == nil && st.Completed {
		h.setupDone.Store(true)
		return true
	}
	return false
}

func (h *Handler) setupGate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		done := h.isSetupDone(r.Context())
		inSetup := r.URL.Path == "/setup" || strings.HasPrefix(r.URL.Path, "/setup/")
		switch {
		case !done && !inSetup:
			http.Redirect(w, r, "/setup", http.StatusSeeOther)
		case done && inSetup:
			h.errorPage(w, r, http.StatusNotFound)
		default:
			next.ServeHTTP(w, r)
		}
	})
}

func (h *Handler) requireLogin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if auth.PrincipalFrom(r.Context()) == nil {
			if s := server.SessionFrom(r.Context()); s != nil && s.MFAPending {
				http.Redirect(w, r, "/login/2fa", http.StatusSeeOther)
				return
			}
			http.Redirect(w, r, "/login?next="+url.QueryEscape(safeNext(r.URL.RequestURI())), http.StatusSeeOther)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// enforce2FA keeps administrators without 2FA on the account page.
func (h *Handler) enforce2FA(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s := server.SessionFrom(r.Context())
		if s != nil && s.NeedsTOTPEnrollment(h.Require2FA) && !strings.HasPrefix(r.URL.Path, "/account") {
			http.Redirect(w, r, "/account", http.StatusSeeOther)
			return
		}
		next.ServeHTTP(w, r)
	})
}

type orgKey struct{}

func (h *Handler) resolveOrg(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		o, err := h.Svc.ResolveOrg(r.Context(), auth.PrincipalFrom(r.Context()), chi.URLParam(r, "org"))
		if err != nil {
			h.fail(w, r, err)
			return
		}
		if s := server.SessionFrom(r.Context()); s != nil && (s.ActiveOrgID == nil || *s.ActiveOrgID != o.Org.ID) {
			_ = h.Svc.SetActiveOrg(r.Context(), s, o.Org.ID)
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), orgKey{}, o)))
	})
}

func orgFrom(r *http.Request) *service.OrgCtx { return r.Context().Value(orgKey{}).(*service.OrgCtx) }

func pathID(r *http.Request, name string) (uuid.UUID, bool) {
	id, err := uuid.Parse(chi.URLParam(r, name))
	return id, err == nil
}

func atoi(s string, def int) int {
	n, err := strconv.Atoi(s)
	if err != nil {
		return def
	}
	return n
}

func (h *Handler) setSession(w http.ResponseWriter, res *service.LoginResult) {
	h.Cookies.Set(w, h.Cookies.Session, res.SessionToken, time.Until(res.ExpiresAt))
}
