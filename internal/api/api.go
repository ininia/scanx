// Package api implements the JSON REST API under /api/v1 (spec §9). The
// contract lives in api/openapi.yaml and is enforced by contract tests.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/ininia/scanx/internal/auth"
	"github.com/ininia/scanx/internal/server"
	"github.com/ininia/scanx/internal/service"
	"github.com/ininia/scanx/internal/store/db"
)

// Handler serves the API.
type Handler struct {
	Svc     *service.Service
	Cookies server.Cookies
}

// Mount registers the routes.
func (h *Handler) Mount(r chi.Router) {
	r.Post("/auth/login", h.login)
	r.Post("/auth/mfa", h.mfa)
	r.Group(func(r chi.Router) {
		r.Use(requireAuth)
		r.Post("/auth/logout", h.logout)
		r.Get("/me", h.me)
		r.Get("/orgs", h.listOrgs)
		r.Post("/orgs", h.createOrg)
		r.Route("/orgs/{org}", func(r chi.Router) {
			r.Use(h.resolveOrg)
			r.Get("/", h.getOrg)
			r.Patch("/", h.updateOrg)
			r.Get("/members", h.listMembers)
			r.Post("/members", h.addMember)
			r.Patch("/members/{user}", h.updateMember)
			r.Delete("/members/{user}", h.removeMember)
			r.Get("/invitations", h.listInvitations)
			r.Post("/invitations", h.createInvitation)
			r.Delete("/invitations/{id}", h.deleteInvitation)
			r.Get("/tokens", h.listTokens)
			r.Post("/tokens", h.createToken)
			r.Delete("/tokens/{id}", h.deleteToken)
			r.Get("/audit", h.listAudit)
			r.Get("/projects", h.listProjects)
			r.Post("/projects", h.createProject)
			r.Get("/projects/{project}", h.getProject)
			r.Patch("/projects/{project}", h.updateProject)
			r.Delete("/projects/{project}", h.deleteProject)
		})
	})
}

func requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if auth.PrincipalFrom(r.Context()) == nil {
			server.WriteError(w, r, http.StatusUnauthorized, "unauthorized", "Authentication required")
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
			writeErr(w, r, err)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), orgKey{}, o)))
	})
}

func orgFrom(r *http.Request) *service.OrgCtx { return r.Context().Value(orgKey{}).(*service.OrgCtx) }

// writeErr maps service errors to the spec §9 error envelope. Internal
// errors are logged with the request id and never shown to the client.
func writeErr(w http.ResponseWriter, r *http.Request, err error) {
	var ve *service.ValidationError
	switch {
	case errors.As(err, &ve):
		server.WriteJSON(w, r, http.StatusUnprocessableEntity, map[string]any{"error": map[string]any{
			"code": "validation", "message": "Invalid input", "field": ve.Field, "reason": ve.Code, "request_id": server.RequestIDFrom(r.Context()),
		}})
	case errors.Is(err, service.ErrNotFound), errors.Is(err, service.ErrSetupCompleted):
		server.WriteError(w, r, http.StatusNotFound, "not_found", "Resource not found")
	case errors.Is(err, service.ErrForbidden):
		server.WriteError(w, r, http.StatusForbidden, "forbidden", "You do not have permission for this action")
	case errors.Is(err, service.ErrUnauthorized), errors.Is(err, service.ErrInvalidCredentials):
		server.WriteError(w, r, http.StatusUnauthorized, "unauthorized", "Invalid credentials")
	case errors.Is(err, service.ErrRateLimited):
		w.Header().Set("Retry-After", "60")
		server.WriteError(w, r, http.StatusTooManyRequests, "rate_limited", "Too many attempts, try again later")
	case errors.Is(err, service.ErrConflict):
		server.WriteError(w, r, http.StatusConflict, "conflict", "Resource already exists")
	case errors.Is(err, service.ErrLastOwner):
		server.WriteError(w, r, http.StatusConflict, "last_owner", "An organization needs at least one owner")
	default:
		slog.ErrorContext(r.Context(), "api error", "err", err)
		server.WriteError(w, r, http.StatusInternalServerError, "internal", "Internal server error")
	}
}

// decode reads a JSON body (max 1 MiB, unknown fields rejected).
func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		server.WriteError(w, r, http.StatusBadRequest, "bad_request", "Malformed JSON body")
		return false
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		server.WriteError(w, r, http.StatusBadRequest, "bad_request", "Unexpected data after JSON body")
		return false
	}
	return true
}

func pathUUID(w http.ResponseWriter, r *http.Request, name string) (uuid.UUID, bool) {
	id, err := uuid.Parse(chi.URLParam(r, name))
	if err != nil {
		server.WriteError(w, r, http.StatusNotFound, "not_found", "Resource not found")
		return uuid.Nil, false
	}
	return id, true
}

func paging(r *http.Request) (page, perPage int) {
	page, _ = strconv.Atoi(r.URL.Query().Get("page"))
	perPage, _ = strconv.Atoi(r.URL.Query().Get("per_page"))
	if page < 1 {
		page = 1
	}
	if perPage < 1 || perPage > 200 {
		perPage = 50
	}
	return page, perPage
}

// Page is the spec §9 pagination envelope.
type Page[T any] struct {
	Items   []T   `json:"items"`
	Page    int   `json:"page"`
	PerPage int   `json:"per_page"`
	Total   int64 `json:"total"`
}

// --- auth ---

type loginReq struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (h *Handler) login(w http.ResponseWriter, r *http.Request) {
	var req loginReq
	if !decode(w, r, &req) {
		return
	}
	res, err := h.Svc.Login(r.Context(), req.Email, req.Password, server.MetaFrom(r))
	if err != nil {
		writeErr(w, r, err)
		return
	}
	h.Cookies.Set(w, h.Cookies.Session, res.SessionToken, time.Until(res.ExpiresAt))
	server.WriteJSON(w, r, http.StatusOK, map[string]any{"mfa_required": res.MFAPending})
}

type mfaReq struct {
	Code string `json:"code"`
}

func (h *Handler) mfa(w http.ResponseWriter, r *http.Request) {
	var req mfaReq
	if !decode(w, r, &req) {
		return
	}
	c, err := r.Cookie(h.Cookies.Session)
	if err != nil {
		writeErr(w, r, service.ErrUnauthorized)
		return
	}
	res, err := h.Svc.VerifyMFA(r.Context(), c.Value, req.Code, server.MetaFrom(r))
	if err != nil {
		writeErr(w, r, err)
		return
	}
	h.Cookies.Set(w, h.Cookies.Session, res.SessionToken, time.Until(res.ExpiresAt))
	server.WriteJSON(w, r, http.StatusOK, map[string]any{"mfa_required": false})
}

func (h *Handler) logout(w http.ResponseWriter, r *http.Request) {
	if sess := server.SessionFrom(r.Context()); sess != nil {
		if err := h.Svc.Logout(r.Context(), sess, server.MetaFrom(r)); err != nil {
			writeErr(w, r, err)
			return
		}
	}
	h.Cookies.Clear(w, h.Cookies.Session)
	w.WriteHeader(http.StatusNoContent)
}

// --- me / orgs ---

type meResp struct {
	ID           uuid.UUID `json:"id"`
	Email        string    `json:"email"`
	Name         string    `json:"name"`
	IsSuperadmin bool      `json:"is_superadmin"`
	Locale       string    `json:"locale"`
	ViaToken     bool      `json:"via_token"`
}

func (h *Handler) me(w http.ResponseWriter, r *http.Request) {
	p := auth.PrincipalFrom(r.Context())
	server.WriteJSON(w, r, http.StatusOK, meResp{ID: p.UserID, Email: p.Email, Name: p.Name, IsSuperadmin: p.IsSuperadmin, Locale: p.Locale, ViaToken: p.ViaToken()})
}

type orgResp struct {
	ID        uuid.UUID `json:"id"`
	Name      string    `json:"name"`
	Slug      string    `json:"slug"`
	Role      string    `json:"role,omitempty"`
	CreatedAt time.Time `json:"created_at,omitempty"`
}

func (h *Handler) listOrgs(w http.ResponseWriter, r *http.Request) {
	orgs, err := h.Svc.ListMyOrgs(r.Context(), auth.PrincipalFrom(r.Context()))
	if err != nil {
		writeErr(w, r, err)
		return
	}
	out := make([]orgResp, 0, len(orgs))
	for _, o := range orgs {
		out = append(out, orgResp{ID: o.ID, Name: o.Name, Slug: o.Slug, Role: string(o.Role)})
	}
	server.WriteJSON(w, r, http.StatusOK, Page[orgResp]{Items: out, Page: 1, PerPage: len(out), Total: int64(len(out))})
}

type createOrgReq struct {
	Name string `json:"name"`
	Slug string `json:"slug"`
}

func (h *Handler) createOrg(w http.ResponseWriter, r *http.Request) {
	var req createOrgReq
	if !decode(w, r, &req) {
		return
	}
	org, err := h.Svc.CreateOrg(r.Context(), auth.PrincipalFrom(r.Context()), req.Name, req.Slug, server.MetaFrom(r))
	if err != nil {
		writeErr(w, r, err)
		return
	}
	server.WriteJSON(w, r, http.StatusCreated, orgResp{ID: org.ID, Name: org.Name, Slug: org.Slug, Role: "owner", CreatedAt: org.CreatedAt})
}

func (h *Handler) getOrg(w http.ResponseWriter, r *http.Request) {
	o := orgFrom(r)
	server.WriteJSON(w, r, http.StatusOK, orgResp{ID: o.Org.ID, Name: o.Org.Name, Slug: o.Org.Slug, Role: string(o.Role), CreatedAt: o.Org.CreatedAt})
}

type updateOrgReq struct {
	Name string `json:"name"`
}

func (h *Handler) updateOrg(w http.ResponseWriter, r *http.Request) {
	var req updateOrgReq
	if !decode(w, r, &req) {
		return
	}
	o := orgFrom(r)
	org, err := h.Svc.UpdateOrg(r.Context(), o, req.Name, server.MetaFrom(r))
	if err != nil {
		writeErr(w, r, err)
		return
	}
	server.WriteJSON(w, r, http.StatusOK, orgResp{ID: org.ID, Name: org.Name, Slug: org.Slug, Role: string(o.Role), CreatedAt: org.CreatedAt})
}

// --- members ---

type memberResp struct {
	UserID      uuid.UUID  `json:"user_id"`
	Email       string     `json:"email"`
	Name        string     `json:"name"`
	Role        string     `json:"role"`
	TOTPEnabled bool       `json:"totp_enabled"`
	LastLoginAt *time.Time `json:"last_login_at"`
}

func (h *Handler) listMembers(w http.ResponseWriter, r *http.Request) {
	rows, err := h.Svc.ListMembers(r.Context(), orgFrom(r))
	if err != nil {
		writeErr(w, r, err)
		return
	}
	out := make([]memberResp, 0, len(rows))
	for _, m := range rows {
		out = append(out, memberResp{UserID: m.UserID, Email: m.Email, Name: m.Name, Role: m.Role, TOTPEnabled: m.TotpEnabled, LastLoginAt: m.LastLoginAt})
	}
	server.WriteJSON(w, r, http.StatusOK, Page[memberResp]{Items: out, Page: 1, PerPage: len(out), Total: int64(len(out))})
}

type memberReq struct {
	Email string `json:"email"`
	Role  string `json:"role"`
}

func (h *Handler) addMember(w http.ResponseWriter, r *http.Request) {
	var req memberReq
	if !decode(w, r, &req) {
		return
	}
	if err := h.Svc.AddExistingMember(r.Context(), orgFrom(r), req.Email, req.Role, server.MetaFrom(r)); err != nil {
		writeErr(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type roleReq struct {
	Role string `json:"role"`
}

func (h *Handler) updateMember(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "user")
	if !ok {
		return
	}
	var req roleReq
	if !decode(w, r, &req) {
		return
	}
	if err := h.Svc.UpdateMemberRole(r.Context(), orgFrom(r), id, req.Role, server.MetaFrom(r)); err != nil {
		writeErr(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) removeMember(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "user")
	if !ok {
		return
	}
	if err := h.Svc.RemoveMember(r.Context(), orgFrom(r), id, server.MetaFrom(r)); err != nil {
		writeErr(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- invitations ---

type invitationResp struct {
	ID        uuid.UUID `json:"id"`
	Email     string    `json:"email"`
	Role      string    `json:"role"`
	ExpiresAt time.Time `json:"expires_at"`
	Token     string    `json:"token,omitempty"` // only in the create response
}

func (h *Handler) listInvitations(w http.ResponseWriter, r *http.Request) {
	rows, err := h.Svc.ListInvitations(r.Context(), orgFrom(r))
	if err != nil {
		writeErr(w, r, err)
		return
	}
	out := make([]invitationResp, 0, len(rows))
	for _, i := range rows {
		out = append(out, invitationResp{ID: i.ID, Email: i.Email, Role: i.Role, ExpiresAt: i.ExpiresAt})
	}
	server.WriteJSON(w, r, http.StatusOK, Page[invitationResp]{Items: out, Page: 1, PerPage: len(out), Total: int64(len(out))})
}

func (h *Handler) createInvitation(w http.ResponseWriter, r *http.Request) {
	var req memberReq
	if !decode(w, r, &req) {
		return
	}
	inv, err := h.Svc.Invite(r.Context(), orgFrom(r), req.Email, req.Role, server.MetaFrom(r))
	if err != nil {
		writeErr(w, r, err)
		return
	}
	server.WriteJSON(w, r, http.StatusCreated, invitationResp{ID: inv.ID, Email: inv.Email, Role: inv.Role, ExpiresAt: inv.ExpiresAt, Token: inv.Token})
}

func (h *Handler) deleteInvitation(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	if err := h.Svc.RevokeInvitation(r.Context(), orgFrom(r), id, server.MetaFrom(r)); err != nil {
		writeErr(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- tokens ---

type tokenResp struct {
	ID         uuid.UUID  `json:"id"`
	Name       string     `json:"name"`
	Prefix     string     `json:"prefix"`
	Scopes     []string   `json:"scopes"`
	LastUsedAt *time.Time `json:"last_used_at"`
	ExpiresAt  *time.Time `json:"expires_at"`
	CreatedAt  time.Time  `json:"created_at"`
	Token      string     `json:"token,omitempty"` // only in the create response
}

func (h *Handler) listTokens(w http.ResponseWriter, r *http.Request) {
	rows, err := h.Svc.ListAPITokens(r.Context(), orgFrom(r))
	if err != nil {
		writeErr(w, r, err)
		return
	}
	out := make([]tokenResp, 0, len(rows))
	for _, t := range rows {
		out = append(out, tokenResp{ID: t.ID, Name: t.Name, Prefix: t.TokenPrefix, Scopes: t.Scopes, LastUsedAt: t.LastUsedAt, ExpiresAt: t.ExpiresAt, CreatedAt: t.CreatedAt})
	}
	server.WriteJSON(w, r, http.StatusOK, Page[tokenResp]{Items: out, Page: 1, PerPage: len(out), Total: int64(len(out))})
}

type tokenReq struct {
	Name          string   `json:"name"`
	Scopes        []string `json:"scopes"`
	ExpiresInDays int      `json:"expires_in_days"`
}

func (h *Handler) createToken(w http.ResponseWriter, r *http.Request) {
	var req tokenReq
	if !decode(w, r, &req) {
		return
	}
	t, err := h.Svc.CreateAPIToken(r.Context(), orgFrom(r), req.Name, req.Scopes, req.ExpiresInDays, server.MetaFrom(r))
	if err != nil {
		writeErr(w, r, err)
		return
	}
	server.WriteJSON(w, r, http.StatusCreated, tokenResp{ID: t.ID, Name: req.Name, Prefix: auth.TokenDisplayPrefix(t.Token), Scopes: req.Scopes, Token: t.Token, CreatedAt: time.Now().UTC()})
}

func (h *Handler) deleteToken(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	if err := h.Svc.RevokeAPIToken(r.Context(), orgFrom(r), id, server.MetaFrom(r)); err != nil {
		writeErr(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- audit ---

type auditResp struct {
	ID         uuid.UUID       `json:"id"`
	Action     string          `json:"action"`
	UserEmail  string          `json:"user_email"`
	TargetType string          `json:"target_type"`
	TargetID   string          `json:"target_id"`
	IP         string          `json:"ip"`
	Metadata   json.RawMessage `json:"metadata"`
	CreatedAt  time.Time       `json:"created_at"`
}

func (h *Handler) listAudit(w http.ResponseWriter, r *http.Request) {
	page, per := paging(r)
	rows, err := h.Svc.ListAudit(r.Context(), orgFrom(r), per, (page-1)*per)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	out := make([]auditResp, 0, len(rows))
	for _, a := range rows {
		out = append(out, auditResp{ID: a.ID, Action: a.Action, UserEmail: a.UserEmail, TargetType: a.TargetType, TargetID: a.TargetID, IP: a.Ip, Metadata: a.Metadata, CreatedAt: a.CreatedAt})
	}
	server.WriteJSON(w, r, http.StatusOK, Page[auditResp]{Items: out, Page: page, PerPage: per, Total: -1})
}

// --- projects ---

type projectResp struct {
	ID        uuid.UUID `json:"id"`
	Name      string    `json:"name"`
	Slug      string    `json:"slug"`
	RepoURL   string    `json:"repo_url"`
	Provider  string    `json:"provider"`
	AuthMode  string    `json:"auth_mode"`
	Branches  []string  `json:"branches"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func projectOut(p *db.Project) projectResp {
	return projectResp{ID: p.ID, Name: p.Name, Slug: p.Slug, RepoURL: p.RepoUrl, Provider: p.Provider, AuthMode: p.AuthMode, Branches: p.Branches, CreatedAt: p.CreatedAt, UpdatedAt: p.UpdatedAt}
}

func (h *Handler) listProjects(w http.ResponseWriter, r *http.Request) {
	page, per := paging(r)
	ps, total, err := h.Svc.ListProjects(r.Context(), orgFrom(r), page, per)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	out := make([]projectResp, 0, len(ps))
	for i := range ps {
		out = append(out, projectOut(&ps[i]))
	}
	server.WriteJSON(w, r, http.StatusOK, Page[projectResp]{Items: out, Page: page, PerPage: per, Total: total})
}

type projectReq struct {
	Name     string   `json:"name"`
	Slug     string   `json:"slug"`
	RepoURL  string   `json:"repo_url"`
	Provider string   `json:"provider"`
	Branches []string `json:"branches"`
}

func (h *Handler) createProject(w http.ResponseWriter, r *http.Request) {
	var req projectReq
	if !decode(w, r, &req) {
		return
	}
	p, err := h.Svc.CreateProject(r.Context(), orgFrom(r), service.ProjectInput(req), server.MetaFrom(r))
	if err != nil {
		writeErr(w, r, err)
		return
	}
	server.WriteJSON(w, r, http.StatusCreated, projectOut(p))
}

func (h *Handler) getProject(w http.ResponseWriter, r *http.Request) {
	p, err := h.Svc.GetProject(r.Context(), orgFrom(r), chi.URLParam(r, "project"))
	if err != nil {
		writeErr(w, r, err)
		return
	}
	server.WriteJSON(w, r, http.StatusOK, projectOut(p))
}

func (h *Handler) updateProject(w http.ResponseWriter, r *http.Request) {
	var req projectReq
	if !decode(w, r, &req) {
		return
	}
	p, err := h.Svc.UpdateProject(r.Context(), orgFrom(r), chi.URLParam(r, "project"), service.ProjectInput(req), server.MetaFrom(r))
	if err != nil {
		writeErr(w, r, err)
		return
	}
	server.WriteJSON(w, r, http.StatusOK, projectOut(p))
}

func (h *Handler) deleteProject(w http.ResponseWriter, r *http.Request) {
	if err := h.Svc.DeleteProject(r.Context(), orgFrom(r), chi.URLParam(r, "project"), server.MetaFrom(r)); err != nil {
		writeErr(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
