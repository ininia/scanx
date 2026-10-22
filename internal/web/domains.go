package web

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/ininia/scanx/internal/server"
	"github.com/ininia/scanx/internal/service"
	"github.com/ininia/scanx/internal/ui"
)

func (h *Handler) mountDomains(r chi.Router) {
	r.Get("/domains", h.domains)
	r.Post("/domains", h.domainCreate)
	r.Get("/domains/{id}", h.domainDetail)
	r.Post("/domains/{id}/check", h.domainCheck)
	r.Post("/domains/{id}/edit", h.domainEdit)
	r.Post("/domains/{id}/delete", h.domainDelete)
}

func (h *Handler) domainURL(r *http.Request, rest string) string {
	return "/o/" + orgFrom(r).Org.Slug + "/domains" + rest
}

func (h *Handler) renderDomains(w http.ResponseWriter, r *http.Request, f *ui.Form, status int) {
	list, err := h.Svc.ListDomains(r.Context(), orgFrom(r))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	render(w, r, status, ui.Domains(h.page(r, "tls.title", "domains"), list, f))
}

func (h *Handler) domains(w http.ResponseWriter, r *http.Request) {
	f := ui.NewForm()
	f.Values["schedule"] = "daily"
	h.renderDomains(w, r, f, http.StatusOK)
}

func (h *Handler) domainCreate(w http.ResponseWriter, r *http.Request) {
	f := formFrom(r, "host", "port", "label", "schedule")
	d, err := h.Svc.CreateDomain(r.Context(), orgFrom(r), service.DomainInput{
		Host: f.V("host"), Port: atoi(f.V("port"), 0), Label: f.V("label"), Schedule: f.V("schedule"), Enabled: true,
	}, server.MetaFrom(r))
	if err != nil {
		if !formErr(f, err) {
			h.fail(w, r, err)
			return
		}
		h.renderDomains(w, r, f, http.StatusUnprocessableEntity)
		return
	}
	redirect(w, r, h.domainURL(r, "/"+d.ID.String()), "flash.domain_created")
}

func (h *Handler) domainDetail(w http.ResponseWriter, r *http.Request) {
	d, err := h.Svc.GetDomain(r.Context(), orgFrom(r), chi.URLParam(r, "id"))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	render(w, r, http.StatusOK, ui.DomainDetail(h.page(r, "", "domains"), d))
}

func (h *Handler) domainCheck(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := h.Svc.CheckDomainNow(r.Context(), orgFrom(r), id); err != nil {
		h.fail(w, r, err)
		return
	}
	redirect(w, r, h.domainURL(r, "/"+id), "flash.domain_checking")
}

func (h *Handler) domainEdit(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	f := formFrom(r, "label", "schedule", "enabled")
	if err := h.Svc.UpdateDomain(r.Context(), orgFrom(r), id, service.DomainInput{
		Label: f.V("label"), Schedule: f.V("schedule"), Enabled: f.V("enabled") == "on",
	}, server.MetaFrom(r)); err != nil {
		h.fail(w, r, err)
		return
	}
	redirect(w, r, h.domainURL(r, "/"+id), "flash.saved")
}

func (h *Handler) domainDelete(w http.ResponseWriter, r *http.Request) {
	if err := h.Svc.DeleteDomain(r.Context(), orgFrom(r), chi.URLParam(r, "id"), server.MetaFrom(r)); err != nil {
		h.fail(w, r, err)
		return
	}
	redirect(w, r, h.domainURL(r, ""), "flash.deleted")
}
