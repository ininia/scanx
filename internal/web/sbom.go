package web

import (
	"encoding/csv"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/ininia/scanx/internal/ui"
)

func (h *Handler) mountSBOM(r chi.Router) {
	r.Get("/sbom", h.sbom)
	r.Post("/sbom/check", h.sbomCheck)
	r.Get("/sbom/export/{what}", h.sbomExport)
}

func (h *Handler) sbom(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	v, err := h.Svc.SBOMOverview(r.Context(), orgFrom(r), q.Get("q"))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	tab := q.Get("tab")
	switch tab {
	case "components", "licenses", "resolved":
	default:
		tab = "vulns"
	}
	if v.Query != "" {
		tab = "components"
	}
	render(w, r, http.StatusOK, ui.SBOM(h.page(r, "sbom.title", "sbom"), v, tab))
}

func (h *Handler) sbomCheck(w http.ResponseWriter, r *http.Request) {
	if err := h.Svc.RequestVulnCheck(r.Context(), orgFrom(r)); err != nil {
		h.fail(w, r, err)
		return
	}
	redirect(w, r, "/o/"+orgFrom(r).Org.Slug+"/sbom", "flash.sbom_checking")
}

func (h *Handler) sbomExport(w http.ResponseWriter, r *http.Request) {
	o := orgFrom(r)
	name := "scanx-" + o.Org.Slug + "-" + chi.URLParam(r, "what") + "-" + time.Now().Format("20060102") + ".csv"
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	switch chi.URLParam(r, "what") {
	case "inventory":
		rows, err := h.Svc.SBOMInventory(r.Context(), o)
		if err != nil {
			h.fail(w, r, err)
			return
		}
		w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
		_, _ = w.Write([]byte("\xef\xbb\xbf"))
		cw := csv.NewWriter(w)
		_ = cw.Write([]string{"project", "ecosystem", "package", "version", "licenses", "purl"})
		for _, c := range rows {
			_ = cw.Write([]string{csvSafe(c.ProjectName), c.Ecosystem, csvSafe(c.Name), csvSafe(c.Version), strings.Join(c.Licenses, " "), csvSafe(c.Purl)})
		}
		cw.Flush()
	case "vulns":
		v, err := h.Svc.SBOMOverview(r.Context(), o, "")
		if err != nil {
			h.fail(w, r, err)
			return
		}
		w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
		_, _ = w.Write([]byte("\xef\xbb\xbf"))
		cw := csv.NewWriter(w)
		_ = cw.Write([]string{"severity", "advisory", "cve", "project", "ecosystem", "package", "version", "fixed_version", "summary", "first_seen"})
		for _, m := range v.Open {
			_ = cw.Write([]string{
				m.Severity, m.VulnID, m.Cve, csvSafe(m.ProjectName), m.Ecosystem, csvSafe(m.Name), csvSafe(m.Version),
				csvSafe(m.FixedVersion), csvSafe(m.Summary), m.FirstSeenAt.Format(time.RFC3339),
			})
		}
		cw.Flush()
	default:
		h.errorPage(w, r, http.StatusNotFound)
	}
}
