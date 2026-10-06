package server

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/ininia/scanx/internal/version"
)

// Check is a named readiness probe (database, migrations, worker heartbeat...).
type Check struct {
	Name string
	Fn   func(ctx context.Context) error
}

type healthResponse struct {
	Status  string            `json:"status"`
	Version string            `json:"version"`
	Checks  map[string]string `json:"checks,omitempty"`
}

func liveHandler(w http.ResponseWriter, r *http.Request) {
	WriteJSON(w, r, http.StatusOK, healthResponse{Status: "ok", Version: version.Version})
}

// readyHandler runs all checks with a short timeout. Failure reasons are only
// logged; the response just says "fail" so internals are not exposed.
func readyHandler(checks []Check) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()
		resp := healthResponse{Status: "ok", Version: version.Version, Checks: map[string]string{}}
		status := http.StatusOK
		for _, c := range checks {
			if err := c.Fn(ctx); err != nil {
				slog.WarnContext(r.Context(), "readiness check failed", "check", c.Name, "err", err)
				resp.Checks[c.Name] = "fail"
				resp.Status = "fail"
				status = http.StatusServiceUnavailable
				continue
			}
			resp.Checks[c.Name] = "ok"
		}
		WriteJSON(w, r, status, resp)
	}
}
