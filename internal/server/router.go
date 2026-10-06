// Package server builds the HTTP handler tree: middleware, health endpoints
// and (in later phases) the REST API, webhooks and web UI.
package server

import (
	"net/http"

	"github.com/go-chi/chi/v5"
)

// Options configures the router.
type Options struct {
	// HSTS enables Strict-Transport-Security (set when BaseURL is https).
	HSTS bool
	// ReadyChecks are evaluated by /health/ready.
	ReadyChecks []Check
}

// New returns the root handler.
func New(opts Options) http.Handler {
	r := chi.NewRouter()
	r.Use(RequestID, Recover, AccessLog, SecurityHeaders(opts.HSTS))

	health := func(r chi.Router) {
		r.Get("/live", liveHandler)
		r.Get("/ready", readyHandler(opts.ReadyChecks))
	}
	r.Route("/health", health)
	r.Route("/api/v1", func(r chi.Router) {
		r.Route("/health", health)
		r.NotFound(notFound)
		r.MethodNotAllowed(methodNotAllowed)
	})
	r.NotFound(notFound)
	r.MethodNotAllowed(methodNotAllowed)
	return r
}

func notFound(w http.ResponseWriter, r *http.Request) {
	WriteError(w, r, http.StatusNotFound, "not_found", "Resource not found")
}

func methodNotAllowed(w http.ResponseWriter, r *http.Request) {
	WriteError(w, r, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
}
