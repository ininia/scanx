// Package server builds the HTTP handler tree: shared middleware, health
// endpoints, authentication/CSRF middleware and the JSON helpers used by the
// API and web packages, which mount themselves through Options.
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
	// API mounts routes under /api/v1 (after the health routes).
	API func(r chi.Router)
	// Web mounts the HTML UI at the root.
	Web func(r chi.Router)
	// Middleware runs for every request after the base middleware (e.g.
	// authentication, which must not run for health checks — it does not
	// matter functionally but keeps probes cheap).
	Middleware []func(http.Handler) http.Handler
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
	r.Route("/api/v1/health", health)

	r.Group(func(r chi.Router) {
		for _, mw := range opts.Middleware {
			r.Use(mw)
		}
		r.Route("/api/v1", func(r chi.Router) {
			if opts.API != nil {
				opts.API(r)
			}
			r.NotFound(notFound)
			r.MethodNotAllowed(methodNotAllowed)
		})
		if opts.Web != nil {
			opts.Web(r)
		}
	})
	if opts.Web == nil {
		r.NotFound(notFound)
		r.MethodNotAllowed(methodNotAllowed)
	}
	return r
}

func notFound(w http.ResponseWriter, r *http.Request) {
	WriteError(w, r, http.StatusNotFound, "not_found", "Resource not found")
}

func methodNotAllowed(w http.ResponseWriter, r *http.Request) {
	WriteError(w, r, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
}
