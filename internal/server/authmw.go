package server

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/ininia/scanx/internal/auth"
	"github.com/ininia/scanx/internal/service"
)

// Cookies holds the cookie names and flags. With HTTPS the __Host- prefix
// pins cookies to this exact origin (Secure, Path=/, no Domain).
type Cookies struct {
	Secure  bool
	Session string
	CSRF    string
	Setup   string
}

// NewCookies picks cookie names for the deployment.
func NewCookies(secure bool) Cookies {
	if secure {
		return Cookies{Secure: true, Session: "__Host-scanx_session", CSRF: "__Host-scanx_csrf", Setup: "__Host-scanx_setup"}
	}
	return Cookies{Session: "scanx_session", CSRF: "scanx_csrf", Setup: "scanx_setup"}
}

// Set writes a cookie with safe defaults.
func (c Cookies) Set(w http.ResponseWriter, name, value string, maxAge time.Duration) {
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // HttpOnly+SameSite always; Secure whenever served over HTTPS
		Name: name, Value: value, Path: "/", HttpOnly: true, Secure: c.Secure,
		SameSite: http.SameSiteLaxMode, MaxAge: int(maxAge.Seconds()),
	})
}

// Clear deletes a cookie.
func (c Cookies) Clear(w http.ResponseWriter, name string) {
	//nolint:gosec // deletion cookie; same flags as Set
	http.SetCookie(w, &http.Cookie{Name: name, Value: "", Path: "/", HttpOnly: true, Secure: c.Secure, SameSite: http.SameSiteLaxMode, MaxAge: -1})
}

type sessionKey struct{}

// SessionFrom returns the browser session (nil for anonymous or token calls).
func SessionFrom(ctx context.Context) *service.Session {
	s, _ := ctx.Value(sessionKey{}).(*service.Session)
	return s
}

// ClientIP returns the client address. nginx overwrites X-Real-IP with the
// connection address, and the app is only reachable through nginx.
func ClientIP(r *http.Request) string {
	if ip := strings.TrimSpace(r.Header.Get("X-Real-IP")); ip != "" && net.ParseIP(ip) != nil {
		return ip
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// MetaFrom builds audit metadata for a request.
func MetaFrom(r *http.Request) service.Meta {
	return service.Meta{IP: ClientIP(r), UserAgent: r.UserAgent()}
}

// Authenticate resolves a Bearer token or session cookie into a principal
// stored in the context. It never rejects requests by itself; handlers
// decide what they require. MFA-pending sessions only reach /login/2fa.
func Authenticate(svc *service.Service, cookies Cookies) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
				p, err := svc.AuthenticateToken(ctx, strings.TrimSpace(strings.TrimPrefix(h, "Bearer ")))
				if err != nil {
					WriteError(w, r, http.StatusUnauthorized, "unauthorized", "Invalid or expired token")
					return
				}
				next.ServeHTTP(w, r.WithContext(auth.WithPrincipal(ctx, p)))
				return
			}
			if c, err := r.Cookie(cookies.Session); err == nil && c.Value != "" {
				sess, err := svc.Authenticate(ctx, c.Value)
				switch {
				case err == nil:
					ctx = context.WithValue(ctx, sessionKey{}, sess)
					if !sess.MFAPending {
						ctx = auth.WithPrincipal(ctx, sess.Principal)
					}
				case errors.Is(err, service.ErrUnauthorized):
					cookies.Clear(w, cookies.Session)
				}
			}
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// CSRF protects cookie-authenticated state-changing requests with two
// independent checks (spec §5.3): the Fetch-Metadata/Origin based
// http.CrossOriginProtection, and an HMAC-bound double-submit token sent in
// the "csrf_token" form field or the X-CSRF-Token header. Bearer-token
// requests carry no ambient credentials and are exempt.
func CSRF(key []byte, cookies Cookies) func(http.Handler) http.Handler {
	cop := http.NewCrossOriginProtection()
	return func(next http.Handler) http.Handler {
		checked := cop.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(w, r)
		}))
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasPrefix(r.URL.Path, "/api/v1/hooks/") {
				// Git provider webhooks: authenticated by their HMAC
				// signature / token, never by cookies.
				next.ServeHTTP(w, r)
				return
			}
			seed := ""
			if c, err := r.Cookie(cookies.CSRF); err == nil {
				seed = c.Value
			}
			if seed == "" {
				var err error
				if seed, err = auth.NewCSRFSeed(); err != nil {
					WriteError(w, r, http.StatusInternalServerError, "internal", "Internal server error")
					return
				}
				cookies.Set(w, cookies.CSRF, seed, 0)
			}
			r = r.WithContext(context.WithValue(r.Context(), csrfKey{}, auth.CSRFToken(key, seed)))
			switch r.Method {
			case http.MethodGet, http.MethodHead, http.MethodOptions:
				next.ServeHTTP(w, r)
				return
			}
			if strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
				next.ServeHTTP(w, r)
				return
			}
			if r.URL.Path == "/api/v1/auth/login" {
				// Scripted clients log in without a prior page load; browsers
				// are still covered by the cross-origin check.
				checked.ServeHTTP(w, r)
				return
			}
			tok := r.Header.Get("X-CSRF-Token")
			if tok == "" {
				tok = r.PostFormValue("csrf_token")
			}
			if !auth.VerifyCSRF(key, seed, tok) {
				WriteError(w, r, http.StatusForbidden, "csrf", "Invalid or missing CSRF token. Reload the page and try again.")
				return
			}
			checked.ServeHTTP(w, r)
		})
	}
}

type csrfKey struct{}

// CSRFTokenFrom returns the token to embed in forms for this request.
func CSRFTokenFrom(ctx context.Context) string {
	t, _ := ctx.Value(csrfKey{}).(string)
	return t
}
