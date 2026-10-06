// Package logging configures the process-wide slog logger and redacts
// sensitive attributes so secrets never reach log output.
package logging

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"
)

const redacted = "[REDACTED]"

// sensitiveKeyParts: an attribute whose (lower-cased) key contains any of
// these substrings has its value replaced, whatever its type.
var sensitiveKeyParts = []string{
	"password", "passwd", "secret", "token", "authorization", "cookie",
	"private_key", "privatekey", "api_key", "apikey", "master_key", "session_key",
	"credential", "dsn", "database_url",
}

// IsSensitiveKey reports whether a log attribute key must be redacted.
func IsSensitiveKey(key string) bool {
	k := strings.ToLower(key)
	for _, p := range sensitiveKeyParts {
		if strings.Contains(k, p) {
			return true
		}
	}
	return false
}

// New builds a logger writing to w. level is debug|info|warn|error, format is
// json|text.
func New(w io.Writer, level, format string) (*slog.Logger, error) {
	var lv slog.Level
	if err := lv.UnmarshalText([]byte(level)); err != nil {
		return nil, fmt.Errorf("logging: invalid level %q", level)
	}
	opts := &slog.HandlerOptions{Level: lv, ReplaceAttr: redact}
	var h slog.Handler
	switch format {
	case "json":
		h = slog.NewJSONHandler(w, opts)
	case "text":
		h = slog.NewTextHandler(w, opts)
	default:
		return nil, fmt.Errorf("logging: invalid format %q", format)
	}
	return slog.New(contextHandler{h}), nil
}

func redact(_ []string, a slog.Attr) slog.Attr {
	if a.Value.Kind() != slog.KindGroup && IsSensitiveKey(a.Key) {
		return slog.String(a.Key, redacted)
	}
	return a
}

type ctxKey struct{}

// WithAttrs returns a context carrying attributes (request_id, org_id,
// scan_id ...) that every log record made with that context will include.
func WithAttrs(ctx context.Context, attrs ...slog.Attr) context.Context {
	prev, _ := ctx.Value(ctxKey{}).([]slog.Attr)
	merged := make([]slog.Attr, 0, len(prev)+len(attrs))
	merged = append(merged, prev...)
	merged = append(merged, attrs...)
	return context.WithValue(ctx, ctxKey{}, merged)
}

// contextHandler adds attributes stored with WithAttrs to each record.
type contextHandler struct{ slog.Handler }

func (h contextHandler) Handle(ctx context.Context, r slog.Record) error {
	if attrs, ok := ctx.Value(ctxKey{}).([]slog.Attr); ok {
		r.AddAttrs(attrs...)
	}
	return h.Handler.Handle(ctx, r)
}

func (h contextHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return contextHandler{h.Handler.WithAttrs(attrs)}
}

func (h contextHandler) WithGroup(name string) slog.Handler {
	return contextHandler{h.Handler.WithGroup(name)}
}
