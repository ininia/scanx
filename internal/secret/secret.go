// Package secret provides a string type that never reveals its value when
// printed, formatted or logged.
package secret

import "log/slog"

const redacted = "[REDACTED]"

// Secret holds a sensitive value. Use Reveal to obtain the plain value at the
// last possible moment; every other representation is redacted.
type Secret string

// Reveal returns the plain value.
func (s Secret) Reveal() string { return string(s) }

// IsZero reports whether the secret is empty.
func (s Secret) IsZero() bool { return s == "" }

// String implements fmt.Stringer.
func (s Secret) String() string { return redacted }

// GoString implements fmt.GoStringer so %#v is redacted too.
func (s Secret) GoString() string { return redacted }

// LogValue implements slog.LogValuer.
func (s Secret) LogValue() slog.Value { return slog.StringValue(redacted) }

// MarshalText implements encoding.TextMarshaler (used by JSON/YAML encoders).
func (s Secret) MarshalText() ([]byte, error) { return []byte(redacted), nil }

// UnmarshalText implements encoding.TextUnmarshaler so env/config loaders can
// populate the value.
func (s *Secret) UnmarshalText(b []byte) error {
	*s = Secret(b)
	return nil
}
