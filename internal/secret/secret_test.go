package secret

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

const fake = "FAKE-super-secret-value"

func TestSecretNeverPrinted(t *testing.T) {
	s := Secret(fake)
	outputs := []string{
		s.String(),
		fmt.Sprintf("%v", s),
		fmt.Sprintf("%s", s), //nolint:staticcheck // exercising the %s verb is the point
		fmt.Sprintf("%+v", s),
		fmt.Sprintf("%#v", s),
		fmt.Sprint(struct{ S Secret }{s}),
	}
	for _, o := range outputs {
		if strings.Contains(o, fake) {
			t.Fatalf("secret leaked in %q", o)
		}
	}
	j, err := json.Marshal(struct{ S Secret }{s})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(j, []byte(fake)) {
		t.Fatalf("secret leaked in json %s", j)
	}
	var buf bytes.Buffer
	slog.New(slog.NewJSONHandler(&buf, nil)).Info("x", "s", s)
	if strings.Contains(buf.String(), fake) {
		t.Fatalf("secret leaked in log %s", buf.String())
	}
}

func TestSecretRevealAndUnmarshal(t *testing.T) {
	var s Secret
	if !s.IsZero() {
		t.Fatal("zero value should be empty")
	}
	if err := s.UnmarshalText([]byte(fake)); err != nil {
		t.Fatal(err)
	}
	if s.Reveal() != fake {
		t.Fatalf("Reveal = %q", s.Reveal())
	}
}
