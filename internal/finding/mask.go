package finding

import (
	"math"
	"regexp"
	"strings"
)

// MaskSecret keeps the first three characters of a secret and replaces the
// rest with "***" (spec §5.1). Short values are fully masked.
func MaskSecret(s string) string {
	r := []rune(s)
	if len(r) < 8 {
		return "***"
	}
	return string(r[:3]) + "***"
}

// tokenRe finds candidate secret tokens: long runs of key-like characters.
var tokenRe = regexp.MustCompile(`[A-Za-z0-9+/=_\-.~]{12,}`)

// MaskLine masks every high-entropy token in a line of text. It is applied to
// snippets of secret findings because the actual secret value is never known
// to scanX (tools run with redaction enabled).
func MaskLine(line string) string {
	return tokenRe.ReplaceAllStringFunc(line, func(tok string) string {
		if looksSecret(tok) {
			return MaskSecret(tok)
		}
		return tok
	})
}

// MaskText applies MaskLine to every line.
func MaskText(text string) string {
	lines := strings.Split(text, "\n")
	for i, l := range lines {
		lines[i] = MaskLine(l)
	}
	return strings.Join(lines, "\n")
}

// looksSecret reports whether a token is random-looking enough to be a
// credential: mixed character classes and Shannon entropy above 3.
func looksSecret(tok string) bool {
	var lower, upper, digit bool
	for _, c := range tok {
		switch {
		case c >= 'a' && c <= 'z':
			lower = true
		case c >= 'A' && c <= 'Z':
			upper = true
		case c >= '0' && c <= '9':
			digit = true
		}
	}
	classes := 0
	for _, b := range []bool{lower, upper, digit} {
		if b {
			classes++
		}
	}
	return classes >= 2 && shannon(tok) > 3.0
}

func shannon(s string) float64 {
	if s == "" {
		return 0
	}
	freq := map[rune]float64{}
	for _, c := range s {
		freq[c]++
	}
	n := float64(len([]rune(s)))
	var h float64
	for _, f := range freq {
		p := f / n
		h -= p * math.Log2(p)
	}
	return h
}
