// Package i18n holds the UI texts in Turkish and English (spec §10).
package i18n

import (
	"fmt"
	"net/http"
	"strings"
)

// Supported languages.
const (
	TR = "tr"
	EN = "en"
)

var catalogs = map[string]map[string]string{TR: tr, EN: en}

// T translates key; extra args are applied with fmt.Sprintf. Unknown keys
// fall back to English, then to the key itself.
func T(lang, key string, args ...any) string {
	msg, ok := catalogs[lang][key]
	if !ok {
		if msg, ok = en[key]; !ok {
			msg = key
		}
	}
	if len(args) > 0 {
		return fmt.Sprintf(msg, args...)
	}
	return msg
}

// Has reports whether key exists (used to whitelist ?msg= flash keys).
func Has(key string) bool { _, ok := en[key]; return ok }

// Valid reports whether lang is supported.
func Valid(lang string) bool { _, ok := catalogs[lang]; return ok }

// Detect picks the language: user preference, then cookie, then the
// Accept-Language header, then the instance default.
func Detect(r *http.Request, userLocale, cookieName, def string) string {
	if Valid(userLocale) {
		return userLocale
	}
	if c, err := r.Cookie(cookieName); err == nil && Valid(c.Value) {
		return c.Value
	}
	for _, part := range strings.Split(r.Header.Get("Accept-Language"), ",") {
		tag := strings.ToLower(strings.TrimSpace(strings.SplitN(part, ";", 2)[0]))
		if len(tag) >= 2 && Valid(tag[:2]) {
			return tag[:2]
		}
	}
	if Valid(def) {
		return def
	}
	return TR
}

// Keys returns all keys of a language (tests).
func Keys(lang string) []string {
	out := make([]string, 0, len(catalogs[lang]))
	for k := range catalogs[lang] {
		out = append(out, k)
	}
	return out
}
