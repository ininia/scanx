package ui

import (
	"strconv"
	"strings"
	"time"

	"github.com/ininia/scanx/internal/tlscheck"
)

// DaysLeft is the number of days until t (negative when past).
func DaysLeft(t *time.Time) int {
	if t == nil {
		return 0
	}
	return int(time.Until(*t).Hours() / 24)
}

// ExpiryClass colours a certificate expiry badge.
func ExpiryClass(t *time.Time) string {
	if t == nil {
		return "sbadge off"
	}
	switch d := DaysLeft(t); {
	case d <= 14:
		return "sbadge bad"
	case d <= 30:
		return "sbadge warn"
	}
	return "sbadge ok"
}

// ExpiryText is "45 days" / "expired".
func (p *Page) ExpiryText(t *time.Time) string {
	if t == nil {
		return "—"
	}
	if d := DaysLeft(t); d >= 0 {
		return p.T("tls.days_left", d)
	}
	return p.T("tls.expired")
}

// TLSMessage renders a TLS finding.
func (p *Page) TLSMessage(f tlscheck.Finding) string {
	args := make([]any, 0, len(f.Params))
	for _, a := range f.Params {
		args = append(args, a)
	}
	msg := p.T("tlsrule."+f.RuleID+".msg", args...)
	if strings.Contains(msg, "%!") {
		return p.T("tlsrule." + f.RuleID + ".title")
	}
	return msg
}

// Versions lists the supported protocol versions, newest first.
func Versions(r *tlscheck.Result) []string {
	var out []string
	for _, v := range []string{"TLS 1.3", "TLS 1.2", "TLS 1.1", "TLS 1.0"} {
		if r.Protocols[v] {
			out = append(out, v)
		}
	}
	return out
}

// VersionClass styles a protocol chip.
func VersionClass(v string) string {
	if v == "TLS 1.0" || v == "TLS 1.1" {
		return "chip bad"
	}
	return "chip"
}

// SortedTLSFindings orders findings worst first.
func SortedTLSFindings(fs []tlscheck.Finding) []tlscheck.Finding {
	rank := map[string]int{"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
	out := append([]tlscheck.Finding(nil), fs...)
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && rank[out[j].Severity] > rank[out[j-1].Severity]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

// HeaderRows is the header table of a check (present first).
var HeaderRows = []string{
	"Strict-Transport-Security", "Content-Security-Policy", "X-Content-Type-Options", "X-Frame-Options",
	"Referrer-Policy", "Permissions-Policy", "Server", "X-Powered-By",
}

// PortSuffix is ":8443" for non-default ports.
func PortSuffix(port int32) string {
	if port == 443 {
		return ""
	}
	return ":" + strconv.Itoa(int(port))
}
