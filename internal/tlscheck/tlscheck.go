// Package tlscheck inspects a public HTTPS endpoint the way an attacker
// sees it: certificate validity and expiry, protocol versions, weak cipher
// suites, the plain-HTTP redirect, security headers and the domain's mail
// spoofing protection (SPF/DMARC). Only public addresses are contacted
// unless explicitly allowed (no SSRF into internal networks).
package tlscheck

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/publicsuffix"

	"github.com/ininia/scanx/internal/notify"
	"github.com/ininia/scanx/internal/report"
)

// Options tune a check.
type Options struct {
	// AllowPrivate permits private/loopback targets (internal sites).
	AllowPrivate bool
	// Roots overrides the system trust store (tests).
	Roots *x509.CertPool
	// Resolver overrides DNS (tests).
	Resolver *net.Resolver
	// Timeout bounds every network step (default 10s).
	Timeout time.Duration
	// Now is the reference time (tests).
	Now time.Time
}

// Cert describes the leaf certificate.
type Cert struct {
	Subject   string    `json:"subject"`
	Issuer    string    `json:"issuer"`
	SANs      []string  `json:"sans,omitempty"`
	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`
	DaysLeft  int       `json:"days_left"`
	KeyType   string    `json:"key_type"`
	KeyBits   int       `json:"key_bits"`
	SigAlg    string    `json:"sig_alg"`
	Serial    string    `json:"serial"`
	Trusted   bool      `json:"trusted"`
	TrustErr  string    `json:"trust_error,omitempty"`
}

// Result is the outcome of one check.
type Result struct {
	Host        string            `json:"host"`
	Port        int               `json:"port"`
	IPs         []string          `json:"ips,omitempty"`
	Cert        *Cert             `json:"cert,omitempty"`
	Protocols   map[string]bool   `json:"protocols,omitempty"` // "TLS 1.0".."TLS 1.3"
	Cipher      string            `json:"cipher,omitempty"`    // negotiated with defaults
	WeakCiphers []string          `json:"weak_ciphers,omitempty"`
	HTTPStatus  int               `json:"http_status,omitempty"`
	Headers     map[string]string `json:"headers,omitempty"`  // security-relevant response headers
	Redirect    string            `json:"redirect,omitempty"` // plain HTTP behaviour: https | none | closed | other
	Apex        string            `json:"apex,omitempty"`
	SPF         string            `json:"spf,omitempty"`
	DMARC       string            `json:"dmarc,omitempty"`
	Findings    []Finding         `json:"findings"`
	Score       int               `json:"score"`
	Grade       string            `json:"grade"`
	Error       string            `json:"error,omitempty"`
	DurationMS  int64             `json:"duration_ms"`
}

// Finding is one problem; message and fix are translated from the rule ID.
type Finding struct {
	RuleID   string   `json:"rule"`
	Severity string   `json:"severity"`
	Params   []string `json:"params,omitempty"`
}

// Rules lists every rule with its default severity (display order).
var Rules = []struct{ ID, Severity, Area string }{
	{"TLS001", "critical", "cert"},
	{"TLS002", "high", "cert"},
	{"TLS003", "high", "cert"},
	{"TLS004", "high", "cert"},
	{"TLS005", "medium", "cert"},
	{"TLS006", "high", "cert"},
	{"TLS007", "medium", "protocol"},
	{"TLS008", "medium", "protocol"},
	{"TLS009", "low", "protocol"},
	{"TLS010", "medium", "protocol"},
	{"TLS011", "medium", "http"},
	{"TLS012", "medium", "http"},
	{"TLS013", "low", "http"},
	{"TLS014", "low", "http"},
	{"TLS015", "low", "http"},
	{"TLS016", "low", "http"},
	{"TLS017", "info", "http"},
	{"TLS018", "low", "http"},
	{"TLS021", "low", "http"},
	{"TLS019", "low", "dns"},
	{"TLS020", "medium", "dns"},
}

var errBlocked = errors.New("the address is not public")

// Check runs every test against host:port.
func Check(ctx context.Context, host string, port int, opt Options) *Result {
	start := time.Now()
	if opt.Timeout == 0 {
		opt.Timeout = 10 * time.Second
	}
	if opt.Now.IsZero() {
		opt.Now = time.Now()
	}
	if opt.Resolver == nil {
		opt.Resolver = net.DefaultResolver
	}
	if port == 0 {
		port = 443
	}
	r := &Result{Host: host, Port: port, Protocols: map[string]bool{}, Headers: map[string]string{}}
	defer func() {
		r.score()
		r.DurationMS = time.Since(start).Milliseconds()
	}()

	ips, err := resolve(ctx, opt, host)
	if err != nil {
		r.Error = err.Error()
		return r
	}
	for _, ip := range ips {
		r.IPs = append(r.IPs, ip.String())
	}
	c := &checker{opt: opt, host: host, port: port, ip: ips[0]}

	// Certificate as presented (even if invalid), then real verification.
	// MinVersion TLS 1.0: legacy-only servers must still be inspectable.
	state, err := c.handshake(ctx, &tls.Config{ServerName: host, InsecureSkipVerify: true, MinVersion: tls.VersionTLS10}) //nolint:gosec // inspecting, verified below
	if err != nil {
		r.Error = "TLS handshake failed: " + firstLine(err.Error())
		return r
	}
	r.Cipher = tls.CipherSuiteName(state.CipherSuite)
	r.Protocols[versionName(state.Version)] = true
	r.inspectCert(state, c, opt)

	for _, v := range []uint16{tls.VersionTLS10, tls.VersionTLS11, tls.VersionTLS12, tls.VersionTLS13} {
		if r.Protocols[versionName(v)] {
			continue
		}
		_, err := c.handshake(ctx, &tls.Config{ServerName: host, InsecureSkipVerify: true, MinVersion: v, MaxVersion: v}) //nolint:gosec // probing versions
		r.Protocols[versionName(v)] = err == nil
	}
	if r.Protocols["TLS 1.0"] {
		r.add("TLS007")
	}
	if r.Protocols["TLS 1.1"] {
		r.add("TLS008")
	}
	if !r.Protocols["TLS 1.3"] {
		r.add("TLS009")
	}
	if r.Protocols["TLS 1.0"] || r.Protocols["TLS 1.1"] || r.Protocols["TLS 1.2"] {
		for _, cs := range tls.InsecureCipherSuites() {
			cfg := &tls.Config{ServerName: host, InsecureSkipVerify: true, MaxVersion: tls.VersionTLS12, CipherSuites: []uint16{cs.ID}} //nolint:gosec // probing weak suites
			if r.Protocols["TLS 1.0"] {
				cfg.MinVersion = tls.VersionTLS10
			}
			if _, err := c.handshake(ctx, cfg); err == nil {
				r.WeakCiphers = append(r.WeakCiphers, cs.Name)
			}
		}
		if len(r.WeakCiphers) > 0 {
			r.add("TLS010", strings.Join(r.WeakCiphers, ", "))
		}
	}

	r.checkHTTP(ctx, c)
	if port == 443 {
		r.checkRedirect(ctx, c)
	}
	r.checkDNS(ctx, opt)
	return r
}

type checker struct {
	opt  Options
	host string
	port int
	ip   net.IP
}

func resolve(ctx context.Context, opt Options, host string) ([]net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		if !opt.AllowPrivate && !notify.PublicIP(ip) {
			return nil, errBlocked
		}
		return []net.IP{ip}, nil
	}
	rctx, cancel := context.WithTimeout(ctx, opt.Timeout)
	defer cancel()
	addrs, err := opt.Resolver.LookupIPAddr(rctx, host)
	if err != nil || len(addrs) == 0 {
		return nil, fmt.Errorf("cannot resolve %s", host)
	}
	var out []net.IP
	for _, a := range addrs {
		if !opt.AllowPrivate && !notify.PublicIP(a.IP) {
			return nil, fmt.Errorf("%s resolves to %s: %w", host, a.IP, errBlocked)
		}
		out = append(out, a.IP)
	}
	return out, nil
}

// dial connects to the resolved address only (no second DNS lookup that
// could be rebound to an internal address).
func (c *checker) dial(ctx context.Context, port int) (net.Conn, error) {
	d := net.Dialer{Timeout: c.opt.Timeout}
	return d.DialContext(ctx, "tcp", net.JoinHostPort(c.ip.String(), strconv.Itoa(port)))
}

func (c *checker) handshake(ctx context.Context, cfg *tls.Config) (tls.ConnectionState, error) {
	hctx, cancel := context.WithTimeout(ctx, c.opt.Timeout)
	defer cancel()
	raw, err := c.dial(hctx, c.port)
	if err != nil {
		return tls.ConnectionState{}, err
	}
	conn := tls.Client(raw, cfg)
	defer func() { _ = conn.Close() }()
	if err := conn.HandshakeContext(hctx); err != nil {
		return tls.ConnectionState{}, err
	}
	return conn.ConnectionState(), nil
}

func (r *Result) add(id string, params ...string) {
	sev := "info"
	for _, x := range Rules {
		if x.ID == id {
			sev = x.Severity
		}
	}
	r.Findings = append(r.Findings, Finding{RuleID: id, Severity: sev, Params: params})
}

func (r *Result) addSev(id, sev string, params ...string) {
	r.Findings = append(r.Findings, Finding{RuleID: id, Severity: sev, Params: params})
}

func (r *Result) inspectCert(state tls.ConnectionState, c *checker, opt Options) {
	if len(state.PeerCertificates) == 0 {
		return
	}
	leaf := state.PeerCertificates[0]
	ce := &Cert{
		Subject: leaf.Subject.CommonName, Issuer: issuerName(leaf), SANs: leaf.DNSNames,
		NotBefore: leaf.NotBefore, NotAfter: leaf.NotAfter, SigAlg: leaf.SignatureAlgorithm.String(),
		Serial: leaf.SerialNumber.Text(16),
	}
	if len(ce.SANs) > 20 {
		ce.SANs = append(ce.SANs[:20], fmt.Sprintf("+%d", len(leaf.DNSNames)-20))
	}
	ce.DaysLeft = int(leaf.NotAfter.Sub(opt.Now).Hours() / 24)
	switch k := leaf.PublicKey.(type) {
	case *rsa.PublicKey:
		ce.KeyType, ce.KeyBits = "RSA", k.N.BitLen()
	case *ecdsa.PublicKey:
		ce.KeyType, ce.KeyBits = "ECDSA", k.Curve.Params().BitSize
	default:
		ce.KeyType = fmt.Sprintf("%T", k)
	}
	inter := x509.NewCertPool()
	for _, ic := range state.PeerCertificates[1:] {
		inter.AddCert(ic)
	}
	_, err := leaf.Verify(x509.VerifyOptions{DNSName: c.host, Roots: opt.Roots, Intermediates: inter, CurrentTime: opt.Now})
	ce.Trusted = err == nil
	r.Cert = ce

	switch {
	case opt.Now.After(leaf.NotAfter):
		r.add("TLS001", leaf.NotAfter.Format("2006-01-02"))
	case ce.DaysLeft <= 7:
		r.addSev("TLS002", "critical", strconv.Itoa(ce.DaysLeft), leaf.NotAfter.Format("2006-01-02"))
	case ce.DaysLeft <= 14:
		r.addSev("TLS002", "high", strconv.Itoa(ce.DaysLeft), leaf.NotAfter.Format("2006-01-02"))
	case ce.DaysLeft <= 30:
		r.addSev("TLS002", "medium", strconv.Itoa(ce.DaysLeft), leaf.NotAfter.Format("2006-01-02"))
	}
	if err != nil {
		ce.TrustErr = firstLine(err.Error())
		var he x509.HostnameError
		var ue x509.UnknownAuthorityError
		switch {
		case errors.As(err, &he):
			r.add("TLS003", strings.Join(leaf.DNSNames, ", "))
		case errors.As(err, &ue):
			r.add("TLS004", ce.Issuer)
		case opt.Now.After(leaf.NotAfter) || opt.Now.Before(leaf.NotBefore):
			// reported as TLS001
		default:
			r.add("TLS004", ce.TrustErr)
		}
	}
	if (ce.KeyType == "RSA" && ce.KeyBits < 2048) || (ce.KeyType == "ECDSA" && ce.KeyBits < 256) {
		r.add("TLS005", ce.KeyType+" "+strconv.Itoa(ce.KeyBits))
	}
	switch leaf.SignatureAlgorithm {
	case x509.SHA1WithRSA, x509.ECDSAWithSHA1, x509.DSAWithSHA1, x509.MD5WithRSA, x509.MD2WithRSA:
		r.add("TLS006", ce.SigAlg)
	}
}

func issuerName(c *x509.Certificate) string {
	if c.Issuer.CommonName != "" {
		if len(c.Issuer.Organization) > 0 {
			return c.Issuer.Organization[0] + " (" + c.Issuer.CommonName + ")"
		}
		return c.Issuer.CommonName
	}
	return c.Issuer.String()
}

func versionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	}
	return "SSL"
}

// httpClient talks only to the resolved address and never follows
// redirects by itself.
func (c *checker) httpClient() *http.Client {
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			_, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			p, _ := strconv.Atoi(port)
			return c.dial(ctx, p)
		},
		TLSClientConfig:     &tls.Config{ServerName: c.host, InsecureSkipVerify: true, MinVersion: tls.VersionTLS10}, //nolint:gosec // headers are checked even with a bad certificate
		TLSHandshakeTimeout: c.opt.Timeout, ResponseHeaderTimeout: c.opt.Timeout, DisableKeepAlives: true, Proxy: nil,
	}
	return &http.Client{
		Transport: tr, Timeout: 2 * c.opt.Timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

var securityHeaders = []string{
	"Strict-Transport-Security", "Content-Security-Policy", "X-Content-Type-Options", "X-Frame-Options",
	"Referrer-Policy", "Permissions-Policy", "Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version",
}

func (r *Result) checkHTTP(ctx context.Context, c *checker) {
	client := c.httpClient()
	u := url.URL{Scheme: "https", Host: net.JoinHostPort(c.host, strconv.Itoa(c.port)), Path: "/"}
	if c.port == 443 {
		u.Host = c.host
	}
	var resp *http.Response
	for hop := 0; hop < 4; hop++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
		if err != nil {
			return
		}
		req.Header.Set("User-Agent", "scanX-tls-check")
		resp, err = client.Do(req)
		if err != nil {
			return
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		_ = resp.Body.Close()
		loc, lerr := resp.Location()
		if resp.StatusCode < 300 || resp.StatusCode >= 400 || lerr != nil || loc.Hostname() != c.host || loc.Scheme != "https" {
			break
		}
		u = *loc
	}
	if resp == nil {
		return
	}
	r.HTTPStatus = resp.StatusCode
	for _, h := range securityHeaders {
		if v := resp.Header.Get(h); v != "" {
			r.Headers[h] = trunc(v, 300)
		}
	}
	hsts := resp.Header.Get("Strict-Transport-Security")
	switch {
	case hsts == "":
		r.add("TLS012")
	case hstsMaxAge(hsts) < 15552000:
		r.add("TLS013", strconv.Itoa(hstsMaxAge(hsts)))
	}
	csp := resp.Header.Get("Content-Security-Policy")
	if csp == "" {
		r.add("TLS014")
	}
	if !strings.EqualFold(resp.Header.Get("X-Content-Type-Options"), "nosniff") {
		r.add("TLS015")
	}
	if resp.Header.Get("X-Frame-Options") == "" && !strings.Contains(csp, "frame-ancestors") {
		r.add("TLS016")
	}
	if resp.Header.Get("Referrer-Policy") == "" {
		r.add("TLS017")
	}
	var leaks []string
	for _, h := range []string{"Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"} {
		if v := resp.Header.Get(h); v != "" && (h != "Server" || strings.ContainsAny(v, "0123456789")) {
			leaks = append(leaks, h+": "+trunc(v, 60))
		}
	}
	if len(leaks) > 0 {
		r.add("TLS018", strings.Join(leaks, "; "))
	}
	var weak []string
	for _, ck := range resp.Cookies() {
		if !ck.Secure || !ck.HttpOnly {
			weak = append(weak, ck.Name)
		}
	}
	if len(weak) > 0 {
		r.add("TLS021", strings.Join(weak, ", "))
	}
}

func hstsMaxAge(v string) int {
	for _, part := range strings.Split(v, ";") {
		k, val, ok := strings.Cut(strings.TrimSpace(part), "=")
		if ok && strings.EqualFold(k, "max-age") {
			n, _ := strconv.Atoi(strings.Trim(val, `"`))
			return n
		}
	}
	return 0
}

// checkRedirect expects plain HTTP on port 80 to redirect to HTTPS.
func (r *Result) checkRedirect(ctx context.Context, c *checker) {
	client := c.httpClient()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+c.host+"/", nil)
	if err != nil {
		return
	}
	resp, err := client.Do(req)
	if err != nil {
		r.Redirect = "closed"
		return
	}
	_ = resp.Body.Close()
	loc, lerr := resp.Location()
	switch {
	case resp.StatusCode >= 300 && resp.StatusCode < 400 && lerr == nil && loc.Scheme == "https":
		r.Redirect = "https"
	case resp.StatusCode >= 300 && resp.StatusCode < 400:
		r.Redirect = "other"
		r.add("TLS011")
	default:
		r.Redirect = "none"
		r.add("TLS011")
	}
}

func (r *Result) checkDNS(ctx context.Context, opt Options) {
	if net.ParseIP(r.Host) != nil {
		return
	}
	apex, err := publicsuffix.EffectiveTLDPlusOne(r.Host)
	if err != nil {
		return
	}
	r.Apex = apex
	dctx, cancel := context.WithTimeout(ctx, opt.Timeout)
	defer cancel()
	if txts, err := opt.Resolver.LookupTXT(dctx, apex); err == nil {
		for _, t := range txts {
			if strings.HasPrefix(strings.ToLower(t), "v=spf1") {
				r.SPF = trunc(t, 300)
			}
		}
	}
	switch l := strings.ToLower(r.SPF); {
	case r.SPF == "":
		r.add("TLS019", apex)
	case strings.Contains(l, "+all"):
		r.addSev("TLS019", "high", apex)
	case strings.HasSuffix(strings.TrimSpace(l), "?all"):
		r.addSev("TLS019", "medium", apex)
	}
	if txts, err := opt.Resolver.LookupTXT(dctx, "_dmarc."+apex); err == nil {
		for _, t := range txts {
			if strings.HasPrefix(strings.ToUpper(t), "V=DMARC1") {
				r.DMARC = trunc(t, 300)
			}
		}
	}
	switch l := strings.ToLower(strings.ReplaceAll(r.DMARC, " ", "")); {
	case r.DMARC == "":
		r.add("TLS020", apex)
	case strings.Contains(l, "p=none"):
		r.addSev("TLS020", "low", apex)
	}
}

// sevPoints are subtracted from 100.
var sevPoints = map[string]int{"critical": 40, "high": 20, "medium": 8, "low": 3, "info": 0}

func (r *Result) score() {
	if r.Error != "" && r.Cert == nil {
		r.Score, r.Grade = 0, "F"
		return
	}
	s := 100
	for _, f := range r.Findings {
		s -= sevPoints[f.Severity]
	}
	r.Score = max(s, 0)
	r.Grade = report.Grade(r.Score)
}

// Worst returns the highest severity found ("" if none).
func (r *Result) Worst() string {
	order := map[string]int{"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
	w := ""
	for _, f := range r.Findings {
		if order[f.Severity] > order[w] {
			w = f.Severity
		}
	}
	return w
}

// Counts tallies findings per severity.
func (r *Result) Counts() map[string]int {
	m := map[string]int{}
	for _, f := range r.Findings {
		m[f.Severity]++
	}
	return m
}

func firstLine(s string) string {
	s, _, _ = strings.Cut(s, "\n")
	return trunc(s, 300)
}

func trunc(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}
