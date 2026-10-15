// Package notify delivers scan notifications to Slack, Microsoft Teams,
// generic webhooks and e-mail. Outbound HTTP refuses private, loopback and
// link-local addresses (SSRF, spec §5.5) unless explicitly allowed.
package notify

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net"
	"net/http"
	"net/mail"
	"net/smtp"
	"net/textproto"
	"net/url"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Kinds of channels.
const (
	KindSlack   = "slack"
	KindTeams   = "teams"
	KindWebhook = "webhook"
	KindEmail   = "email"
)

// Events.
const (
	EventScanCompleted = "scan.completed"
	EventGateFailed    = "gate.failed"
	EventScanFailed    = "scan.failed"
	EventTest          = "test"
)

// AllEvents lists the subscribable events.
var AllEvents = []string{EventScanCompleted, EventGateFailed, EventScanFailed}

// Message is one notification.
type Message struct {
	Event    string `json:"event"`
	Org      string `json:"org"`
	Project  string `json:"project"`
	Branch   string `json:"branch,omitempty"`
	Commit   string `json:"commit,omitempty"`
	Status   string `json:"status,omitempty"`
	Gate     string `json:"gate,omitempty"`
	Score    int    `json:"score"`
	Critical int    `json:"critical"`
	High     int    `json:"high"`
	Medium   int    `json:"medium"`
	Low      int    `json:"low"`
	New      int    `json:"new_issues"`
	Fixed    int    `json:"fixed_issues"`
	Reason   string `json:"reason,omitempty"`
	URL      string `json:"url,omitempty"`
	// Level is filled for JSON webhooks: critical | fail | error | pass | test.
	LevelTag      string `json:"level,omitempty"`
	Grade         string `json:"grade,omitempty"`
	Scope         string `json:"scope,omitempty"` // diff | full
	ChangedFiles  int    `json:"changed_files,omitempty"`
	CommitMessage string `json:"commit_message,omitempty"`
	Author        string `json:"author,omitempty"`
	// BaseURL (public URL of the instance, for the status icons) and Lang
	// (instance default language) only shape the rendering.
	BaseURL string `json:"-"`
	Lang    string `json:"-"`
}

// Title is a one-line summary (e-mail subject, chat preview).
func (m Message) Title() string {
	switch m.Level() {
	case LevelTest:
		return m.t("card.title.test", m.Org)
	case LevelCritical:
		return m.t("card.title.critical", m.Project, m.Branch, m.Critical)
	default:
		return m.t("card.title."+m.Level(), m.Project, m.Branch)
	}
}

// Text is the plain-text body.
func (m Message) Text() string {
	var b strings.Builder
	b.WriteString(m.lead() + "\n")
	if m.showCounts() {
		var parts []string
		for _, s := range m.severities() {
			parts = append(parts, fmt.Sprintf("%s %d", m.t("card."+s.Key), s.N))
		}
		b.WriteString(strings.Join(parts, " · ") + "\n")
	}
	for _, f := range m.facts() {
		fmt.Fprintf(&b, "%s: %s\n", f.Title, f.Value)
	}
	if m.URL != "" {
		b.WriteString(m.URL + "\n")
	}
	return strings.TrimSpace(b.String())
}

// SMTP configures e-mail delivery (SCANX_SMTP_*).
type SMTP struct {
	Host     string
	Port     int
	Username string
	Password string
	From     string
	// TLS: "starttls" (default), "tls" (implicit, port 465) or "none".
	TLS string
}

// Configured reports whether e-mail can be sent.
func (s SMTP) Configured() bool { return s.Host != "" && s.From != "" }

// Sender delivers messages.
type Sender struct {
	HTTP         *http.Client
	SMTP         SMTP
	AllowPrivate bool
}

// NewSender returns a Sender with an SSRF-safe HTTP client.
func NewSender(smtpCfg SMTP, allowPrivate bool) *Sender {
	return &Sender{HTTP: SafeHTTPClient(allowPrivate, 15*time.Second), SMTP: smtpCfg, AllowPrivate: allowPrivate}
}

// ErrBlockedAddress is returned when a target resolves to a non-public IP.
var ErrBlockedAddress = errors.New("destination address is not allowed (private or local network)")

// SafeHTTPClient refuses connections to non-public addresses (checked on the
// resolved IP at dial time, so DNS rebinding cannot bypass it) and does not
// follow redirects.
func SafeHTTPClient(allowPrivate bool, timeout time.Duration) *http.Client {
	d := &net.Dialer{Timeout: 10 * time.Second, Control: func(_, address string, _ syscall.RawConn) error {
		if allowPrivate {
			return nil
		}
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return err
		}
		ip := net.ParseIP(host)
		if ip == nil || !PublicIP(ip) {
			return ErrBlockedAddress
		}
		return nil
	}}
	tr := &http.Transport{
		DialContext: d.DialContext, TLSHandshakeTimeout: 10 * time.Second, MaxIdleConns: 4,
		Proxy: nil, ForceAttemptHTTP2: true,
	}
	return &http.Client{
		Transport: tr, Timeout: timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// PublicIP reports whether ip is a globally routable unicast address.
func PublicIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() || ip.IsUnspecified() || ip.IsInterfaceLocalMulticast() {
		return false
	}
	if v4 := ip.To4(); v4 != nil {
		switch {
		case v4[0] == 0, v4[0] == 100 && v4[1]&0xc0 == 64, // 0/8, CGNAT 100.64/10
			v4[0] == 192 && v4[1] == 0 && v4[2] == 0, // 192.0.0/24
			v4[0] == 198 && (v4[1] == 18 || v4[1] == 19), v4[0] >= 240:
			return false
		}
	}
	return true
}

// ValidateTarget checks a channel target before it is stored.
func ValidateTarget(kind, target string) error {
	target = strings.TrimSpace(target)
	switch kind {
	case KindSlack, KindTeams, KindWebhook:
		u, err := url.Parse(target)
		if err != nil || u.Host == "" || u.User != nil || len(target) > 2000 {
			return errors.New("invalid URL")
		}
		if u.Scheme != "https" && (kind != KindWebhook || u.Scheme != "http") {
			return errors.New("URL must use https")
		}
		if ip := net.ParseIP(u.Hostname()); ip != nil && !PublicIP(ip) {
			return ErrBlockedAddress
		}
		return nil
	case KindEmail:
		for _, a := range strings.Split(target, ",") {
			if _, err := mail.ParseAddress(strings.TrimSpace(a)); err != nil {
				return errors.New("invalid e-mail address")
			}
		}
		if strings.Count(target, ",") >= 20 {
			return errors.New("too many recipients")
		}
		return nil
	default:
		return errors.New("unknown channel kind")
	}
}

// Send delivers m to one channel.
func (s *Sender) Send(ctx context.Context, kind, target string, m Message) error {
	switch kind {
	case KindSlack:
		return s.postJSON(ctx, target, m.slackPayload())
	case KindTeams:
		// Adaptive card: accepted by Teams "Workflows" webhooks and legacy
		// incoming-webhook connectors.
		return s.postJSON(ctx, target, m.teamsCard())
	case KindWebhook:
		m.LevelTag = m.Level()
		return s.postJSON(ctx, target, m)
	case KindEmail:
		return s.sendMail(ctx, target, m)
	default:
		return fmt.Errorf("unknown channel kind %q", kind)
	}
}

func (s *Sender) postJSON(ctx context.Context, target string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "scanX-notifier")
	resp, err := s.HTTP.Do(req)
	if err != nil {
		if errors.Is(err, ErrBlockedAddress) {
			return ErrBlockedAddress
		}
		// url.Error embeds the full URL, which for Slack/Teams is a
		// credential: report only the cause.
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return fmt.Errorf("deliver: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("deliver: endpoint returned HTTP %d", resp.StatusCode)
	}
	return nil
}

func (s *Sender) sendMail(ctx context.Context, to string, m Message) error {
	if !s.SMTP.Configured() {
		return errors.New("e-mail is not configured on this server (SCANX_SMTP_HOST / SCANX_SMTP_FROM)")
	}
	var rcpts []string
	for _, a := range strings.Split(to, ",") {
		addr, err := mail.ParseAddress(strings.TrimSpace(a))
		if err != nil {
			return err
		}
		rcpts = append(rcpts, addr.Address)
	}
	from, err := mail.ParseAddress(s.SMTP.From)
	if err != nil {
		return fmt.Errorf("SCANX_SMTP_FROM: %w", err)
	}
	subject := strings.NewReplacer("\r", "", "\n", " ").Replace(m.Title())
	body, boundary, err := mailBody(m)
	if err != nil {
		return err
	}
	var msg bytes.Buffer
	fmt.Fprintf(&msg, "From: %s\r\nTo: %s\r\nSubject: %s\r\nDate: %s\r\nMIME-Version: 1.0\r\n"+
		"Content-Type: multipart/alternative; boundary=%q\r\n\r\n",
		from.String(), strings.Join(rcpts, ", "), mimeHeader(subject), time.Now().UTC().Format(time.RFC1123Z), boundary)
	msg.Write(body)

	port := s.SMTP.Port
	if port == 0 {
		port = 587
	}
	addr := net.JoinHostPort(s.SMTP.Host, strconv.Itoa(port))
	dl, ok := ctx.Deadline()
	if !ok {
		dl = time.Now().Add(30 * time.Second)
	}
	d := &net.Dialer{Deadline: dl}
	var conn net.Conn
	tlsCfg := &tls.Config{ServerName: s.SMTP.Host, MinVersion: tls.VersionTLS12}
	if s.SMTP.TLS == "tls" {
		td := &tls.Dialer{NetDialer: d, Config: tlsCfg}
		conn, err = td.DialContext(ctx, "tcp", addr)
	} else {
		conn, err = d.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return fmt.Errorf("smtp: %w", err)
	}
	_ = conn.SetDeadline(dl)
	c, err := smtp.NewClient(conn, s.SMTP.Host)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("smtp: %w", err)
	}
	defer func() { _ = c.Close() }()
	if s.SMTP.TLS == "" || s.SMTP.TLS == "starttls" {
		if err := c.StartTLS(tlsCfg); err != nil {
			return fmt.Errorf("smtp starttls: %w", err)
		}
	}
	if s.SMTP.Username != "" {
		if err := c.Auth(smtp.PlainAuth("", s.SMTP.Username, s.SMTP.Password, s.SMTP.Host)); err != nil {
			return fmt.Errorf("smtp auth: %w", err)
		}
	}
	if err := c.Mail(from.Address); err != nil {
		return fmt.Errorf("smtp: %w", err)
	}
	for _, r := range rcpts {
		if err := c.Rcpt(r); err != nil {
			return fmt.Errorf("smtp: %w", err)
		}
	}
	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("smtp: %w", err)
	}
	if _, err := w.Write(msg.Bytes()); err != nil {
		return fmt.Errorf("smtp: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("smtp: %w", err)
	}
	return c.Quit()
}

func mimeHeader(s string) string { return mime.BEncoding.Encode("utf-8", s) }

// mailBody builds a multipart/alternative body: plain text first, then the
// HTML card (both quoted-printable, so long lines stay valid SMTP).
func mailBody(m Message) ([]byte, string, error) {
	html, err := m.mailHTML()
	if err != nil {
		return nil, "", err
	}
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	for _, part := range []struct{ ctype, content string }{
		{"text/plain; charset=utf-8", m.Text()},
		{"text/html; charset=utf-8", html},
	} {
		w, err := mw.CreatePart(textproto.MIMEHeader{
			"Content-Type": {part.ctype}, "Content-Transfer-Encoding": {"quoted-printable"},
		})
		if err != nil {
			return nil, "", err
		}
		qp := quotedprintable.NewWriter(w)
		if _, err := qp.Write([]byte(part.content)); err != nil {
			return nil, "", err
		}
		if err := qp.Close(); err != nil {
			return nil, "", err
		}
	}
	if err := mw.Close(); err != nil {
		return nil, "", err
	}
	return buf.Bytes(), mw.Boundary(), nil
}
