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
	"net"
	"net/http"
	"net/mail"
	"net/smtp"
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
}

// Title is a one-line summary.
func (m Message) Title() string {
	switch m.Event {
	case EventTest:
		return "scanX: test notification for " + m.Org
	case EventScanFailed:
		return fmt.Sprintf("scanX: scan of %s (%s) failed", m.Project, m.Branch)
	case EventGateFailed:
		return fmt.Sprintf("scanX: quality gate FAILED for %s (%s)", m.Project, m.Branch)
	default:
		return fmt.Sprintf("scanX: scan of %s (%s) completed — gate %s", m.Project, m.Branch, strings.ToUpper(m.Gate))
	}
}

// Text is the multi-line body.
func (m Message) Text() string {
	if m.Event == EventTest {
		return "This is a test message from scanX. Notifications for this channel are working."
	}
	var b strings.Builder
	if m.Commit != "" {
		c := m.Commit
		if len(c) > 12 {
			c = c[:12]
		}
		fmt.Fprintf(&b, "Commit %s\n", c)
	}
	if m.Event == EventScanFailed {
		fmt.Fprintf(&b, "Reason: %s\n", m.Reason)
	} else {
		fmt.Fprintf(&b, "Score %d/100 · critical %d · high %d · medium %d · low %d\n", m.Score, m.Critical, m.High, m.Medium, m.Low)
		fmt.Fprintf(&b, "New issues: %d · fixed: %d\n", m.New, m.Fixed)
	}
	if m.URL != "" {
		fmt.Fprintf(&b, "%s\n", m.URL)
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
		return s.postJSON(ctx, target, map[string]any{"text": "*" + m.Title() + "*\n" + m.Text()})
	case KindTeams:
		// Adaptive card: accepted by Teams "Workflows" webhooks and legacy
		// incoming-webhook connectors.
		body := []map[string]any{{"type": "TextBlock", "text": m.Title(), "weight": "Bolder", "wrap": true}}
		for _, line := range strings.Split(m.Text(), "\n") {
			body = append(body, map[string]any{"type": "TextBlock", "text": line, "wrap": true, "spacing": "Small"})
		}
		return s.postJSON(ctx, target, map[string]any{
			"type": "message",
			"attachments": []map[string]any{{
				"contentType": "application/vnd.microsoft.card.adaptive",
				"content": map[string]any{
					"$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
					"type":    "AdaptiveCard", "version": "1.4", "body": body,
				},
			}},
		})
	case KindWebhook:
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
	var msg bytes.Buffer
	fmt.Fprintf(&msg, "From: %s\r\nTo: %s\r\nSubject: %s\r\nDate: %s\r\nMIME-Version: 1.0\r\n"+
		"Content-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n%s\r\n",
		from.String(), strings.Join(rcpts, ", "), mimeHeader(subject), time.Now().UTC().Format(time.RFC1123Z),
		strings.ReplaceAll(m.Text(), "\n", "\r\n"))

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
