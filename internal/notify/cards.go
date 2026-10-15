package notify

import (
	"bytes"
	"fmt"
	"html/template"
	"strconv"
	"strings"

	"github.com/ininia/scanx/internal/i18n"
)

// Levels decide colour, icon and wording of a notification.
const (
	LevelCritical = "critical" // open critical findings: alarm
	LevelFail     = "fail"     // quality gate failed
	LevelError    = "error"    // the scan itself failed
	LevelPass     = "pass"
	LevelTest     = "test"
)

// Level classifies the message. Critical findings raise the alarm even
// when the project's gate would let them pass.
func (m Message) Level() string {
	switch {
	case m.Event == EventTest:
		return LevelTest
	case m.Event == EventScanFailed:
		return LevelError
	case m.Critical > 0:
		return LevelCritical
	case m.Gate == "fail" || m.Event == EventGateFailed:
		return LevelFail
	}
	return LevelPass
}

func (m Message) lang() string {
	if i18n.Valid(m.Lang) {
		return m.Lang
	}
	return i18n.EN
}

func (m Message) t(key string, args ...any) string { return i18n.T(m.lang(), key, args...) }

func (m Message) shortCommit() string {
	if len(m.Commit) > 7 {
		return m.Commit[:7]
	}
	return m.Commit
}

// IconURL is the hosted status icon (an animated alarm for critical
// findings); empty when the instance has no public base URL.
func (m Message) IconURL() string {
	if m.BaseURL == "" {
		return ""
	}
	name := m.Level() + ".png"
	if m.Level() == LevelCritical {
		name = "critical.gif"
	}
	return strings.TrimRight(m.BaseURL, "/") + "/static/img/notify/" + name
}

// Headline is the big first line of a card.
func (m Message) Headline() string { return m.t("card." + m.Level() + ".headline") }

// subtitle is "project · branch · commit".
func (m Message) subtitle() string {
	parts := []string{}
	for _, p := range []string{m.Project, m.Branch, m.shortCommit()} {
		if p != "" {
			parts = append(parts, p)
		}
	}
	return strings.Join(parts, " · ")
}

// lead is the sentence under the headline.
func (m Message) lead() string {
	switch m.Level() {
	case LevelCritical:
		return m.t("card.critical.lead", m.Critical)
	case LevelFail:
		return m.t("card.fail.lead")
	case LevelError:
		return m.t("card.error.lead", m.Reason)
	case LevelTest:
		return m.t("card.test.lead", m.Org)
	}
	return m.t("card.pass.lead")
}

type fact struct{ Title, Value string }

func (m Message) facts() []fact {
	if m.Level() == LevelTest || m.Level() == LevelError {
		var out []fact
		if m.Commit != "" {
			out = append(out, fact{m.t("card.commit"), m.commitLine()})
		}
		return out
	}
	score := strconv.Itoa(m.Score) + "/100"
	if m.Grade != "" {
		score += " (" + m.Grade + ")"
	}
	out := []fact{
		{m.t("card.score"), score},
		{m.t("card.newfixed"), fmt.Sprintf("+%d / −%d", m.New, m.Fixed)},
	}
	switch m.Scope {
	case "diff":
		out = append(out, fact{m.t("card.scope"), m.t("card.scope.diff", m.ChangedFiles)})
	case "full":
		out = append(out, fact{m.t("card.scope"), m.t("card.scope.full")})
	}
	if m.Commit != "" {
		out = append(out, fact{m.t("card.commit"), m.commitLine()})
	}
	return out
}

func (m Message) commitLine() string {
	s := m.shortCommit()
	if m.CommitMessage != "" {
		s += " — " + m.CommitMessage
	}
	if m.Author != "" {
		s += " (" + m.Author + ")"
	}
	return s
}

type sevCount struct {
	Key   string
	N     int
	Color string // Adaptive Card colour
	Hex   string
	Emoji string
}

func (m Message) severities() []sevCount {
	return []sevCount{
		{"critical", m.Critical, "Attention", "#e11d48", "🔴"},
		{"high", m.High, "Warning", "#f97316", "🟠"},
		{"medium", m.Medium, "Accent", "#eab308", "🟡"},
		{"low", m.Low, "Default", "#3b82f6", "🔵"},
	}
}

func (m Message) showCounts() bool { return m.Level() != LevelTest && m.Level() != LevelError }

// levelStyle maps a level to Adaptive Card container style / text colour
// and to a hex colour for Slack and e-mail.
func levelStyle(level string) (container, color, hex string) {
	switch level {
	case LevelCritical:
		return "attention", "Attention", "#e11d48"
	case LevelFail:
		return "warning", "Warning", "#f97316"
	case LevelError:
		return "attention", "Attention", "#64748b"
	case LevelTest:
		return "accent", "Accent", "#3b82f6"
	}
	return "good", "Good", "#10b981"
}

// ---------- Microsoft Teams (Adaptive Card) ----------

func (m Message) teamsCard() map[string]any {
	style, color, _ := levelStyle(m.Level())
	headCols := []map[string]any{}
	if icon := m.IconURL(); icon != "" {
		headCols = append(headCols, map[string]any{
			"type": "Column", "width": "auto", "verticalContentAlignment": "Center",
			"items": []map[string]any{{"type": "Image", "url": icon, "size": "Medium", "style": "Person", "altText": m.Level()}},
		})
	}
	headCols = append(headCols, map[string]any{
		"type": "Column", "width": "stretch", "verticalContentAlignment": "Center",
		"items": []map[string]any{
			{"type": "TextBlock", "text": m.Headline(), "size": "Large", "weight": "Bolder", "color": color, "wrap": true},
			{"type": "TextBlock", "text": "**" + m.Project + "**" + strings.TrimPrefix(m.subtitle(), m.Project), "spacing": "None", "isSubtle": true, "wrap": true},
		},
	})
	lead := map[string]any{"type": "TextBlock", "text": m.lead(), "wrap": true, "spacing": "Medium"}
	if m.Level() == LevelCritical {
		lead["weight"], lead["color"] = "Bolder", "Attention"
	}
	body := []map[string]any{
		{"type": "Container", "style": style, "bleed": true, "items": []map[string]any{{"type": "ColumnSet", "columns": headCols}}},
		lead,
	}
	if m.showCounts() {
		cols := []map[string]any{}
		for _, s := range m.severities() {
			c := map[string]any{"type": "TextBlock", "text": strconv.Itoa(s.N), "size": "ExtraLarge", "weight": "Bolder", "horizontalAlignment": "Center"}
			if s.N > 0 {
				c["color"] = s.Color
			} else {
				c["isSubtle"] = true
			}
			cols = append(cols, map[string]any{
				"type": "Column", "width": "stretch",
				"items": []map[string]any{{
					"type": "Container", "style": "emphasis",
					"items": []map[string]any{c, {
						"type": "TextBlock", "text": m.t("card." + s.Key), "size": "Small", "isSubtle": true,
						"horizontalAlignment": "Center", "spacing": "None",
					}},
				}},
			})
		}
		body = append(body, map[string]any{"type": "ColumnSet", "columns": cols, "spacing": "Medium"})
	}
	if fs := m.facts(); len(fs) > 0 {
		items := make([]map[string]any, 0, len(fs))
		for _, f := range fs {
			items = append(items, map[string]any{"title": f.Title, "value": f.Value})
		}
		body = append(body, map[string]any{"type": "FactSet", "facts": items, "spacing": "Medium"})
	}
	card := map[string]any{
		"$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
		"type":    "AdaptiveCard", "version": "1.4", "body": body,
		"msteams": map[string]any{"width": "Full"},
	}
	if m.URL != "" {
		action := map[string]any{"type": "Action.OpenUrl", "title": m.t("card.open"), "url": m.URL}
		if m.Level() == LevelCritical || m.Level() == LevelFail {
			action["style"] = "destructive"
		} else {
			action["style"] = "positive"
		}
		card["actions"] = []map[string]any{action}
	}
	return map[string]any{
		"type": "message",
		"attachments": []map[string]any{{
			"contentType": "application/vnd.microsoft.card.adaptive",
			"content":     card,
		}},
	}
}

// ---------- Slack (Block Kit in a coloured attachment) ----------

func (m Message) slackPayload() map[string]any {
	_, _, hex := levelStyle(m.Level())
	head := map[string]any{
		"type": "section",
		"text": map[string]any{"type": "mrkdwn", "text": "*" + m.Headline() + "*\n*" + m.Project + "*" + strings.TrimPrefix(m.subtitle(), m.Project) + "\n" + m.lead()},
	}
	if icon := m.IconURL(); icon != "" {
		head["accessory"] = map[string]any{"type": "image", "image_url": icon, "alt_text": m.Level()}
	}
	blocks := []map[string]any{head}
	if m.showCounts() {
		var fields []map[string]any
		for _, s := range m.severities() {
			fields = append(fields, map[string]any{"type": "mrkdwn", "text": fmt.Sprintf("%s *%s*\n%d", s.Emoji, m.t("card."+s.Key), s.N)})
		}
		blocks = append(blocks, map[string]any{"type": "section", "fields": fields})
	}
	if fs := m.facts(); len(fs) > 0 {
		var parts []string
		for _, f := range fs {
			parts = append(parts, "*"+f.Title+":* "+f.Value)
		}
		blocks = append(blocks, map[string]any{"type": "context", "elements": []map[string]any{{"type": "mrkdwn", "text": strings.Join(parts, "  ·  ")}}})
	}
	if m.URL != "" {
		btn := map[string]any{"type": "button", "text": map[string]any{"type": "plain_text", "text": m.t("card.open")}, "url": m.URL}
		if m.Level() == LevelCritical || m.Level() == LevelFail {
			btn["style"] = "danger"
		} else {
			btn["style"] = "primary"
		}
		blocks = append(blocks, map[string]any{"type": "actions", "elements": []map[string]any{btn}})
	}
	return map[string]any{
		"text":        m.Title(), // notification preview / fallback
		"attachments": []map[string]any{{"color": hex, "blocks": blocks}},
	}
}

// ---------- e-mail (HTML part) ----------

var mailTmpl = template.Must(template.New("mail").Parse(`<!doctype html>
<html><body style="margin:0;padding:24px;background:#f1f5f9;font-family:Segoe UI,Helvetica,Arial,sans-serif;color:#0f172a">
<table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="max-width:600px;margin:0 auto;background:#ffffff;border-radius:12px;overflow:hidden;border:1px solid #e2e8f0">
<tr><td style="background:{{.Hex}};padding:20px 24px;color:#ffffff">
<table role="presentation" cellspacing="0" cellpadding="0"><tr>
{{if .Icon}}<td style="padding-right:16px"><img src="{{.Icon}}" width="48" height="48" alt="" style="border-radius:24px;display:block"></td>{{end}}
<td><div style="font-size:20px;font-weight:700">{{.Headline}}</div><div style="font-size:14px;opacity:.9;margin-top:4px">{{.Subtitle}}</div></td>
</tr></table></td></tr>
<tr><td style="padding:20px 24px">
<p style="margin:0 0 16px;font-size:15px{{if .Critical}};color:#e11d48;font-weight:700{{end}}">{{.Lead}}</p>
{{if .Counts}}<table role="presentation" width="100%" cellspacing="8" cellpadding="0" style="margin:0 -8px 12px"><tr>
{{range .Counts}}<td width="25%" style="background:#f8fafc;border-radius:8px;border-top:3px solid {{.Hex}};padding:10px 0;text-align:center">
<div style="font-size:24px;font-weight:700;color:{{if .N}}{{.Hex}}{{else}}#94a3b8{{end}}">{{.N}}</div><div style="font-size:12px;color:#64748b">{{.Label}}</div></td>{{end}}
</tr></table>{{end}}
{{if .Facts}}<table role="presentation" cellspacing="0" cellpadding="0" style="font-size:14px;margin-bottom:16px">
{{range .Facts}}<tr><td style="padding:3px 16px 3px 0;color:#64748b;white-space:nowrap;vertical-align:top">{{.Title}}</td><td style="padding:3px 0">{{.Value}}</td></tr>{{end}}
</table>{{end}}
{{if .URL}}<a href="{{.URL}}" style="display:inline-block;background:{{.Hex}};color:#ffffff;text-decoration:none;font-weight:600;padding:10px 18px;border-radius:8px">{{.Open}}</a>{{end}}
</td></tr>
<tr><td style="padding:12px 24px;background:#f8fafc;color:#94a3b8;font-size:12px">scanX · {{.Org}}</td></tr>
</table></body></html>`))

func (m Message) mailHTML() (string, error) {
	_, _, hex := levelStyle(m.Level())
	type count struct {
		Label, Hex string
		N          int
	}
	var counts []count
	if m.showCounts() {
		for _, s := range m.severities() {
			counts = append(counts, count{m.t("card." + s.Key), s.Hex, s.N})
		}
	}
	var b bytes.Buffer
	err := mailTmpl.Execute(&b, map[string]any{
		"Hex": hex, "Icon": m.IconURL(), "Headline": m.Headline(), "Subtitle": m.subtitle(), "Lead": m.lead(),
		"Critical": m.Level() == LevelCritical, "Counts": counts, "Facts": m.facts(), "URL": m.URL,
		"Open": m.t("card.open"), "Org": m.Org,
	})
	return b.String(), err
}
