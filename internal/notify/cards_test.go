package notify

import (
	"encoding/json"
	"io"
	"mime/quotedprintable"
	"strings"
	"testing"
)

func TestLevels(t *testing.T) {
	cases := []struct {
		m    Message
		want string
	}{
		{Message{Event: EventTest}, LevelTest},
		{Message{Event: EventScanFailed, Critical: 3}, LevelError},
		{Message{Event: EventScanCompleted, Gate: "pass", Critical: 1}, LevelCritical},
		{Message{Event: EventGateFailed, Gate: "fail", High: 2}, LevelFail},
		{Message{Event: EventScanCompleted, Gate: "pass", Low: 4}, LevelPass},
	}
	for _, c := range cases {
		if got := c.m.Level(); got != c.want {
			t.Errorf("%+v: %s want %s", c.m, got, c.want)
		}
	}
}

func TestTeamsCardCritical(t *testing.T) {
	m := Message{
		Event: EventGateFailed, Org: "enterprise", Project: "Qdmx", Branch: "main", Commit: "625b95f94901abc",
		Gate: "fail", Score: 72, Grade: "C", Critical: 1, High: 21, Medium: 62, Low: 197, New: 326,
		Scope: "diff", ChangedFiles: 36, URL: "https://scanx.example/o/e/scans/1", BaseURL: "https://scanx.example/", Lang: "tr",
	}
	b, err := json.Marshal(m.teamsCard())
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, want := range []string{
		`"style":"attention"`, `"url":"https://scanx.example/static/img/notify/critical.gif"`, "KRİTİK GÜVENLİK AÇIĞI",
		`"text":"21"`, `"color":"Attention"`, "Değişen dosyalar (36)", `"72/100 (C)"`, `"Action.OpenUrl"`,
		`"style":"destructive"`, `"width":"Full"`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("card misses %s\n%s", want, s)
		}
	}
}

func TestTeamsCardPassWithoutBaseURL(t *testing.T) {
	m := Message{Event: EventScanCompleted, Project: "Web", Branch: "master", Gate: "pass", Score: 100, Low: 1}
	s, _ := json.Marshal(m.teamsCard())
	if strings.Contains(string(s), `"Image"`) || !strings.Contains(string(s), `"style":"good"`) || !strings.Contains(string(s), "Scan passed") {
		t.Fatalf("%s", s)
	}
}

func TestSlackPayload(t *testing.T) {
	m := Message{Event: EventGateFailed, Project: "P", Branch: "main", Gate: "fail", High: 2, URL: "https://x.example/s", BaseURL: "https://x.example"}
	b, _ := json.Marshal(m.slackPayload())
	s := string(b)
	for _, want := range []string{`"color":"#f97316"`, `"accessory"`, "fail.png", `"style":"danger"`, "quality gate FAILED for P"} {
		if !strings.Contains(s, want) {
			t.Errorf("slack misses %s\n%s", want, s)
		}
	}
}

func TestMailBodyHasHTMLAndText(t *testing.T) {
	m := Message{Event: EventScanCompleted, Org: "O", Project: "P<x>", Branch: "main", Gate: "pass", Critical: 2, URL: "https://x.example/s"}
	body, boundary, err := mailBody(m)
	if err != nil || boundary == "" {
		t.Fatal(err)
	}
	dec, _ := io.ReadAll(quotedprintable.NewReader(strings.NewReader(string(body))))
	s := string(dec)
	if !strings.Contains(s, "text/html") || !strings.Contains(s, "text/plain") || !strings.Contains(s, "CRITICAL VULNERABILITY") ||
		!strings.Contains(s, "P&lt;x&gt;") {
		t.Fatalf("%s", s)
	}
}
