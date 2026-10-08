package notify

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPublicIP(t *testing.T) {
	for _, s := range []string{"127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.1", "169.254.169.254", "100.64.0.1", "::1", "fd00::1", "0.0.0.0"} {
		if PublicIP(net.ParseIP(s)) {
			t.Errorf("%s treated as public", s)
		}
	}
	for _, s := range []string{"8.8.8.8", "140.82.112.3", "2606:4700::1111"} {
		if !PublicIP(net.ParseIP(s)) {
			t.Errorf("%s treated as private", s)
		}
	}
}

func TestValidateTarget(t *testing.T) {
	ok := [][2]string{{"slack", "https://hooks.slack.com/services/x"}, {"email", "a@x.io, b@y.io"}, {"webhook", "http://example.com/h"}}
	for _, c := range ok {
		if err := ValidateTarget(c[0], c[1]); err != nil {
			t.Errorf("%v: %v", c, err)
		}
	}
	bad := [][2]string{
		{"slack", "http://hooks.slack.com/x"},
		{"teams", "https://169.254.169.254/x"},
		{"email", "nope"},
		{"webhook", "https://u:p@x.io/"},
		{"sms", "x"},
	}
	for _, c := range bad {
		if err := ValidateTarget(c[0], c[1]); err == nil {
			t.Errorf("%v accepted", c)
		}
	}
}

// Loopback is refused at dial time unless explicitly allowed (SSRF).
func TestSendBlocksPrivate(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&got)
	}))
	defer srv.Close()
	m := Message{Event: EventGateFailed, Org: "O", Project: "P", Branch: "main", Gate: "fail", High: 2}
	if err := NewSender(SMTP{}, false).Send(t.Context(), KindSlack, srv.URL, m); !errors.Is(err, ErrBlockedAddress) {
		t.Fatalf("expected blocked, got %v", err)
	}
	if err := NewSender(SMTP{}, true).Send(t.Context(), KindSlack, srv.URL, m); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got["text"].(string), "quality gate FAILED for P") {
		t.Fatalf("payload %v", got)
	}
}

func TestErrorsDoNotLeakURL(t *testing.T) {
	err := NewSender(SMTP{}, true).Send(t.Context(), KindSlack, "https://127.0.0.1:1/services/SECRET", Message{})
	if err == nil || strings.Contains(err.Error(), "SECRET") {
		t.Fatalf("error leaks URL: %v", err)
	}
}

func TestEmailNeedsSMTP(t *testing.T) {
	if err := NewSender(SMTP{}, false).Send(t.Context(), KindEmail, "a@x.io", Message{}); err == nil {
		t.Fatal("expected error without SMTP")
	}
}
