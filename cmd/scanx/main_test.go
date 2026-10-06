package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRunBasics(t *testing.T) {
	cases := []struct {
		args     []string
		code     int
		inStdout string
		inStderr string
	}{
		{nil, exitConfig, "", "Usage:"},
		{[]string{"help"}, exitOK, "Commands:", ""},
		{[]string{"version"}, exitOK, "scanx ", ""},
		{[]string{"bogus"}, exitConfig, "", "unknown command"},
		{[]string{"gen-secrets"}, exitOK, "SCANX_MASTER_KEY=", ""},
		{[]string{"healthcheck", "--url", "http://127.0.0.1:1/x"}, exitScanError, "", "healthcheck"},
		{[]string{"healthcheck", "--nope"}, exitConfig, "", "flag provided but not defined"},
	}
	for _, tc := range cases {
		var out, errOut bytes.Buffer
		code := run(tc.args, &out, &errOut)
		if code != tc.code {
			t.Errorf("%v: code %d want %d (stderr %q)", tc.args, code, tc.code, errOut.String())
		}
		if !strings.Contains(out.String(), tc.inStdout) || !strings.Contains(errOut.String(), tc.inStderr) {
			t.Errorf("%v: stdout %q stderr %q", tc.args, out.String(), errOut.String())
		}
	}
}

func TestServerFailsFastOnMissingConfig(t *testing.T) {
	t.Setenv("SCANX_DATABASE_URL", "")
	t.Setenv("SCANX_DATABASE_ADMIN_URL", "")
	t.Setenv("SCANX_MASTER_KEY", "")
	var out, errOut bytes.Buffer
	if code := run([]string{"server"}, &out, &errOut); code != exitConfig {
		t.Fatalf("code %d", code)
	}
	for _, want := range []string{"SCANX_DATABASE_URL", "SCANX_MASTER_KEY"} {
		if !strings.Contains(errOut.String(), want) {
			t.Errorf("stderr missing %s: %s", want, errOut.String())
		}
	}
	// The server must not demand privileged DB credentials (ADR-005).
	if strings.Contains(errOut.String(), "SCANX_DATABASE_ADMIN_URL") {
		t.Errorf("server must not require the admin URL: %s", errOut.String())
	}
}

func TestMigrateRequiresAdminURL(t *testing.T) {
	t.Setenv("SCANX_DATABASE_ADMIN_URL", "")
	var out, errOut bytes.Buffer
	if code := run([]string{"migrate"}, &out, &errOut); code != exitConfig {
		t.Fatalf("code %d", code)
	}
	if !strings.Contains(errOut.String(), "SCANX_DATABASE_ADMIN_URL") {
		t.Errorf("stderr: %s", errOut.String())
	}
}

func TestGenCert(t *testing.T) {
	dir := t.TempDir()
	var out, errOut bytes.Buffer
	if code := run([]string{"gen-cert", "--dir", dir, "--hosts", "a.test, 10.0.0.1"}, &out, &errOut); code != exitOK {
		t.Fatalf("code %d: %s", code, errOut.String())
	}
	if code := run([]string{"gen-cert", "--dir", dir, "--hosts", " , "}, &out, &errOut); code != exitScanError {
		t.Fatalf("empty hosts should fail, got %d", code)
	}
}
