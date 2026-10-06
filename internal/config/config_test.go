package config

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

// Values below are FAKE test fixtures.
var (
	fakeMasterKey  = base64.StdEncoding.EncodeToString([]byte("FAKE-0123456789abcdef0123456789a"))
	fakeSessionKey = "FAKE-session-key-0123456789abcdef0123"
	fakeDBURL      = "postgres://scanx_app:FAKEpass@db:5432/scanx?sslmode=disable"
)

func validEnv() map[string]string {
	return map[string]string{
		"SCANX_DATABASE_URL":       fakeDBURL,
		"SCANX_DATABASE_ADMIN_URL": "postgres://scanx:FAKEpass@db:5432/scanx?sslmode=disable",
		"SCANX_MASTER_KEY":         fakeMasterKey,
		"SCANX_SESSION_KEY":        fakeSessionKey,
	}
}

func TestDefaults(t *testing.T) {
	cfg, err := LoadFrom(map[string]string{})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Mode != ModeSelfHosted || cfg.HTTPAddr != ":8080" || cfg.WorkerConcurrency != 2 ||
		cfg.ScannerParallelism != 3 || cfg.ScanTimeout != 30*time.Minute || cfg.MaxRepoMB != 2048 ||
		cfg.SandboxRuntime != "runc" || cfg.AllowPrivateGitHosts || cfg.RetentionDays != 365 ||
		cfg.AllowSignup || cfg.LogLevel != "info" || cfg.LogFormat != "json" {
		t.Fatalf("unexpected defaults: %+v", cfg)
	}
	if err := cfg.Validate(0); err != nil {
		t.Fatalf("defaults must validate without requirements: %v", err)
	}
}

func TestValidFullConfig(t *testing.T) {
	cfg, err := LoadFrom(validEnv())
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.Validate(NeedDatabase | NeedMigrations | NeedKeys); err != nil {
		t.Fatalf("expected valid config: %v", err)
	}
	key, err := cfg.MasterKeyBytes()
	if err != nil || len(key) != 32 {
		t.Fatalf("master key: %v len=%d", err, len(key))
	}
}

func TestValidationErrors(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(map[string]string)
		req     Requirement
		wantErr string
	}{
		{"bad mode", func(e map[string]string) { e["SCANX_MODE"] = "cloud" }, 0, "SCANX_MODE"},
		{"bad base url", func(e map[string]string) { e["SCANX_BASE_URL"] = "ftp://x" }, 0, "SCANX_BASE_URL"},
		{"relative base url", func(e map[string]string) { e["SCANX_BASE_URL"] = "/x" }, 0, "SCANX_BASE_URL"},
		{"bad runtime", func(e map[string]string) { e["SCANX_SANDBOX_RUNTIME"] = "kata" }, 0, "SCANX_SANDBOX_RUNTIME"},
		{"bad log level", func(e map[string]string) { e["SCANX_LOG_LEVEL"] = "trace" }, 0, "SCANX_LOG_LEVEL"},
		{"bad log format", func(e map[string]string) { e["SCANX_LOG_FORMAT"] = "xml" }, 0, "SCANX_LOG_FORMAT"},
		{"concurrency zero", func(e map[string]string) { e["SCANX_WORKER_CONCURRENCY"] = "0" }, 0, "SCANX_WORKER_CONCURRENCY"},
		{"parallelism high", func(e map[string]string) { e["SCANX_SCANNER_PARALLELISM"] = "99" }, 0, "SCANX_SCANNER_PARALLELISM"},
		{"timeout short", func(e map[string]string) { e["SCANX_SCAN_TIMEOUT"] = "5s" }, 0, "SCANX_SCAN_TIMEOUT"},
		{"cpus zero", func(e map[string]string) { e["SCANX_SCANNER_CPUS"] = "0" }, 0, "SCANX_SCANNER_CPUS"},
		{"missing db", func(e map[string]string) { delete(e, "SCANX_DATABASE_URL") }, NeedDatabase, "SCANX_DATABASE_URL"},
		{"mysql db", func(e map[string]string) { e["SCANX_DATABASE_URL"] = "mysql://x" }, NeedDatabase, "postgres://"},
		{"missing admin db", func(e map[string]string) { delete(e, "SCANX_DATABASE_ADMIN_URL") }, NeedMigrations, "SCANX_DATABASE_ADMIN_URL"},
		{"missing master key", func(e map[string]string) { delete(e, "SCANX_MASTER_KEY") }, NeedKeys, "SCANX_MASTER_KEY"},
		{"short master key", func(e map[string]string) {
			e["SCANX_MASTER_KEY"] = base64.StdEncoding.EncodeToString([]byte("short"))
		}, NeedKeys, "32 bytes"},
		{"non-base64 master key", func(e map[string]string) { e["SCANX_MASTER_KEY"] = "%%%" }, NeedKeys, "base64"},
		{"short session key", func(e map[string]string) { e["SCANX_SESSION_KEY"] = "abc" }, NeedKeys, "SCANX_SESSION_KEY"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := validEnv()
			tc.mutate(e)
			cfg, err := LoadFrom(e)
			if err != nil {
				t.Fatal(err)
			}
			err = cfg.Validate(tc.req)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("want error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
}

func TestParseErrorOnBadType(t *testing.T) {
	if _, err := LoadFrom(map[string]string{"SCANX_WORKER_CONCURRENCY": "many"}); err == nil {
		t.Fatal("expected parse error")
	}
}

func TestValidateReportsAllErrors(t *testing.T) {
	cfg, err := LoadFrom(map[string]string{"SCANX_MODE": "x", "SCANX_LOG_FORMAT": "y"})
	if err != nil {
		t.Fatal(err)
	}
	msg := cfg.Validate(0).Error()
	if !strings.Contains(msg, "SCANX_MODE") || !strings.Contains(msg, "SCANX_LOG_FORMAT") {
		t.Fatalf("expected both errors, got %q", msg)
	}
}

func TestErrorsDoNotLeakSecrets(t *testing.T) {
	e := validEnv()
	e["SCANX_DATABASE_URL"] = "postgres://u:FAKEleak@%zz"
	cfg, err := LoadFrom(e)
	if err != nil {
		t.Fatal(err)
	}
	err = cfg.Validate(NeedDatabase)
	if err == nil {
		t.Fatal("expected error")
	}
	if strings.Contains(err.Error(), "FAKEleak") {
		t.Fatalf("error leaks password: %v", err)
	}
}
