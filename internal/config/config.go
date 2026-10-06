// Package config loads and validates scanX configuration from environment
// variables (SCANX_*).
package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/caarlos0/env/v11"

	"github.com/ininia/scanx/internal/secret"
)

// Mode is the deployment mode of an instance.
type Mode string

// Supported modes.
const (
	ModeSelfHosted Mode = "selfhosted"
	ModeSaaS       Mode = "saas"
)

// Config is the full runtime configuration. Field names map 1:1 to the
// SCANX_* variables documented in docs (spec §14.2).
type Config struct {
	BaseURL string `env:"BASE_URL"`
	Mode    Mode   `env:"MODE" envDefault:"selfhosted"`

	HTTPAddr string `env:"HTTP_ADDR" envDefault:":8080"`

	// DatabaseURL is used by the application at runtime. It must point to a
	// role WITHOUT superuser/BYPASSRLS so row-level security is enforced.
	DatabaseURL secret.Secret `env:"DATABASE_URL"`
	// DatabaseAdminURL owns the schema and is used only to run migrations.
	DatabaseAdminURL secret.Secret `env:"DATABASE_ADMIN_URL"`

	MasterKey  secret.Secret `env:"MASTER_KEY"`
	SessionKey secret.Secret `env:"SESSION_KEY"`
	SetupToken secret.Secret `env:"SETUP_TOKEN"`

	WorkerConcurrency    int           `env:"WORKER_CONCURRENCY" envDefault:"2"`
	ScannerParallelism   int           `env:"SCANNER_PARALLELISM" envDefault:"3"`
	ScanTimeout          time.Duration `env:"SCAN_TIMEOUT" envDefault:"30m"`
	ScannerMemory        string        `env:"SCANNER_MEMORY" envDefault:"2g"`
	ScannerCPUs          float64       `env:"SCANNER_CPUS" envDefault:"2"`
	MaxRepoMB            int           `env:"MAX_REPO_MB" envDefault:"2048"`
	SandboxRuntime       string        `env:"SANDBOX_RUNTIME" envDefault:"runc"`
	AllowPrivateGitHosts bool          `env:"ALLOW_PRIVATE_GIT_HOSTS" envDefault:"false"`
	RetentionDays        int           `env:"RETENTION_DAYS" envDefault:"365"`
	AllowSignup          bool          `env:"ALLOW_SIGNUP" envDefault:"false"`

	LogLevel  string `env:"LOG_LEVEL" envDefault:"info"`
	LogFormat string `env:"LOG_FORMAT" envDefault:"json"`
}

// Requirement selects which settings a command needs.
type Requirement int

// Requirement flags; combine with |.
const (
	NeedDatabase Requirement = 1 << iota
	NeedMigrations
	NeedKeys
)

// Load reads configuration from the environment. Requirements are checked by
// Validate.
func Load() (*Config, error) {
	return LoadFrom(nil)
}

// LoadFrom reads configuration from the given map instead of the process
// environment (nil means os environment). Intended for tests.
func LoadFrom(environ map[string]string) (*Config, error) {
	cfg := &Config{}
	opts := env.Options{Prefix: "SCANX_"}
	if environ != nil {
		opts.Environment = environ
	}
	if err := env.ParseWithOptions(cfg, opts); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	return cfg, nil
}

// Validate checks values and that everything required by req is present.
// All problems are reported at once so operators can fix them in one go.
func (c *Config) Validate(req Requirement) error {
	var errs []error
	add := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }

	switch c.Mode {
	case ModeSelfHosted, ModeSaaS:
	default:
		add("SCANX_MODE must be %q or %q, got %q", ModeSelfHosted, ModeSaaS, c.Mode)
	}
	if c.BaseURL != "" {
		u, err := url.Parse(c.BaseURL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			add("SCANX_BASE_URL must be an absolute http(s) URL, got %q", c.BaseURL)
		}
	}
	switch c.SandboxRuntime {
	case "runc", "runsc":
	default:
		add("SCANX_SANDBOX_RUNTIME must be runc or runsc, got %q", c.SandboxRuntime)
	}
	switch strings.ToLower(c.LogLevel) {
	case "debug", "info", "warn", "error":
	default:
		add("SCANX_LOG_LEVEL must be debug|info|warn|error, got %q", c.LogLevel)
	}
	switch c.LogFormat {
	case "json", "text":
	default:
		add("SCANX_LOG_FORMAT must be json|text, got %q", c.LogFormat)
	}
	if c.WorkerConcurrency < 1 || c.WorkerConcurrency > 64 {
		add("SCANX_WORKER_CONCURRENCY must be between 1 and 64")
	}
	if c.ScannerParallelism < 1 || c.ScannerParallelism > 32 {
		add("SCANX_SCANNER_PARALLELISM must be between 1 and 32")
	}
	if c.ScanTimeout < time.Minute || c.ScanTimeout > 24*time.Hour {
		add("SCANX_SCAN_TIMEOUT must be between 1m and 24h")
	}
	if c.ScannerCPUs <= 0 {
		add("SCANX_SCANNER_CPUS must be positive")
	}
	if c.MaxRepoMB < 1 {
		add("SCANX_MAX_REPO_MB must be positive")
	}
	if c.RetentionDays < 1 {
		add("SCANX_RETENTION_DAYS must be positive")
	}

	if req&NeedDatabase != 0 {
		if err := validateDBURL(c.DatabaseURL); err != nil {
			add("SCANX_DATABASE_URL: %w", err)
		}
	}
	if req&NeedMigrations != 0 {
		if err := validateDBURL(c.DatabaseAdminURL); err != nil {
			add("SCANX_DATABASE_ADMIN_URL: %w", err)
		}
	}
	if req&NeedKeys != 0 {
		if _, err := c.MasterKeyBytes(); err != nil {
			add("SCANX_MASTER_KEY: %w", err)
		}
		if len(c.SessionKey.Reveal()) < 32 {
			add("SCANX_SESSION_KEY must be at least 32 characters")
		}
	}
	return errors.Join(errs...)
}

// MasterKeyBytes decodes the base64 master key and checks it is 32 bytes
// (AES-256).
func (c *Config) MasterKeyBytes() ([]byte, error) {
	if c.MasterKey.IsZero() {
		return nil, errors.New("is required (32 bytes, base64)")
	}
	b, err := base64.StdEncoding.DecodeString(c.MasterKey.Reveal())
	if err != nil {
		return nil, errors.New("must be valid standard base64")
	}
	if len(b) != 32 {
		return nil, fmt.Errorf("must decode to 32 bytes, got %d", len(b))
	}
	return b, nil
}

func validateDBURL(s secret.Secret) error {
	if s.IsZero() {
		return errors.New("is required")
	}
	u, err := url.Parse(s.Reveal())
	if err != nil {
		// Do not echo the URL: it contains a password.
		return errors.New("is not a valid URL")
	}
	if u.Scheme != "postgres" && u.Scheme != "postgresql" {
		return errors.New("must use the postgres:// scheme")
	}
	return nil
}
