package dbscan

import (
	"errors"
	"path"
	"strings"
)

// Profile is an organization's rule configuration. The zero value of every
// field means "scanX default" (best practice), so stored profiles keep
// working when new options are added.
type Profile struct {
	// Language names are expected in: en (default), tr, any.
	Language string `json:"language,omitempty"`
	// TableCase / ColumnCase: auto (consistency with the dominant style,
	// default), snake, pascal, camel, upper_snake.
	TableCase  string `json:"table_case,omitempty"`
	ColumnCase string `json:"column_case,omitempty"`
	// TableNumber: auto (default), singular, plural, any.
	TableNumber string `json:"table_number,omitempty"`
	// MaxNameLength for table and column names (default 50).
	MaxNameLength int `json:"max_name_length,omitempty"`
	// MaxColumns per table (default 60).
	MaxColumns int `json:"max_columns,omitempty"`
	// AuditNames fixes the expected name per audit concept (created,
	// updated, deleted, deleted_flag, created_by, updated_by); empty = the
	// most used variant in the database.
	AuditNames map[string]string `json:"audit_names,omitempty"`
	// RequireAudit expects created/updated timestamps on every table.
	RequireAudit *bool `json:"require_audit,omitempty"`
	// Exclude are object patterns (globs on "schema.table" or "table",
	// case-insensitive) left out of the scan; Default excludes are added.
	Exclude []string `json:"exclude,omitempty"`
	// Rules switches rules on/off and overrides their severity.
	Rules map[string]RuleSetting `json:"rules,omitempty"`
	// FailOn is the quality gate (critical..info, none); default high.
	FailOn string `json:"fail_on,omitempty"`
}

// RuleSetting overrides one rule.
type RuleSetting struct {
	Enabled  *bool  `json:"enabled,omitempty"`
	Severity string `json:"severity,omitempty"`
}

// Case styles.
const (
	CaseAuto       = "auto"
	CaseSnake      = "snake"
	CasePascal     = "pascal"
	CaseCamel      = "camel"
	CaseUpperSnake = "upper_snake"
)

// DefaultExcludes are migration/tool tables that follow their tool's own
// conventions.
var DefaultExcludes = []string{
	"__EFMigrationsHistory", "*.__EFMigrationsHistory", "flyway_schema_history", "*.flyway_schema_history",
	"schema_migrations", "*.schema_migrations", "goose_db_version", "*.goose_db_version",
	"databasechangelog*", "*.databasechangelog*", "sysdiagrams", "*.sysdiagrams", "ar_internal_metadata",
	"*.ar_internal_metadata", "django_*", "*.django_*", "knex_migrations*", "*.knex_migrations*",
	"hangfire.*", "HangFire.*", "_prisma_migrations", "*._prisma_migrations", "spatial_ref_sys", "*.spatial_ref_sys",
	"__diesel_schema_migrations", "*.__diesel_schema_migrations", "__MigrationHistory", "*.__MigrationHistory",
}

// Effective returns the profile with defaults filled in.
func (p Profile) Effective() Profile {
	if p.Language == "" {
		p.Language = "en"
	}
	if p.TableCase == "" {
		p.TableCase = CaseAuto
	}
	if p.ColumnCase == "" {
		p.ColumnCase = CaseAuto
	}
	if p.TableNumber == "" {
		p.TableNumber = CaseAuto
	}
	if p.MaxNameLength <= 0 {
		p.MaxNameLength = 50
	}
	if p.MaxColumns <= 0 {
		p.MaxColumns = 60
	}
	if p.RequireAudit == nil {
		t := true
		p.RequireAudit = &t
	}
	if p.FailOn == "" {
		p.FailOn = "high"
	}
	return p
}

// Validate checks user input.
func (p Profile) Validate() error {
	in := func(v string, ok ...string) bool {
		if v == "" {
			return true
		}
		for _, o := range ok {
			if v == o {
				return true
			}
		}
		return false
	}
	cases := []string{CaseAuto, CaseSnake, CasePascal, CaseCamel, CaseUpperSnake}
	switch {
	case !in(p.Language, "en", "tr", "any"):
		return errors.New("language")
	case !in(p.TableCase, cases...), !in(p.ColumnCase, cases...):
		return errors.New("case")
	case !in(p.TableNumber, CaseAuto, "singular", "plural", "any"):
		return errors.New("table_number")
	case p.MaxNameLength < 0 || p.MaxNameLength > 128, p.MaxColumns < 0 || p.MaxColumns > 1000:
		return errors.New("limits")
	case !in(p.FailOn, "critical", "high", "medium", "low", "info", "none"):
		return errors.New("fail_on")
	case len(p.Exclude) > 200:
		return errors.New("exclude")
	}
	for id, rs := range p.Rules {
		if RuleByID(id) == nil || !in(rs.Severity, "high", "medium", "low", "info") {
			return errors.New("rules")
		}
	}
	for k := range p.AuditNames {
		if _, ok := auditConcepts[k]; !ok {
			return errors.New("audit_names")
		}
	}
	return nil
}

// RuleOn reports whether a rule runs and with which severity.
func (p Profile) RuleOn(r *RuleInfo) (bool, string) {
	on, sev := r.DefaultOn, r.Severity
	if rs, ok := p.Rules[r.ID]; ok {
		if rs.Enabled != nil {
			on = *rs.Enabled
		}
		if rs.Severity != "" {
			sev = rs.Severity
		}
	}
	return on, sev
}

// Excluded reports whether a table is left out.
func (p Profile) Excluded(schema, name string) bool {
	q := strings.ToLower(name)
	if schema != "" {
		q = strings.ToLower(schema) + "." + q
	}
	for _, pats := range [][]string{DefaultExcludes, p.Exclude} {
		for _, pat := range pats {
			pat = strings.ToLower(strings.TrimSpace(pat))
			if pat == "" {
				continue
			}
			if ok, _ := path.Match(pat, q); ok {
				return true
			}
			if ok, _ := path.Match(pat, strings.ToLower(name)); ok && !strings.Contains(pat, ".") {
				return true
			}
		}
	}
	return false
}
