package service

import (
	"context"
	"encoding/json"

	"github.com/google/uuid"

	"github.com/ininia/scanx/internal/auth"
	"github.com/ininia/scanx/internal/store"
	"github.com/ininia/scanx/internal/store/db"
)

// Modules.
const (
	ModuleRepo = "repo" // repository (code) scanning
	ModuleDB   = "db"   // database structure scanning
	ModuleTLS  = "tls"  // certificate, domain and TLS monitoring
)

// AllModules lists the modules in display order.
var AllModules = []string{ModuleRepo, ModuleDB, ModuleTLS}

// ModuleSettings are the instance admin's limits for one module of one
// organization. Zero values mean "no limit / allowed".
type ModuleSettings struct {
	// MaxItems caps projects (repo) or connections (db); 0 = unlimited.
	MaxItems int `json:"max_items,omitempty"`
	// NoSchedule forbids scheduled scans.
	NoSchedule bool `json:"no_schedule,omitempty"`
	// NoNotifications stops the module's notifications.
	NoNotifications bool `json:"no_notifications,omitempty"`
	// AdminsOnly lets only admins/owners change the module's objects.
	AdminsOnly bool `json:"admins_only,omitempty"`
}

// OrgModule is one module's entitlement.
type OrgModule struct {
	Module   string
	Enabled  bool
	Settings ModuleSettings
}

// Modules returns every module of an organization (defaults for modules
// without a stored row: enabled, no limits).
func (s *Service) Modules(ctx context.Context, orgID uuid.UUID) (map[string]OrgModule, error) {
	out := map[string]OrgModule{}
	for _, m := range AllModules {
		out[m] = OrgModule{Module: m, Enabled: true}
	}
	err := s.db.Tx(ctx, store.Scope{OrgID: orgID}, func(q *db.Queries) error {
		rows, err := q.ListOrgModules(ctx, orgID)
		if err != nil {
			return err
		}
		for _, r := range rows {
			om := OrgModule{Module: r.Module, Enabled: r.Enabled}
			_ = json.Unmarshal(r.Settings, &om.Settings)
			out[r.Module] = om
		}
		return nil
	})
	return out, wrap("modules", err)
}

// ModuleOf returns one module of the org (default: enabled).
func (s *Service) ModuleOf(ctx context.Context, o *OrgCtx, module string) OrgModule {
	mods, err := s.Modules(ctx, o.Org.ID)
	if err != nil {
		return OrgModule{Module: module, Enabled: true}
	}
	return mods[module]
}

// RequireModule fails with ErrForbidden when the module is switched off
// for the organization.
func (s *Service) RequireModule(ctx context.Context, o *OrgCtx, module string) error {
	if !s.ModuleOf(ctx, o, module).Enabled {
		return ErrForbidden
	}
	return nil
}

// requireModuleWrite also applies the "admins only" setting.
func (s *Service) requireModuleWrite(ctx context.Context, o *OrgCtx, module string) (OrgModule, error) {
	m := s.ModuleOf(ctx, o, module)
	if !m.Enabled || (m.Settings.AdminsOnly && !o.Role.AtLeast(auth.RoleAdmin)) {
		return m, ErrForbidden
	}
	return m, nil
}

// OrgModulesRow is one organization in the admin's module overview.
type OrgModulesRow struct {
	Org     db.ListAllOrgsRow
	Modules map[string]OrgModule
}

// AdminOrgModules lists every organization with its modules (instance
// admins only).
func (s *Service) AdminOrgModules(ctx context.Context, p *auth.Principal) ([]OrgModulesRow, error) {
	if p == nil || !p.IsSuperadmin {
		return nil, ErrForbidden
	}
	var out []OrgModulesRow
	err := s.db.Tx(ctx, store.Scope{UserID: p.UserID, Superadmin: true}, func(q *db.Queries) error {
		orgs, err := q.ListAllOrgs(ctx, db.ListAllOrgsParams{Limit: 1000, Offset: 0})
		if err != nil {
			return err
		}
		rows, err := q.ListAllOrgModules(ctx)
		if err != nil {
			return err
		}
		stored := map[uuid.UUID]map[string]OrgModule{}
		for _, r := range rows {
			om := OrgModule{Module: r.Module, Enabled: r.Enabled}
			_ = json.Unmarshal(r.Settings, &om.Settings)
			if stored[r.OrgID] == nil {
				stored[r.OrgID] = map[string]OrgModule{}
			}
			stored[r.OrgID][r.Module] = om
		}
		for _, o := range orgs {
			mods := map[string]OrgModule{}
			for _, m := range AllModules {
				mods[m] = OrgModule{Module: m, Enabled: true}
				if om, ok := stored[o.ID][m]; ok {
					mods[m] = om
				}
			}
			out = append(out, OrgModulesRow{Org: o, Modules: mods})
		}
		return nil
	})
	return out, wrap("admin modules", err)
}

// SetOrgModule changes one module of one organization (instance admins).
func (s *Service) SetOrgModule(ctx context.Context, p *auth.Principal, orgID uuid.UUID, module string, enabled bool, st ModuleSettings, m Meta) error {
	if p == nil || !p.IsSuperadmin {
		return ErrForbidden
	}
	valid := false
	for _, x := range AllModules {
		valid = valid || x == module
	}
	if !valid || st.MaxItems < 0 || st.MaxItems > 100000 {
		return invalid("module", "invalid")
	}
	raw, err := json.Marshal(st)
	if err != nil {
		return err
	}
	err = s.db.Tx(ctx, store.Scope{UserID: p.UserID, Superadmin: true}, func(q *db.Queries) error {
		if _, err := q.GetOrgByID(ctx, orgID); err != nil {
			return store.NotFound(err)
		}
		if err := q.UpsertOrgModule(ctx, db.UpsertOrgModuleParams{OrgID: orgID, Module: module, Enabled: enabled, Settings: raw}); err != nil {
			return err
		}
		return audit(ctx, q, &orgID, &p.UserID, "org.module_updated", "org", orgID.String(), m,
			map[string]any{"module": module, "enabled": enabled, "settings": st})
	})
	return wrap("set module", err)
}
