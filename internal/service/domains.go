package service

import (
	"context"
	"encoding/json"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/ininia/scanx/internal/auth"
	"github.com/ininia/scanx/internal/store"
	"github.com/ininia/scanx/internal/store/db"
	"github.com/ininia/scanx/internal/tlscheck"
)

// DomainInput adds or edits a monitored endpoint.
type DomainInput struct {
	Host     string // host name, IP, or a pasted URL
	Port     int
	Label    string
	Schedule string // hourly | daily
	Enabled  bool
}

// normalizeHost accepts "example.com", "https://example.com:8443/path" or
// "example.com:8443" and returns host and port.
func normalizeHost(in string, port int) (string, int, error) {
	in = strings.TrimSpace(in)
	if strings.Contains(in, "://") {
		u, err := url.Parse(in)
		if err != nil || u.Hostname() == "" {
			return "", 0, invalid("host", "invalid")
		}
		in = u.Host
	}
	in = strings.TrimSuffix(in, "/")
	if h, p, err := net.SplitHostPort(in); err == nil {
		in = h
		if n, err := strconv.Atoi(p); err == nil && port == 0 {
			port = n
		}
	}
	host := strings.ToLower(strings.TrimSuffix(strings.Trim(in, "[]"), "."))
	if host == "" || len(host) > 253 || strings.ContainsAny(host, " /\\@?#'\"`;,") {
		return "", 0, invalid("host", "invalid")
	}
	if net.ParseIP(host) == nil {
		labels := strings.Split(host, ".")
		if len(labels) < 2 {
			return "", 0, invalid("host", "invalid")
		}
		for _, l := range labels {
			if l == "" || len(l) > 63 || strings.HasPrefix(l, "-") || strings.HasSuffix(l, "-") {
				return "", 0, invalid("host", "invalid")
			}
		}
	}
	if port == 0 {
		port = 443
	}
	if port < 1 || port > 65535 {
		return "", 0, invalid("port", "invalid")
	}
	return host, port, nil
}

// CreateDomain starts monitoring an endpoint; the first check runs at once.
func (s *Service) CreateDomain(ctx context.Context, o *OrgCtx, in DomainInput, m Meta) (*db.MonitoredDomain, error) {
	if err := o.Require(auth.ActProjectWrite, "write"); err != nil {
		return nil, err
	}
	mod, err := s.requireModuleWrite(ctx, o, ModuleTLS)
	if err != nil {
		return nil, err
	}
	host, port, err := normalizeHost(in.Host, in.Port)
	if err != nil {
		return nil, err
	}
	label, err := cleanName("label", in.Label, 0, 100)
	if err != nil {
		return nil, err
	}
	if in.Schedule != "hourly" {
		in.Schedule = "daily"
	}
	var d db.MonitoredDomain
	err = s.db.Tx(ctx, o.Scope(), func(q *db.Queries) error {
		if mod.Settings.MaxItems > 0 {
			n, err := q.CountDomains(ctx, o.Org.ID)
			if err != nil {
				return err
			}
			if n >= int64(mod.Settings.MaxItems) {
				return invalid("host", "limit")
			}
		}
		var err error
		d, err = q.CreateDomain(ctx, db.CreateDomainParams{
			ID: newID(), OrgID: o.Org.ID, Host: host, Port: int32(port), Label: label, Schedule: in.Schedule, //nolint:gosec // validated
			CreatedBy: &o.P.UserID,
		})
		if err != nil {
			if isUniqueViolation(err) {
				return invalid("host", "taken")
			}
			return err
		}
		return audit(ctx, q, &o.Org.ID, &o.P.UserID, "domain.created", "domain", d.ID.String(), m,
			map[string]any{"host": host, "port": port})
	})
	if err != nil {
		return nil, wrap("create domain", err)
	}
	return &d, nil
}

// UpdateDomain changes label, schedule and the enabled switch.
func (s *Service) UpdateDomain(ctx context.Context, o *OrgCtx, id string, in DomainInput, m Meta) error {
	if err := o.Require(auth.ActProjectWrite, "write"); err != nil {
		return err
	}
	if _, err := s.requireModuleWrite(ctx, o, ModuleTLS); err != nil {
		return err
	}
	did, err := parseID(id)
	if err != nil {
		return err
	}
	label, err := cleanName("label", in.Label, 0, 100)
	if err != nil {
		return err
	}
	if in.Schedule != "hourly" {
		in.Schedule = "daily"
	}
	return wrap("update domain", s.db.Tx(ctx, o.Scope(), func(q *db.Queries) error {
		d, err := q.UpdateDomain(ctx, db.UpdateDomainParams{OrgID: o.Org.ID, ID: did, Label: label, Schedule: in.Schedule, Enabled: in.Enabled})
		if err != nil {
			return store.NotFound(err)
		}
		return audit(ctx, q, &o.Org.ID, &o.P.UserID, "domain.updated", "domain", d.ID.String(), m,
			map[string]any{"schedule": in.Schedule, "enabled": in.Enabled})
	}))
}

// DeleteDomain stops monitoring and removes the history.
func (s *Service) DeleteDomain(ctx context.Context, o *OrgCtx, id string, m Meta) error {
	if err := o.Require(auth.ActProjectDelete, "write"); err != nil {
		return err
	}
	did, err := parseID(id)
	if err != nil {
		return err
	}
	return wrap("delete domain", s.db.Tx(ctx, o.Scope(), func(q *db.Queries) error {
		d, err := q.GetDomain(ctx, db.GetDomainParams{OrgID: o.Org.ID, ID: did})
		if err != nil {
			return store.NotFound(err)
		}
		if _, err := q.DeleteDomain(ctx, db.DeleteDomainParams{OrgID: o.Org.ID, ID: did}); err != nil {
			return err
		}
		return audit(ctx, q, &o.Org.ID, &o.P.UserID, "domain.deleted", "domain", did.String(), m, map[string]any{"host": d.Host})
	}))
}

// CheckDomainNow queues an immediate check (picked up within a minute).
func (s *Service) CheckDomainNow(ctx context.Context, o *OrgCtx, id string) error {
	if err := o.Require(auth.ActScanTrigger, "write"); err != nil {
		return err
	}
	if err := s.RequireModule(ctx, o, ModuleTLS); err != nil {
		return err
	}
	did, err := parseID(id)
	if err != nil {
		return err
	}
	return wrap("check domain", s.db.Tx(ctx, o.Scope(), func(q *db.Queries) error {
		return q.RequestDomainCheck(ctx, db.RequestDomainCheckParams{OrgID: o.Org.ID, ID: did})
	}))
}

// ListDomains lists monitored endpoints (soonest expiry first).
func (s *Service) ListDomains(ctx context.Context, o *OrgCtx) ([]db.MonitoredDomain, error) {
	if err := o.Require(auth.ActProjectRead, "read"); err != nil {
		return nil, err
	}
	if err := s.RequireModule(ctx, o, ModuleTLS); err != nil {
		return nil, err
	}
	var out []db.MonitoredDomain
	err := s.db.Tx(ctx, o.Scope(), func(q *db.Queries) error {
		var err error
		out, err = q.ListDomains(ctx, o.Org.ID)
		return err
	})
	return out, wrap("list domains", err)
}

// DomainDetail is an endpoint with its latest result and history.
type DomainDetail struct {
	Domain  db.MonitoredDomain
	Last    *tlscheck.Result
	History []db.ListDomainChecksRow
}

// GetDomain returns an endpoint with its latest check.
func (s *Service) GetDomain(ctx context.Context, o *OrgCtx, id string) (*DomainDetail, error) {
	if err := o.Require(auth.ActProjectRead, "read"); err != nil {
		return nil, err
	}
	if err := s.RequireModule(ctx, o, ModuleTLS); err != nil {
		return nil, err
	}
	did, err := parseID(id)
	if err != nil {
		return nil, err
	}
	out := &DomainDetail{}
	err = s.db.Tx(ctx, o.Scope(), func(q *db.Queries) error {
		d, err := q.GetDomain(ctx, db.GetDomainParams{OrgID: o.Org.ID, ID: did})
		if err != nil {
			return store.NotFound(err)
		}
		out.Domain = d
		if d.LastCheckID != nil {
			if c, err := q.GetDomainCheck(ctx, db.GetDomainCheckParams{OrgID: o.Org.ID, ID: *d.LastCheckID}); err == nil {
				var r tlscheck.Result
				if json.Unmarshal(c.Result, &r) == nil {
					out.Last = &r
				}
			}
		}
		out.History, err = q.ListDomainChecks(ctx, db.ListDomainChecksParams{OrgID: o.Org.ID, DomainID: did, Limit: 60})
		return err
	})
	if err != nil {
		return nil, wrap("get domain", err)
	}
	return out, nil
}
