package service

import (
	"context"
	"strings"

	"github.com/ininia/scanx/internal/auth"
	"github.com/ininia/scanx/internal/gitutil"
	"github.com/ininia/scanx/internal/store"
	"github.com/ininia/scanx/internal/store/db"
)

// ProjectInput creates or updates a project.
type ProjectInput struct {
	Name     string
	Slug     string
	RepoURL  string
	Provider string // empty = inferred from the URL host
	Branches []string
}

var providers = map[string]bool{"github": true, "gitlab": true, "gitea": true, "bitbucket": true, "generic": true}

func (in *ProjectInput) validate() (*gitutil.RepoURL, error) {
	repo, err := gitutil.ParseRepoURL(in.RepoURL)
	if err != nil {
		return nil, invalid("repo_url", "invalid")
	}
	if in.Name == "" {
		in.Name = repo.Name()
	}
	name, err := cleanName("name", in.Name, 1, 200)
	if err != nil {
		return nil, err
	}
	in.Name = name
	if in.Slug == "" {
		in.Slug = Slugify(name)
	}
	if err := validSlug(in.Slug); err != nil {
		return nil, err
	}
	if in.Provider == "" {
		in.Provider = repo.Provider
	}
	if !providers[in.Provider] {
		return nil, invalid("provider", "invalid")
	}
	var branches []string
	seen := map[string]bool{}
	for _, b := range in.Branches {
		b = strings.TrimSpace(b)
		if b == "" || seen[b] {
			continue
		}
		if len(b) > 200 || strings.HasPrefix(b, "-") || strings.Contains(b, "..") || strings.ContainsAny(b, " ~^:?[\\\x00") { // "*" allowed: glob for webhook filters
			return nil, invalid("branches", "invalid")
		}
		seen[b] = true
		branches = append(branches, b)
	}
	if len(branches) == 0 {
		branches = []string{"main", "master"}
	}
	if len(branches) > 50 {
		return nil, invalid("branches", "too_many")
	}
	in.Branches = branches
	return repo, nil
}

// CreateProject adds a repository to the org.
func (s *Service) CreateProject(ctx context.Context, o *OrgCtx, in ProjectInput, m Meta) (*db.Project, error) {
	if err := o.Require(auth.ActProjectWrite, "write"); err != nil {
		return nil, err
	}
	if _, err := in.validate(); err != nil {
		return nil, err
	}
	var p db.Project
	err := s.db.Tx(ctx, o.Scope(), func(q *db.Queries) error {
		var err error
		p, err = q.CreateProject(ctx, db.CreateProjectParams{
			ID: newID(), OrgID: o.Org.ID, Name: in.Name, Slug: in.Slug, RepoUrl: in.RepoURL, Provider: in.Provider,
			AuthMode: "deploy_key", Branches: in.Branches,
		})
		if err != nil {
			if isUniqueViolation(err) {
				return invalid("slug", "taken")
			}
			return err
		}
		if _, err := s.createDeployKey(ctx, q, &p); err != nil {
			return err
		}
		if _, err := s.createWebhookSecret(ctx, q, &p); err != nil {
			return err
		}
		return audit(ctx, q, &o.Org.ID, &o.P.UserID, "project.created", "project", p.ID.String(), m,
			map[string]any{"slug": p.Slug, "repo_url": p.RepoUrl})
	})
	if err != nil {
		return nil, wrap("create project", err)
	}
	return &p, nil
}

// ListProjects lists active projects (paged).
func (s *Service) ListProjects(ctx context.Context, o *OrgCtx, page, perPage int) ([]db.Project, int64, error) {
	if err := o.Require(auth.ActProjectRead, "read"); err != nil {
		return nil, 0, err
	}
	if perPage <= 0 || perPage > 200 {
		perPage = 50
	}
	if page < 1 {
		page = 1
	}
	var out []db.Project
	var total int64
	err := s.db.Tx(ctx, o.Scope(), func(q *db.Queries) error {
		var err error
		if total, err = q.CountProjects(ctx, db.CountProjectsParams{OrgID: o.Org.ID}); err != nil {
			return err
		}
		out, err = q.ListProjects(ctx, db.ListProjectsParams{OrgID: o.Org.ID, Limit: int32(perPage), Offset: int32((page - 1) * perPage)}) //nolint:gosec // bounded
		return err
	})
	return out, total, wrap("list projects", err)
}

// GetProject returns a project by slug.
func (s *Service) GetProject(ctx context.Context, o *OrgCtx, slug string) (*db.Project, error) {
	if err := o.Require(auth.ActProjectRead, "read"); err != nil {
		return nil, err
	}
	if validSlug(slug) != nil {
		return nil, ErrNotFound
	}
	var p db.Project
	err := s.db.Tx(ctx, o.Scope(), func(q *db.Queries) error {
		var err error
		p, err = q.GetProjectBySlug(ctx, db.GetProjectBySlugParams{OrgID: o.Org.ID, Slug: slug})
		return store.NotFound(err)
	})
	if err != nil {
		return nil, wrap("get project", err)
	}
	return &p, nil
}

// UpdateProject changes a project's settings.
func (s *Service) UpdateProject(ctx context.Context, o *OrgCtx, slug string, in ProjectInput, m Meta) (*db.Project, error) {
	cur, err := s.GetProject(ctx, o, slug)
	if err != nil {
		return nil, err
	}
	if err := o.Require(auth.ActProjectWrite, "write"); err != nil {
		return nil, err
	}
	in.Slug = cur.Slug
	if in.RepoURL == "" {
		in.RepoURL = cur.RepoUrl
	}
	if in.Name == "" {
		in.Name = cur.Name
	}
	if in.Branches == nil {
		in.Branches = cur.Branches
	}
	if _, err := in.validate(); err != nil {
		return nil, err
	}
	var p db.Project
	err = s.db.Tx(ctx, o.Scope(), func(q *db.Queries) error {
		var err error
		p, err = q.UpdateProject(ctx, db.UpdateProjectParams{
			OrgID: o.Org.ID, ID: cur.ID, Name: in.Name, RepoUrl: in.RepoURL, Provider: in.Provider,
			Branches: in.Branches, ScheduleCron: cur.ScheduleCron,
		})
		if err != nil {
			return store.NotFound(err)
		}
		return audit(ctx, q, &o.Org.ID, &o.P.UserID, "project.updated", "project", cur.ID.String(), m, nil)
	})
	return &p, wrap("update project", err)
}

// DeleteProject removes a project and everything stored for it.
func (s *Service) DeleteProject(ctx context.Context, o *OrgCtx, slug string, m Meta) error {
	cur, err := s.GetProject(ctx, o, slug)
	if err != nil {
		return err
	}
	if err := o.Require(auth.ActProjectDelete, "write"); err != nil {
		return err
	}
	return wrap("delete project", s.db.Tx(ctx, o.Scope(), func(q *db.Queries) error {
		n, err := q.DeleteProject(ctx, db.DeleteProjectParams{OrgID: o.Org.ID, ID: cur.ID})
		if err != nil {
			return err
		}
		if n == 0 {
			return ErrNotFound
		}
		return audit(ctx, q, &o.Org.ID, &o.P.UserID, "project.deleted", "project", cur.ID.String(), m,
			map[string]any{"slug": cur.Slug})
	}))
}
