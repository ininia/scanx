package service

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"path"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/ininia/scanx/internal/gitfetch"
	"github.com/ininia/scanx/internal/store"
	"github.com/ininia/scanx/internal/store/db"
)

// WebhookProviders accepted in /api/v1/hooks/{provider}/{project}.
var WebhookProviders = map[string]bool{"github": true, "gitlab": true, "gitea": true, "bitbucket": true, "generic": true}

// WebhookResult is returned to the provider.
type WebhookResult struct {
	Status int        `json:"-"`
	Result string     `json:"result"` // queued | pong | ignored_event | ignored_branch | ignored_ref | duplicate | already_queued
	ScanID *uuid.UUID `json:"scan_id,omitempty"`
}

// Webhook errors (mapped to 401/404 without detail).
var (
	ErrWebhookSignature = errors.New("invalid webhook signature")
	ErrWebhookPayload   = errors.New("invalid webhook payload")
)

// pushEvent is the provider-independent content of a push.
type pushEvent struct {
	Ref     string
	Before  string // previous tip of the branch (diff base)
	Commit  string
	Message string
	Author  string
	Deleted bool
}

// HandleWebhook verifies and processes a webhook delivery (spec §6.4).
func (s *Service) HandleWebhook(ctx context.Context, provider, projectID string, h http.Header, body []byte) (*WebhookResult, error) {
	if !WebhookProviders[provider] {
		return nil, ErrNotFound
	}
	pid, err := parseID(projectID)
	if err != nil {
		return nil, err
	}
	var lp db.LookupWebhookProjectRow
	err = s.db.Tx(ctx, store.Scope{}, func(q *db.Queries) error {
		var err error
		lp, err = q.LookupWebhookProject(ctx, pid)
		return store.NotFound(err)
	})
	if err != nil {
		return nil, wrap("webhook", err)
	}
	if lp.Archived || len(lp.WebhookSecretEnc) == 0 {
		return nil, ErrNotFound
	}
	secret, err := s.box.Open(lp.WebhookSecretEnc, lp.WebhookSecretNonce, WebhookSecretAAD(lp.ID))
	if err != nil {
		return nil, wrap("webhook", err)
	}
	if !verifyWebhook(provider, h, body, secret) {
		return nil, ErrWebhookSignature
	}

	event, delivery := webhookMeta(provider, h, body)
	res := &WebhookResult{Status: http.StatusAccepted}
	var push *pushEvent
	switch {
	case isPing(provider, event):
		res.Status, res.Result = http.StatusOK, "pong"
	case !isPush(provider, event):
		res.Result = "ignored_event"
	default:
		push, err = parsePush(provider, body)
		if err != nil {
			return nil, ErrWebhookPayload
		}
		branch, isBranch := strings.CutPrefix(push.Ref, "refs/heads/")
		switch {
		case !isBranch || push.Deleted || push.Commit == "" || strings.Trim(push.Commit, "0") == "":
			res.Result = "ignored_ref"
		case !gitfetch.ValidBranch(branch):
			res.Result = "ignored_ref"
		case !BranchMatches(lp.Branches, branch):
			res.Result = "ignored_branch"
		default:
			push.Ref = branch
			res.Result = "queued"
		}
	}

	scope := store.Scope{OrgID: lp.OrgID}
	err = s.db.Tx(ctx, scope, func(q *db.Queries) error {
		if delivery != "" {
			_, err := q.InsertWebhookDelivery(ctx, db.InsertWebhookDeliveryParams{
				ID: newID(), OrgID: lp.OrgID, ProjectID: lp.ID, Provider: provider, DeliveryID: trunc(delivery, 200),
				Event: trunc(event, 100), Result: res.Result,
			})
			if errors.Is(err, pgx.ErrNoRows) {
				res.Status, res.Result = http.StatusOK, "duplicate"
				return nil
			}
			if err != nil {
				return err
			}
		}
		if res.Result != "queued" {
			return nil
		}
		p, err := q.GetProjectByID(ctx, lp.ID)
		if err != nil {
			return err
		}
		sc, err := enqueueScan(ctx, q, &p, TriggerWebhook, nil, push.Ref, strings.ToLower(push.Commit), push.Message, push.Author,
			strings.ToLower(push.Before))
		if err != nil {
			return err
		}
		if sc == nil {
			res.Status, res.Result = http.StatusOK, "already_queued"
			return nil
		}
		res.ScanID = &sc.ID
		return audit(ctx, q, &lp.OrgID, nil, "scan.triggered", "scan", sc.ID.String(), Meta{},
			map[string]any{"project": p.Slug, "branch": push.Ref, "trigger": TriggerWebhook, "provider": provider})
	})
	if err != nil {
		return nil, wrap("webhook", err)
	}
	return res, nil
}

// BranchMatches reports whether branch is selected by the project's branch
// list; entries may be glob patterns ("release/*").
func BranchMatches(patterns []string, branch string) bool {
	for _, p := range patterns {
		if p == branch {
			return true
		}
		if ok, err := path.Match(p, branch); err == nil && ok {
			return true
		}
	}
	return false
}

func hmacHex(secret, body []byte) string {
	m := hmac.New(sha256.New, secret)
	m.Write(body)
	return hex.EncodeToString(m.Sum(nil))
}

func equalHex(got, want string) bool {
	return subtle.ConstantTimeCompare([]byte(strings.ToLower(strings.TrimSpace(got))), []byte(want)) == 1
}

// verifyWebhook checks the provider's signature scheme.
func verifyWebhook(provider string, h http.Header, body, secret []byte) bool {
	want := hmacHex(secret, body)
	switch provider {
	case "github":
		sig, ok := strings.CutPrefix(h.Get("X-Hub-Signature-256"), "sha256=")
		return ok && equalHex(sig, want)
	case "gitea":
		sig := h.Get("X-Gitea-Signature")
		if sig == "" {
			sig = h.Get("X-Forgejo-Signature")
		}
		if sig == "" {
			sig, _ = strings.CutPrefix(h.Get("X-Hub-Signature-256"), "sha256=")
		}
		return sig != "" && equalHex(sig, want)
	case "gitlab":
		tok := h.Get("X-Gitlab-Token")
		return tok != "" && subtle.ConstantTimeCompare([]byte(tok), secret) == 1
	case "bitbucket":
		sig, ok := strings.CutPrefix(h.Get("X-Hub-Signature"), "sha256=")
		return ok && equalHex(sig, want)
	case "generic":
		sig, ok := strings.CutPrefix(h.Get("X-Scanx-Signature"), "sha256=")
		return ok && equalHex(sig, want)
	}
	return false
}

func webhookMeta(provider string, h http.Header, body []byte) (event, delivery string) {
	switch provider {
	case "github":
		event, delivery = h.Get("X-GitHub-Event"), h.Get("X-GitHub-Delivery")
	case "gitea":
		event, delivery = firstHeader(h, "X-Gitea-Event", "X-Forgejo-Event", "X-GitHub-Event"),
			firstHeader(h, "X-Gitea-Delivery", "X-Forgejo-Delivery", "X-GitHub-Delivery")
	case "gitlab":
		event, delivery = h.Get("X-Gitlab-Event"), firstHeader(h, "X-Gitlab-Event-UUID", "Idempotency-Key")
	case "bitbucket":
		event, delivery = h.Get("X-Event-Key"), firstHeader(h, "X-Request-UUID", "X-Hook-UUID")
	case "generic":
		event, delivery = h.Get("X-Scanx-Event"), h.Get("X-Scanx-Delivery")
		if event == "" {
			event = "push"
		}
	}
	if delivery == "" {
		// No delivery id: deduplicate identical bodies.
		sum := sha256.Sum256(body)
		delivery = "body:" + hex.EncodeToString(sum[:])
	}
	return event, delivery
}

func firstHeader(h http.Header, keys ...string) string {
	for _, k := range keys {
		if v := h.Get(k); v != "" {
			return v
		}
	}
	return ""
}

func isPing(provider, event string) bool {
	switch provider {
	case "github", "gitea":
		return event == "ping"
	case "bitbucket":
		return event == "diagnostics:ping"
	case "generic":
		return event == "ping"
	}
	return false
}

func isPush(provider, event string) bool {
	switch provider {
	case "github", "gitea", "generic":
		return event == "push"
	case "gitlab":
		return event == "Push Hook"
	case "bitbucket":
		return event == "repo:push"
	}
	return false
}

func parsePush(provider string, body []byte) (*pushEvent, error) {
	switch provider {
	case "github", "gitea":
		var p struct {
			Ref        string `json:"ref"`
			Before     string `json:"before"`
			After      string `json:"after"`
			Deleted    bool   `json:"deleted"`
			HeadCommit *struct {
				ID      string `json:"id"`
				Message string `json:"message"`
				Author  struct {
					Name  string `json:"name"`
					Email string `json:"email"`
				} `json:"author"`
			} `json:"head_commit"`
		}
		if err := json.Unmarshal(body, &p); err != nil {
			return nil, err
		}
		ev := &pushEvent{Ref: p.Ref, Before: p.Before, Commit: p.After, Deleted: p.Deleted}
		if p.HeadCommit != nil {
			if p.HeadCommit.ID != "" {
				ev.Commit = p.HeadCommit.ID
			}
			ev.Message = firstLine(p.HeadCommit.Message)
			ev.Author = authorString(p.HeadCommit.Author.Name, p.HeadCommit.Author.Email)
		}
		return ev, validCommit(ev)
	case "gitlab":
		var p struct {
			Ref         string `json:"ref"`
			Before      string `json:"before"`
			After       string `json:"after"`
			CheckoutSHA string `json:"checkout_sha"`
			Commits     []struct {
				ID      string `json:"id"`
				Message string `json:"message"`
				Author  struct {
					Name  string `json:"name"`
					Email string `json:"email"`
				} `json:"author"`
			} `json:"commits"`
		}
		if err := json.Unmarshal(body, &p); err != nil {
			return nil, err
		}
		ev := &pushEvent{Ref: p.Ref, Before: p.Before, Commit: p.CheckoutSHA}
		if ev.Commit == "" {
			ev.Commit = p.After
		}
		ev.Deleted = strings.Trim(p.After, "0") == ""
		for _, c := range p.Commits {
			if c.ID == ev.Commit {
				ev.Message, ev.Author = firstLine(c.Message), authorString(c.Author.Name, c.Author.Email)
			}
		}
		return ev, validCommit(ev)
	case "bitbucket":
		var p struct {
			Push struct {
				Changes []struct {
					Old *struct {
						Target struct {
							Hash string `json:"hash"`
						} `json:"target"`
					} `json:"old"`
					New *struct {
						Type   string `json:"type"`
						Name   string `json:"name"`
						Target struct {
							Hash    string `json:"hash"`
							Message string `json:"message"`
							Author  struct {
								Raw string `json:"raw"`
							} `json:"author"`
						} `json:"target"`
					} `json:"new"`
				} `json:"changes"`
			} `json:"push"`
		}
		if err := json.Unmarshal(body, &p); err != nil {
			return nil, err
		}
		for _, c := range p.Push.Changes {
			if c.New != nil && c.New.Type == "branch" {
				ev := &pushEvent{
					Ref: "refs/heads/" + c.New.Name, Commit: c.New.Target.Hash,
					Message: firstLine(c.New.Target.Message), Author: c.New.Target.Author.Raw,
				}
				return ev, validCommit(ev)
			}
		}
		return &pushEvent{Deleted: true}, nil
	case "generic":
		var p struct {
			Ref     string `json:"ref"`
			Branch  string `json:"branch"`
			Before  string `json:"before"`
			Commit  string `json:"commit"`
			Message string `json:"message"`
			Author  string `json:"author"`
		}
		if err := json.Unmarshal(body, &p); err != nil {
			return nil, err
		}
		ev := &pushEvent{Ref: p.Ref, Before: p.Before, Commit: p.Commit, Message: firstLine(p.Message), Author: p.Author}
		if ev.Ref == "" && p.Branch != "" {
			ev.Ref = "refs/heads/" + p.Branch
		}
		return ev, validCommit(ev)
	}
	return nil, ErrWebhookPayload
}

func validCommit(ev *pushEvent) error {
	c := strings.ToLower(ev.Commit)
	if c == "" {
		return nil
	}
	if len(c) != 40 && len(c) != 64 {
		return ErrWebhookPayload
	}
	for _, r := range c {
		if !strings.ContainsRune("0123456789abcdef", r) {
			return ErrWebhookPayload
		}
	}
	return nil
}

func firstLine(s string) string {
	s, _, _ = strings.Cut(strings.TrimSpace(s), "\n")
	return trunc(s, 500)
}

func authorString(name, email string) string {
	if email == "" {
		return name
	}
	return name + " <" + email + ">"
}
