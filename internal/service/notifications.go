package service

import (
	"context"
	"net/url"
	"strings"

	"github.com/google/uuid"

	"github.com/ininia/scanx/internal/auth"
	"github.com/ininia/scanx/internal/notify"
	"github.com/ininia/scanx/internal/store"
	"github.com/ininia/scanx/internal/store/db"
)

// SetNotifier enables test notifications from the UI.
func (s *Service) SetNotifier(n *notify.Sender) { s.notifier = n }

// ChannelAAD binds an encrypted channel target to its row.
func ChannelAAD(id uuid.UUID) []byte { return []byte("notify:" + id.String()) }

// Channel is a notification channel with its target masked.
type Channel struct {
	ID     uuid.UUID
	Kind   string
	Name   string
	Target string // masked: never shows webhook URL tokens
	Events []string
}

// MaskTarget hides the secret part of webhook URLs (they are bearer
// credentials) while keeping enough to recognize the destination.
func MaskTarget(kind, target string) string {
	if kind == notify.KindEmail {
		return target
	}
	u, err := url.Parse(target)
	if err != nil || u.Host == "" {
		return "•••"
	}
	return u.Scheme + "://" + u.Host + "/•••"
}

// ListChannels lists the org's notification channels.
func (s *Service) ListChannels(ctx context.Context, o *OrgCtx) ([]Channel, error) {
	if err := o.Require(auth.ActOrgRead, "read"); err != nil {
		return nil, err
	}
	var rows []db.NotificationChannel
	err := s.db.Tx(ctx, o.Scope(), func(q *db.Queries) error {
		var err error
		rows, err = q.ListNotificationChannels(ctx, o.Org.ID)
		return err
	})
	if err != nil {
		return nil, wrap("list channels", err)
	}
	out := make([]Channel, 0, len(rows))
	for _, r := range rows {
		t, err := s.box.Open(r.TargetEnc, r.Nonce, ChannelAAD(r.ID))
		masked := "•••"
		if err == nil {
			masked = MaskTarget(r.Kind, string(t))
		}
		out = append(out, Channel{ID: r.ID, Kind: r.Kind, Name: r.Name, Target: masked, Events: r.Events})
	}
	return out, nil
}

// CreateChannel adds a notification channel (admins).
func (s *Service) CreateChannel(ctx context.Context, o *OrgCtx, kind, name, target string, events []string, m Meta) (*Channel, error) {
	if err := o.Require(auth.ActOrgUpdate, "write"); err != nil {
		return nil, err
	}
	name, err := cleanName("name", name, 1, 100)
	if err != nil {
		return nil, err
	}
	target = strings.TrimSpace(target)
	if err := notify.ValidateTarget(kind, target); err != nil {
		return nil, invalid("target", "invalid")
	}
	var evs []string
	for _, e := range events {
		for _, known := range notify.AllEvents {
			if e == known {
				evs = append(evs, e)
			}
		}
	}
	if len(evs) == 0 {
		return nil, invalid("events", "required")
	}
	id := newID()
	ct, nonce, err := s.box.Seal([]byte(target), ChannelAAD(id))
	if err != nil {
		return nil, err
	}
	err = s.db.Tx(ctx, o.Scope(), func(q *db.Queries) error {
		if err := q.CreateNotificationChannel(ctx, db.CreateNotificationChannelParams{
			ID: id, OrgID: o.Org.ID, Kind: kind, Name: name, TargetEnc: ct, Nonce: nonce, Events: evs,
		}); err != nil {
			return err
		}
		return audit(ctx, q, &o.Org.ID, &o.P.UserID, "notification.channel_created", "notification_channel", id.String(), m,
			map[string]any{"kind": kind, "name": name})
	})
	if err != nil {
		return nil, wrap("create channel", err)
	}
	return &Channel{ID: id, Kind: kind, Name: name, Target: MaskTarget(kind, target), Events: evs}, nil
}

// DeleteChannel removes a channel.
func (s *Service) DeleteChannel(ctx context.Context, o *OrgCtx, channelID string, m Meta) error {
	if err := o.Require(auth.ActOrgUpdate, "write"); err != nil {
		return err
	}
	id, err := parseID(channelID)
	if err != nil {
		return err
	}
	return wrap("delete channel", s.db.Tx(ctx, o.Scope(), func(q *db.Queries) error {
		n, err := q.DeleteNotificationChannel(ctx, db.DeleteNotificationChannelParams{OrgID: o.Org.ID, ID: id})
		if err != nil {
			return err
		}
		if n == 0 {
			return ErrNotFound
		}
		return audit(ctx, q, &o.Org.ID, &o.P.UserID, "notification.channel_deleted", "notification_channel", id.String(), m, nil)
	}))
}

// TestChannel sends a test message through a channel.
func (s *Service) TestChannel(ctx context.Context, o *OrgCtx, channelID string) error {
	if err := o.Require(auth.ActOrgUpdate, "write"); err != nil {
		return err
	}
	id, err := parseID(channelID)
	if err != nil {
		return err
	}
	var ch db.NotificationChannel
	err = s.db.Tx(ctx, o.Scope(), func(q *db.Queries) error {
		var err error
		ch, err = q.GetNotificationChannel(ctx, db.GetNotificationChannelParams{OrgID: o.Org.ID, ID: id})
		return store.NotFound(err)
	})
	if err != nil {
		return wrap("test channel", err)
	}
	target, err := s.box.Open(ch.TargetEnc, ch.Nonce, ChannelAAD(ch.ID))
	if err != nil {
		return wrap("test channel", err)
	}
	if s.notifier == nil {
		return &DeliveryError{Msg: "notifications are not enabled on this server"}
	}
	if err := s.notifier.Send(ctx, ch.Kind, string(target), notify.Message{Event: notify.EventTest, Org: o.Org.Name}); err != nil {
		return &DeliveryError{Msg: err.Error()}
	}
	return nil
}

// DeliveryError is a failed test notification; its message is safe to show.
type DeliveryError struct{ Msg string }

func (e *DeliveryError) Error() string { return e.Msg }
