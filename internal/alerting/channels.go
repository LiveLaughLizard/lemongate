package alerting

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/mail"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"lemongate/internal/hooks"
	"lemongate/internal/secret"
)

type ChannelKind string

const (
	KindSlack   ChannelKind = "slack"
	KindWebhook ChannelKind = "webhook"
	KindEmail   ChannelKind = "email"

	KindMattermost ChannelKind = "mattermost"
)

var ChannelKinds = []ChannelKind{KindSlack, KindMattermost, KindWebhook, KindEmail}

// ChannelConfig is stored encrypted (alert_channels.config_enc).
type ChannelConfig struct {
	// Slack incoming webhook URL, or the generic webhook endpoint.
	URL string `json:"url,omitempty"`
	// Webhook: extra request headers and optional HMAC signing secret.
	Headers map[string]string `json:"headers,omitempty"`
	Secret  string            `json:"secret,omitempty"`
	// Slack / Mattermost: text prepended to critical alerts, e.g. "<!channel>" or "@channel".
	Mention string `json:"mention,omitempty"`
	// Mattermost: optional overrides for the posting channel, display name and avatar
	// (the webhook must allow overrides for Channel/Username/IconURL to take effect).
	Channel  string `json:"channel,omitempty"`
	Username string `json:"username,omitempty"`
	IconURL  string `json:"icon_url,omitempty"`
	// Email recipients.
	Recipients []string `json:"recipients,omitempty"`
}

// Channel is an alert destination.
type Channel struct {
	ID          string        `json:"id"`
	Name        string        `json:"name"`
	Kind        ChannelKind   `json:"kind"`
	Config      ChannelConfig `json:"-"`
	ConfigErr   error         `json:"-"`
	Events      []string      `json:"events"`
	MinSeverity string        `json:"min_severity"`
	Enabled     bool          `json:"enabled"`
	CreatedAt   time.Time     `json:"created_at"`
	UpdatedAt   time.Time     `json:"updated_at"`
	// Delivery stats over the last 7 days (populated by ListChannels).
	Sent7d     int        `json:"sent_7d"`
	Failed7d   int        `json:"failed_7d"`
	LastSentAt *time.Time `json:"last_sent_at"`
	LastError  string     `json:"last_error"`
}

// Matches reports whether the channel should receive the event.
func (c Channel) Matches(ev hooks.Event) bool {
	if !c.Enabled || c.ConfigErr != nil {
		return false
	}
	if len(c.Events) > 0 && !slices.Contains(c.Events, ev.Kind) {
		return false
	}
	return SeverityRank(ev.Severity) >= SeverityRank(c.MinSeverity)
}

// Target is a short, non-secret description of where the channel delivers.
func (c Channel) Target() string {
	switch c.Kind {
	case KindSlack, KindMattermost, KindWebhook:
		t := RedactURL(c.Config.URL)
		if c.Kind == KindMattermost && c.Config.Channel != "" {
			t += " → " + c.Config.Channel
		}
		return t
	case KindEmail:
		return strings.Join(c.Config.Recipients, ", ")
	}
	return ""
}

// RedactURL keeps scheme and host and hides the path/query (which often carries
// the secret for incoming webhooks).
func RedactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return secret.Hint(raw)
	}
	tail := ""
	if p := strings.Trim(u.Path, "/"); p != "" {
		if len(p) > 4 {
			tail = "/…" + p[len(p)-4:]
		} else {
			tail = "/…"
		}
	}
	return u.Scheme + "://" + u.Host + tail
}

// Validate checks the config for the given kind.
func (c ChannelConfig) Validate(kind ChannelKind) error {
	switch kind {
	case KindSlack, KindMattermost, KindWebhook:
		if kind == KindMattermost && c.IconURL != "" {
			if u, err := url.Parse(c.IconURL); err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
				return errors.New("icon URL must be a valid http(s) URL")
			}
		}
		if kind == KindMattermost && strings.ContainsAny(c.Channel, " \r\n") {
			return errors.New("channel must be a channel name such as town-square (no spaces)")
		}
		u, err := url.Parse(c.URL)
		if c.URL == "" || err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
			return errors.New("enter a valid http(s) URL")
		}
		for k := range c.Headers {
			if k == "" || strings.ContainsAny(k, " :\r\n") {
				return fmt.Errorf("invalid header name %q", k)
			}
		}
	case KindEmail:
		if len(c.Recipients) == 0 {
			return errors.New("add at least one recipient")
		}
		for _, r := range c.Recipients {
			if _, err := mail.ParseAddress(r); err != nil {
				return fmt.Errorf("invalid email address %q", r)
			}
		}
	default:
		return fmt.Errorf("unknown channel kind %q", kind)
	}
	return nil
}

const chanCols = `c.id, c.name, c.kind, c.config_enc, c.events, c.min_severity, c.enabled, c.created_at, c.updated_at`

func (a *Alerter) scanChannel(row pgx.Row, extra ...any) (Channel, error) {
	var c Channel
	var kind string
	var enc []byte
	dest := append([]any{&c.ID, &c.Name, &kind, &enc, &c.Events, &c.MinSeverity, &c.Enabled, &c.CreatedAt, &c.UpdatedAt}, extra...)
	if err := row.Scan(dest...); err != nil {
		return c, err
	}
	c.Kind = ChannelKind(kind)
	if c.Events == nil {
		c.Events = []string{}
	}
	plain, err := a.box.Open(enc)
	if err == nil {
		err = json.Unmarshal(plain, &c.Config)
	}
	c.ConfigErr = err
	return c, nil
}

// ListChannels returns all channels with 7-day delivery stats.
func (a *Alerter) ListChannels(ctx context.Context) ([]Channel, error) {
	rows, err := a.pool.Query(ctx, `SELECT `+chanCols+`,
		COALESCE(h.sent,0), COALESCE(h.failed,0), h.last_at,
		COALESCE((SELECT error FROM alert_history e WHERE e.channel = c.name AND NOT e.ok ORDER BY e.at DESC LIMIT 1), '')
		FROM alert_channels c
		LEFT JOIN (SELECT channel, count(*) FILTER (WHERE ok) AS sent, count(*) FILTER (WHERE NOT ok) AS failed, max(at) AS last_at
			FROM alert_history WHERE at > now() - interval '7 days' AND channel <> '' GROUP BY channel) h ON h.channel = c.name
		ORDER BY c.name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Channel{}
	for rows.Next() {
		var sent, failed int
		var last *time.Time
		var lastErr string
		c, err := a.scanChannel(rows, &sent, &failed, &last, &lastErr)
		if err != nil {
			return nil, err
		}
		c.Sent7d, c.Failed7d, c.LastSentAt, c.LastError = sent, failed, last, lastErr
		out = append(out, c)
	}
	return out, rows.Err()
}

func (a *Alerter) GetChannel(ctx context.Context, id string) (Channel, error) {
	c, err := a.scanChannel(a.pool.QueryRow(ctx, `SELECT `+chanCols+` FROM alert_channels c WHERE c.id::text = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return c, ErrNotFound
	}
	return c, err
}

// ErrDuplicateName is returned when a channel name is taken.
var ErrDuplicateName = errors.New("a channel with that name already exists")

// SaveChannel inserts (empty ID) or updates a channel and returns its ID.
func (a *Alerter) SaveChannel(ctx context.Context, c Channel) (string, error) {
	if c.Name = strings.TrimSpace(c.Name); c.Name == "" {
		return "", errors.New("name is required")
	}
	if !slices.Contains(ChannelKinds, c.Kind) {
		return "", fmt.Errorf("unknown channel kind %q", c.Kind)
	}
	if err := c.Config.Validate(c.Kind); err != nil {
		return "", err
	}
	if !slices.Contains(Severities, c.MinSeverity) {
		c.MinSeverity = "info"
	}
	if c.Events == nil {
		c.Events = []string{}
	}
	plain, _ := json.Marshal(c.Config)
	enc, err := a.box.Seal(plain)
	if err != nil {
		return "", err
	}
	if c.ID == "" {
		err = a.pool.QueryRow(ctx, `INSERT INTO alert_channels (name, kind, config_enc, events, min_severity, enabled)
			VALUES ($1,$2,$3,$4,$5,$6) RETURNING id`, c.Name, string(c.Kind), enc, c.Events, c.MinSeverity, c.Enabled).Scan(&c.ID)
	} else {
		var tag pgconn.CommandTag
		tag, err = a.pool.Exec(ctx, `UPDATE alert_channels SET name=$2, kind=$3, config_enc=$4, events=$5, min_severity=$6,
			enabled=$7, updated_at=now() WHERE id=$1`, c.ID, c.Name, string(c.Kind), enc, c.Events, c.MinSeverity, c.Enabled)
		if err == nil && tag.RowsAffected() == 0 {
			err = ErrNotFound
		}
	}
	var pg *pgconn.PgError
	if errors.As(err, &pg) && pg.Code == "23505" {
		return "", ErrDuplicateName
	}
	return c.ID, err
}

func (a *Alerter) SetChannelEnabled(ctx context.Context, id string, enabled bool) error {
	tag, err := a.pool.Exec(ctx, `UPDATE alert_channels SET enabled=$2, updated_at=now() WHERE id::text=$1`, id, enabled)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

func (a *Alerter) DeleteChannel(ctx context.Context, id string) error {
	tag, err := a.pool.Exec(ctx, `DELETE FROM alert_channels WHERE id::text=$1`, id)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// HistoryEntry is one alert_history row.
type HistoryEntry struct {
	ID        int64     `json:"id"`
	At        time.Time `json:"at"`
	Event     string    `json:"event"`
	Severity  string    `json:"severity"`
	Title     string    `json:"title"`
	Body      string    `json:"body"`
	DedupeKey string    `json:"dedupe_key"`
	Channel   string    `json:"channel"`
	OK        bool      `json:"ok"`
	Error     string    `json:"error"`
}

type HistoryFilter struct {
	Event    string
	Severity string
	Channel  string
	Status   string // ok | failed | undelivered
	Search   string
	Limit    int
	Offset   int
}

func (a *Alerter) History(ctx context.Context, f HistoryFilter) ([]HistoryEntry, error) {
	if f.Limit <= 0 || f.Limit > 500 {
		f.Limit = 100
	}
	rows, err := a.pool.Query(ctx, `SELECT id, at, event, severity, title, body, dedupe_key, channel, ok, error FROM alert_history
		WHERE ($1 = '' OR event = $1) AND ($2 = '' OR severity = $2) AND ($3 = '' OR channel = $3)
		AND ($4 = '' OR ($4 = 'ok' AND ok AND channel <> '') OR ($4 = 'failed' AND NOT ok) OR ($4 = 'undelivered' AND channel = ''))
		AND ($5 = '' OR title ILIKE '%'||$5||'%' OR body ILIKE '%'||$5||'%')
		ORDER BY at DESC, id DESC LIMIT $6 OFFSET $7`, f.Event, f.Severity, f.Channel, f.Status, f.Search, f.Limit, f.Offset)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (HistoryEntry, error) {
		var h HistoryEntry
		err := r.Scan(&h.ID, &h.At, &h.Event, &h.Severity, &h.Title, &h.Body, &h.DedupeKey, &h.Channel, &h.OK, &h.Error)
		return h, err
	})
}

// HistoryStats summarizes the last 24 hours.
type HistoryStats struct {
	Events24h   int
	Critical24h int
	Failed24h   int
}

func (a *Alerter) Stats(ctx context.Context) (HistoryStats, error) {
	var s HistoryStats
	err := a.pool.QueryRow(ctx, `SELECT count(DISTINCT (event, title, date_trunc('second', at)))::int,
		count(DISTINCT (event, title, date_trunc('second', at))) FILTER (WHERE severity = 'critical')::int,
		count(*) FILTER (WHERE NOT ok)::int
		FROM alert_history WHERE at > now() - interval '24 hours' AND event <> 'test'`).Scan(&s.Events24h, &s.Critical24h, &s.Failed24h)
	return s, err
}
