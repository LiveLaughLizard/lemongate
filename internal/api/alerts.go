package api

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"lemongate/internal/alerting"
)

func (h *H) alertRoutes() []route {
	return []route{
		{Method: "GET", Path: "/alert-channels", Tag: "Alerts", Summary: "List alert channels", Desc: "Includes 7-day delivery stats. Secrets are never returned; `target` is a redacted destination.",
			Access: accessViewer, Resp: "list:AlertChannel", handler: h.listChannels},
		{Method: "POST", Path: "/alert-channels", Tag: "Alerts", Summary: "Create alert channel",
			Desc:   "`kind` is `slack` (incoming webhook `url`, optional `mention`), `mattermost` (incoming webhook `url`, optional `mention`, `channel`, `username`, `icon_url`), `webhook` (`url`, optional `headers` and HMAC `secret`) or `email` (`recipients`). Empty `events` subscribes to every event.",
			Access: accessViewer, Body: "AlertChannelInput", Resp: "AlertChannel", Status: 201,
			Example: `{"name": "ops-slack", "kind": "slack", "config": {"url": "https://hooks.example.com/services/T000/B000/XXXX"}, "events": ["deployment_down", "budget_threshold"], "min_severity": "warning", "enabled": true}`,
			handler: h.createChannel},
		{Method: "GET", Path: "/alert-channels/{id}", Tag: "Alerts", Summary: "Get alert channel", Access: accessViewer, Resp: "AlertChannel", handler: h.getChannel},
		{Method: "PATCH", Path: "/alert-channels/{id}", Tag: "Alerts", Summary: "Update alert channel",
			Desc:   "Partial update. Omitted or empty secret fields (`config.url`, `config.secret`, header values) keep their current values.",
			Access: accessViewer, Body: "AlertChannelInput", Resp: "AlertChannel", Example: `{"min_severity": "critical", "config": {"mention": "<!channel>"}}`, handler: h.updateChannel},
		{Method: "DELETE", Path: "/alert-channels/{id}", Tag: "Alerts", Summary: "Delete alert channel", Access: accessViewer, Resp: "Deleted", handler: h.deleteChannel},
		{Method: "POST", Path: "/alert-channels/{id}/test", Tag: "Alerts", Summary: "Send test alert", Desc: "Delivers a test event to this channel only. Returns 502 with the delivery error on failure.",
			Access: accessViewer, Resp: "TestResult", handler: h.testChannel},
		{Method: "GET", Path: "/alert-history", Tag: "Alerts", Summary: "Alert history", Desc: "One row per delivery attempt, newest first.", Access: accessViewer, Resp: "list:AlertHistoryEntry",
			Query: []qparam{{"event", "string", "Event kind, e.g. budget_threshold"}, {"severity", "string", "info, warning or critical"}, {"channel", "string", "Channel name"},
				{"status", "string", "ok, failed or undelivered"}, {"q", "string", "Search title and body"}, {"limit", "integer", "Default 100, max 500"}, {"offset", "integer", ""}},
			handler: h.alertHistory},
	}
}

// channelOut is the public channel shape (never carries secrets).
type channelOut struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Kind        string     `json:"kind"`
	Events      []string   `json:"events"`
	MinSeverity string     `json:"min_severity"`
	Enabled     bool       `json:"enabled"`
	Target      string     `json:"target"`
	HasSecret   bool       `json:"has_signing_secret"`
	HeaderNames []string   `json:"header_names"`
	Mention     string     `json:"mention,omitempty"`
	Channel     string     `json:"channel,omitempty"`
	Username    string     `json:"username,omitempty"`
	IconURL     string     `json:"icon_url,omitempty"`
	ConfigError string     `json:"config_error,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
	Sent7d      int        `json:"sent_7d"`
	Failed7d    int        `json:"failed_7d"`
	LastSentAt  *time.Time `json:"last_sent_at"`
	LastError   string     `json:"last_error"`
}

func toChannelOut(c alerting.Channel) channelOut {
	o := channelOut{ID: c.ID, Name: c.Name, Kind: string(c.Kind), Events: c.Events, MinSeverity: c.MinSeverity, Enabled: c.Enabled,
		Target: c.Target(), HasSecret: c.Config.Secret != "", HeaderNames: []string{}, Mention: c.Config.Mention,
		Channel: c.Config.Channel, Username: c.Config.Username, IconURL: c.Config.IconURL,
		CreatedAt: c.CreatedAt, UpdatedAt: c.UpdatedAt, Sent7d: c.Sent7d, Failed7d: c.Failed7d, LastSentAt: c.LastSentAt, LastError: c.LastError}
	if o.Events == nil {
		o.Events = []string{}
	}
	for k := range c.Config.Headers {
		o.HeaderNames = append(o.HeaderNames, k)
	}
	if c.ConfigErr != nil {
		o.ConfigError = "stored configuration cannot be decrypted"
	}
	return o
}

type channelConfigInput struct {
	URL        *string           `json:"url"`
	Headers    map[string]string `json:"headers"`
	Secret     *string           `json:"secret"`
	Mention    *string           `json:"mention"`
	Channel    *string           `json:"channel"`
	Username   *string           `json:"username"`
	IconURL    *string           `json:"icon_url"`
	Recipients []string          `json:"recipients"`
}

type channelInput struct {
	Name        *string             `json:"name"`
	Kind        *string             `json:"kind"`
	Events      []string            `json:"events"`
	MinSeverity *string             `json:"min_severity"`
	Enabled     *bool               `json:"enabled"`
	Config      *channelConfigInput `json:"config"`
}

// applyChannel merges the input onto c. Empty secret fields keep existing values.
func applyChannel(c *alerting.Channel, in channelInput) {
	if in.Name != nil {
		c.Name = *in.Name
	}
	if in.Kind != nil {
		c.Kind = alerting.ChannelKind(*in.Kind)
	}
	if in.Events != nil {
		c.Events = in.Events
	}
	if in.MinSeverity != nil {
		c.MinSeverity = *in.MinSeverity
	}
	if in.Enabled != nil {
		c.Enabled = *in.Enabled
	}
	cfg := in.Config
	if cfg == nil {
		return
	}
	if cfg.URL != nil && *cfg.URL != "" {
		c.Config.URL = *cfg.URL
	}
	if cfg.Secret != nil && *cfg.Secret != "" {
		c.Config.Secret = *cfg.Secret
	}
	if cfg.Mention != nil {
		c.Config.Mention = *cfg.Mention
	}
	if cfg.Channel != nil {
		c.Config.Channel = strings.TrimPrefix(*cfg.Channel, "~")
	}
	if cfg.Username != nil {
		c.Config.Username = *cfg.Username
	}
	if cfg.IconURL != nil {
		c.Config.IconURL = *cfg.IconURL
	}
	if cfg.Recipients != nil {
		c.Config.Recipients = cfg.Recipients
	}
	if cfg.Headers != nil {
		next := map[string]string{}
		for k, v := range cfg.Headers {
			if v == "" {
				v = c.Config.Headers[k] // keep the stored value
			}
			if v != "" {
				next[k] = v
			}
		}
		c.Config.Headers = next
	}
}

func (h *H) alerter(w http.ResponseWriter) (*alerting.Alerter, bool) {
	al, ok := h.d.Alerter.(*alerting.Alerter)
	if !ok || al == nil {
		fail(w, http.StatusServiceUnavailable, "unavailable", "alerting is not enabled")
		return nil, false
	}
	return al, true
}

func channelErr(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, alerting.ErrNotFound):
		notFound(w, "alert channel")
	case errors.Is(err, alerting.ErrDuplicateName):
		fail(w, http.StatusConflict, "conflict", err.Error())
	default:
		storeErr(w, err, "alert channel")
	}
}

// findChannel returns the channel with stats (ListChannels carries them).
func findChannel(r *http.Request, al *alerting.Alerter, id string) (alerting.Channel, error) {
	all, err := al.ListChannels(r.Context())
	if err != nil {
		return alerting.Channel{}, err
	}
	for _, c := range all {
		if c.ID == id {
			return c, nil
		}
	}
	return alerting.Channel{}, alerting.ErrNotFound
}

func (h *H) listChannels(w http.ResponseWriter, r *http.Request) {
	al, ok := h.alerter(w)
	if !ok {
		return
	}
	chans, err := al.ListChannels(r.Context())
	if err != nil {
		channelErr(w, err)
		return
	}
	out := make([]channelOut, 0, len(chans))
	for _, c := range chans {
		out = append(out, toChannelOut(c))
	}
	writeJSON(w, 200, list(out))
}

func (h *H) getChannel(w http.ResponseWriter, r *http.Request) {
	al, ok := h.alerter(w)
	if !ok {
		return
	}
	c, err := findChannel(r, al, param(r, "id"))
	if err != nil {
		channelErr(w, err)
		return
	}
	writeJSON(w, 200, toChannelOut(c))
}

func (h *H) saveChannel(w http.ResponseWriter, r *http.Request, al *alerting.Alerter, c alerting.Channel, before *alerting.Channel) {
	id, err := al.SaveChannel(r.Context(), c)
	if err != nil {
		if errors.Is(err, alerting.ErrNotFound) || errors.Is(err, alerting.ErrDuplicateName) || isDBError(err) {
			channelErr(w, err)
		} else {
			badRequest(w, "%s", err.Error()) // validation error
		}
		return
	}
	saved, err := findChannel(r, al, id)
	if err != nil {
		channelErr(w, err)
		return
	}
	out := toChannelOut(saved)
	if before == nil {
		h.d.Audit(r, "create", "alert_channel", id, "Created alert channel "+saved.Name+" via API", nil, out)
		writeJSON(w, 201, out)
		return
	}
	h.d.Audit(r, "update", "alert_channel", id, "Updated alert channel "+saved.Name+" via API", toChannelOut(*before), out)
	writeJSON(w, 200, out)
}

func (h *H) createChannel(w http.ResponseWriter, r *http.Request) {
	al, ok := h.alerter(w)
	if !ok {
		return
	}
	var in channelInput
	if !decode(w, r, &in) {
		return
	}
	c := alerting.Channel{MinSeverity: "info", Enabled: true}
	applyChannel(&c, in)
	h.saveChannel(w, r, al, c, nil)
}

func (h *H) updateChannel(w http.ResponseWriter, r *http.Request) {
	al, ok := h.alerter(w)
	if !ok {
		return
	}
	c, err := al.GetChannel(r.Context(), param(r, "id"))
	if err != nil {
		channelErr(w, err)
		return
	}
	if c.ConfigErr != nil {
		c.Config = alerting.ChannelConfig{}
	}
	before := c
	var in channelInput
	if !decode(w, r, &in) {
		return
	}
	applyChannel(&c, in)
	h.saveChannel(w, r, al, c, &before)
}

func (h *H) deleteChannel(w http.ResponseWriter, r *http.Request) {
	al, ok := h.alerter(w)
	if !ok {
		return
	}
	c, err := al.GetChannel(r.Context(), param(r, "id"))
	if err != nil {
		channelErr(w, err)
		return
	}
	if err := al.DeleteChannel(r.Context(), c.ID); err != nil {
		channelErr(w, err)
		return
	}
	h.d.Audit(r, "delete", "alert_channel", c.ID, "Deleted alert channel "+c.Name+" via API", toChannelOut(c), nil)
	writeJSON(w, 200, deleted(c.ID))
}

func (h *H) testChannel(w http.ResponseWriter, r *http.Request) {
	al, ok := h.alerter(w)
	if !ok {
		return
	}
	id := param(r, "id")
	if _, err := al.GetChannel(r.Context(), id); err != nil {
		channelErr(w, err)
		return
	}
	if err := al.SendTest(r.Context(), id, principal(r).Label()); err != nil {
		if errors.Is(err, alerting.ErrNotFound) {
			channelErr(w, err)
			return
		}
		writeJSON(w, http.StatusBadGateway, map[string]any{"ok": false, "error": apiError{Message: err.Error(), Type: "delivery_error"}})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (h *H) alertHistory(w http.ResponseWriter, r *http.Request) {
	al, ok := h.alerter(w)
	if !ok {
		return
	}
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	offset, _ := strconv.Atoi(q.Get("offset"))
	status := q.Get("status")
	if status != "" && status != "ok" && status != "failed" && status != "undelivered" {
		badRequest(w, "status must be ok, failed or undelivered")
		return
	}
	entries, err := al.History(r.Context(), alerting.HistoryFilter{Event: q.Get("event"), Severity: q.Get("severity"), Channel: q.Get("channel"),
		Status: status, Search: q.Get("q"), Limit: min(max(limit, 0), 500), Offset: max(offset, 0)})
	if err != nil {
		storeErr(w, err, "alert history")
		return
	}
	writeJSON(w, 200, list(entries))
}
