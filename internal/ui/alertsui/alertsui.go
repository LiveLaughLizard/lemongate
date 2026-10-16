// Package alertsui is the console area for alert channels, alert history and test sends.
package alertsui

import (
	"errors"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	"lemongate/internal/alerting"
	"lemongate/internal/auth"
	"lemongate/internal/settings"
	"lemongate/internal/ui"
)

const area = "alerts"

// maskedValue stands in for secret header values in the edit form; submitting it
// unchanged keeps the stored value.
const maskedValue = "••••••"

type H struct {
	d *ui.Deps
	a *alerting.Alerter
}

// Mount registers routes for this area on the session-protected router.
// Viewers (admin_viewer) can read; only admins can change channels or send tests.
func Mount(r chi.Router, d *ui.Deps, a *alerting.Alerter) {
	h := &H{d: d, a: a}
	r.Group(func(r chi.Router) {
		r.Use(ui.AdminWrites)
		r.Get("/ui/alerts", h.index)
		r.Get("/ui/alerts/channels", h.channels)
		r.Get("/ui/alerts/history", h.history)
		r.Get("/ui/alerts/history/{id}", h.historyDetail)
		r.Get("/ui/alerts/channels/new", h.newForm)
		r.Post("/ui/alerts/channels", h.create)
		r.Get("/ui/alerts/channels/{id}/edit", h.editForm)
		r.Post("/ui/alerts/channels/{id}", h.update)
		r.Post("/ui/alerts/channels/{id}/test", h.test)
		r.Post("/ui/alerts/channels/{id}/enable", h.setEnabled(true))
		r.Post("/ui/alerts/channels/{id}/disable", h.setEnabled(false))
		r.Post("/ui/alerts/channels/{id}/delete", h.delete)
	})
}

// --- index ---

type indexData struct {
	Stats      alerting.HistoryStats
	Alerting   settings.Alerting
	Thresholds []int
	Kinds      []alerting.EventKind
	Severities []string
	Channels   []alerting.Channel
	CanEdit    bool
	SMTP       bool
}

func (h *H) index(w http.ResponseWriter, r *http.Request) {
	p := auth.FromContext(r.Context())
	al := h.d.Settings.Current().Alerting
	th := append([]int{}, al.BudgetThresholds...)
	sort.Ints(th)
	data := indexData{Alerting: al, Thresholds: th, Kinds: alerting.EventKinds, Severities: alerting.Severities,
		CanEdit: p.IsAdmin(), SMTP: h.a.SMTPEnabled()}
	data.Stats, _ = h.a.Stats(r.Context())
	data.Channels, _ = h.a.ListChannels(r.Context())
	h.d.Render(w, r, "alerts/index", "alerts", "Alerts", data)
}

type channelView struct {
	alerting.Channel
	Target     string
	EventNames []string
}

type channelsData struct {
	Channels []channelView
	CanEdit  bool
	SMTP     bool
}

func kindLabel(k string) string {
	for _, e := range alerting.EventKinds {
		if e.Key == k {
			return e.Label
		}
	}
	return k
}

func (h *H) channels(w http.ResponseWriter, r *http.Request) {
	p := auth.FromContext(r.Context())
	list, err := h.a.ListChannels(r.Context())
	if err != nil {
		ui.Fail(w, 500, err.Error())
		return
	}
	data := channelsData{CanEdit: p.IsAdmin(), SMTP: h.a.SMTPEnabled()}
	for _, c := range list {
		v := channelView{Channel: c, Target: c.Target()}
		for _, e := range c.Events {
			v.EventNames = append(v.EventNames, kindLabel(e))
		}
		data.Channels = append(data.Channels, v)
	}
	h.d.Partial(w, r, 200, area, "alert-channels", data)
}

// --- history ---

type historyData struct {
	Entries  []alerting.HistoryEntry
	Filter   alerting.HistoryFilter
	Page     int
	HasMore  bool
	Filtered bool
}

const historyPageSize = 25

func (h *H) history(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	page, _ := strconv.Atoi(q.Get("page"))
	page = max(page, 1)
	f := alerting.HistoryFilter{Event: q.Get("event"), Severity: q.Get("severity"), Channel: q.Get("channel"),
		Status: q.Get("status"), Search: strings.TrimSpace(q.Get("q")), Limit: historyPageSize + 1, Offset: (page - 1) * historyPageSize}
	entries, err := h.a.History(r.Context(), f)
	if err != nil {
		ui.Fail(w, 500, err.Error())
		return
	}
	data := historyData{Filter: f, Page: page, Filtered: f.Event != "" || f.Severity != "" || f.Channel != "" || f.Status != "" || f.Search != ""}
	if len(entries) > historyPageSize {
		data.HasMore = true
		entries = entries[:historyPageSize]
	}
	data.Entries = entries
	h.d.Partial(w, r, 200, area, "alert-history", data)
}

func (h *H) historyDetail(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		ui.Fail(w, 404, "Alert not found")
		return
	}
	var e alerting.HistoryEntry
	err = h.d.Store.Pool.QueryRow(r.Context(), `SELECT id, at, event, severity, title, body, dedupe_key, channel, ok, error
		FROM alert_history WHERE id=$1`, id).Scan(&e.ID, &e.At, &e.Event, &e.Severity, &e.Title, &e.Body, &e.DedupeKey, &e.Channel, &e.OK, &e.Error)
	if err != nil {
		ui.Fail(w, 404, "Alert not found")
		return
	}
	h.d.Partial(w, r, 200, area, "alert-detail", e)
}

// --- create / edit ---

type formData struct {
	Channel    alerting.Channel
	IsNew      bool
	Error      string
	Kinds      []alerting.EventKind
	Severities []string
	SMTP       bool
	// Display hints for stored secrets (never the values).
	URLHint     string
	HasSecret   bool
	HeadersText string
}

func (h *H) form(c alerting.Channel, isNew bool) formData {
	fd := formData{Channel: c, IsNew: isNew, Kinds: alerting.EventKinds, Severities: alerting.Severities, SMTP: h.a.SMTPEnabled()}
	if !isNew {
		fd.URLHint = alerting.RedactURL(c.Config.URL)
		fd.HasSecret = c.Config.Secret != ""
		fd.HeadersText = maskHeaders(c.Config.Headers)
	}
	return fd
}

// maskHeaders renders "Name: ••••••" lines so header values (often tokens) are not re-displayed.
func maskHeaders(hs map[string]string) string {
	names := make([]string, 0, len(hs))
	for k := range hs {
		names = append(names, k)
	}
	sort.Strings(names)
	var b strings.Builder
	for _, k := range names {
		b.WriteString(k + ": " + maskedValue + "\n")
	}
	return strings.TrimRight(b.String(), "\n")
}

func (h *H) newForm(w http.ResponseWriter, r *http.Request) {
	kind := alerting.ChannelKind(r.URL.Query().Get("kind"))
	if kind == "" {
		kind = alerting.KindSlack
	}
	c := alerting.Channel{Kind: kind, MinSeverity: "warning", Enabled: true, Events: []string{}}
	h.d.Partial(w, r, 200, area, "channel-form", h.form(c, true))
}

// bind reads the form onto c. Secret fields left blank keep their stored values.
func bind(r *http.Request, c *alerting.Channel) error {
	_ = r.ParseForm()
	old := c.Config
	c.Name = ui.FormStr(r, "name")
	c.Kind = alerting.ChannelKind(ui.FormStr(r, "kind"))
	c.MinSeverity = ui.FormStr(r, "min_severity")
	c.Enabled = ui.FormBool(r, "enabled")
	c.Events = []string{}
	for _, e := range r.Form["events"] {
		for _, k := range alerting.EventKinds {
			if k.Key == e {
				c.Events = append(c.Events, e)
			}
		}
	}
	if len(c.Events) == len(alerting.EventKinds) {
		c.Events = []string{} // everything selected = subscribe to all (including future kinds)
	}
	cfg := alerting.ChannelConfig{}
	keepURL := func(field string) string {
		if v := ui.FormStr(r, field); v != "" {
			return v
		}
		return old.URL
	}
	switch c.Kind {
	case alerting.KindSlack:
		cfg.URL = keepURL("slack_url")
		cfg.Mention = ui.FormStr(r, "mention")
	case alerting.KindMattermost:
		cfg.URL = keepURL("mattermost_url")
		cfg.Mention = ui.FormStr(r, "mm_mention")
		cfg.Channel = strings.TrimPrefix(ui.FormStr(r, "mm_channel"), "~")
		cfg.Username = ui.FormStr(r, "mm_username")
		cfg.IconURL = ui.FormStr(r, "mm_icon_url")
	case alerting.KindWebhook:
		cfg.URL = keepURL("webhook_url")
		cfg.Secret = old.Secret
		if v := ui.FormStr(r, "secret"); v != "" {
			cfg.Secret = v
		}
		if ui.FormBool(r, "clear_secret") {
			cfg.Secret = ""
		}
		cfg.Headers = map[string]string{}
		for k, v := range parseHeaders(r.FormValue("headers")) {
			if v == maskedValue {
				ov, ok := old.Headers[k]
				if !ok {
					return errors.New("enter a value for header " + k)
				}
				v = ov
			}
			cfg.Headers[k] = v
		}
	case alerting.KindEmail:
		cfg.Recipients = ui.FormList(r, "recipients")
	default:
		return errors.New("choose a channel type")
	}
	c.Config = cfg
	return nil
}

func parseHeaders(s string) map[string]string {
	m := map[string]string{}
	for _, line := range strings.Split(s, "\n") {
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		if k = strings.TrimSpace(k); k != "" {
			m[k] = strings.TrimSpace(v)
		}
	}
	return m
}

func (h *H) create(w http.ResponseWriter, r *http.Request) {
	c := alerting.Channel{}
	h.save(w, r, c, true)
}

func (h *H) save(w http.ResponseWriter, r *http.Request, c alerting.Channel, isNew bool) {
	before := redacted(c)
	err := bind(r, &c)
	if err == nil {
		c.ID, err = h.a.SaveChannel(r.Context(), c)
	}
	if err != nil {
		fd := h.form(c, isNew)
		fd.Error = err.Error()
		h.d.Partial(w, r, 422, area, "channel-form", fd)
		return
	}
	if isNew {
		h.d.Audit(r, "create", "alert_channel", c.ID, "Created alert channel "+c.Name, nil, redacted(c))
		ui.Done(w, "Channel "+c.Name+" created", "refresh-alert-channels")
		return
	}
	h.d.Audit(r, "update", "alert_channel", c.ID, "Updated alert channel "+c.Name, before, redacted(c))
	ui.Done(w, "Channel "+c.Name+" saved", "refresh-alert-channels")
}

// redacted is the audit representation of a channel (no secrets).
func redacted(c alerting.Channel) map[string]any {
	if c.ID == "" && c.Name == "" {
		return nil
	}
	headers := make([]string, 0, len(c.Config.Headers))
	for k := range c.Config.Headers {
		headers = append(headers, k)
	}
	sort.Strings(headers)
	return map[string]any{"name": c.Name, "kind": c.Kind, "events": c.Events, "min_severity": c.MinSeverity,
		"enabled": c.Enabled, "target": c.Target(), "header_names": headers, "signed": c.Config.Secret != ""}
}

func (h *H) load(w http.ResponseWriter, r *http.Request) (alerting.Channel, bool) {
	c, err := h.a.GetChannel(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		ui.Fail(w, 404, "Channel not found")
		return c, false
	}
	return c, true
}

func (h *H) editForm(w http.ResponseWriter, r *http.Request) {
	c, ok := h.load(w, r)
	if !ok {
		return
	}
	fd := h.form(c, false)
	if c.ConfigErr != nil {
		fd.Error = "The stored configuration could not be decrypted (was LEMONGATE_SECRET_KEY changed?). Re-enter the destination to fix it."
	}
	h.d.Partial(w, r, 200, area, "channel-form", fd)
}

func (h *H) update(w http.ResponseWriter, r *http.Request) {
	c, ok := h.load(w, r)
	if !ok {
		return
	}
	h.save(w, r, c, false)
}

func (h *H) test(w http.ResponseWriter, r *http.Request) {
	c, ok := h.load(w, r)
	if !ok {
		return
	}
	p := auth.FromContext(r.Context())
	err := h.a.SendTest(r.Context(), c.ID, p.Label())
	ui.Refresh(w, "refresh-alert-history")
	ui.Refresh(w, "refresh-alert-channels")
	if err != nil {
		ui.Fail(w, http.StatusOK, "Test to "+c.Name+" failed: "+err.Error())
		return
	}
	ui.Toast(w, "success", "Test alert delivered to "+c.Name)
	w.Header().Set("HX-Reswap", "none")
	w.WriteHeader(http.StatusOK)
}

func (h *H) setEnabled(enabled bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, ok := h.load(w, r)
		if !ok {
			return
		}
		if err := h.a.SetChannelEnabled(r.Context(), c.ID, enabled); err != nil {
			ui.Fail(w, 500, err.Error())
			return
		}
		verb := map[bool]string{true: "Enabled", false: "Paused"}[enabled]
		h.d.Audit(r, map[bool]string{true: "enable", false: "disable"}[enabled], "alert_channel", c.ID, verb+" alert channel "+c.Name, nil, nil)
		ui.Done(w, verb+" "+c.Name, "refresh-alert-channels")
	}
}

func (h *H) delete(w http.ResponseWriter, r *http.Request) {
	c, ok := h.load(w, r)
	if !ok {
		return
	}
	if err := h.a.DeleteChannel(r.Context(), c.ID); err != nil {
		ui.Fail(w, 500, err.Error())
		return
	}
	h.d.Audit(r, "delete", "alert_channel", c.ID, "Deleted alert channel "+c.Name, redacted(c), nil)
	ui.Done(w, "Channel "+c.Name+" deleted", "refresh-alert-channels")
}
