// Package logs is the request log explorer: filterable table, live tail and a
// detail drawer with tokens, timings, metadata and (when stored) payloads.
package logs

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"lemongate/internal/analytics"
	"lemongate/internal/auth"
	"lemongate/internal/store"
	"lemongate/internal/ui"
)

const area = "logs"

const pageSize = 50

type H struct{ d *ui.Deps }

func Mount(r chi.Router, d *ui.Deps) {
	h := &H{d}
	r.Get("/ui/logs", h.index)
	r.Get("/ui/logs/table", h.table)
	r.Get("/ui/logs/{id}", h.show)
}

type filterState struct {
	Status  string
	Model   string
	Key     string
	Team    string
	User    string
	EndUser string
	Q       string
	Window  string // 15m | 1h | 24h | 7d | 30d | all
}

func (f filterState) Query() string {
	v := url.Values{}
	for k, s := range map[string]string{"status": f.Status, "model": f.Model, "key": f.Key, "team": f.Team, "user": f.User,
		"end_user": f.EndUser, "q": f.Q, "window": f.Window} {
		if s != "" {
			v.Set(k, s)
		}
	}
	return v.Encode()
}

// Active reports whether any narrowing filter is set.
func (f filterState) Active() bool {
	return f.Status != "" || f.Model != "" || f.Key != "" || f.Team != "" || f.User != "" || f.EndUser != "" || f.Q != ""
}

var windows = map[string]time.Duration{"15m": 15 * time.Minute, "1h": time.Hour, "24h": 24 * time.Hour, "7d": 7 * 24 * time.Hour, "30d": 30 * 24 * time.Hour}

func parse(r *http.Request, p *auth.Principal) filterState {
	q := r.URL.Query()
	f := filterState{Status: q.Get("status"), Model: q.Get("model"), Key: q.Get("key"), Team: q.Get("team"),
		EndUser: strings.TrimSpace(q.Get("end_user")), Q: strings.TrimSpace(q.Get("q")), Window: q.Get("window")}
	if p.CanViewAll() {
		f.User = q.Get("user")
	}
	if _, ok := windows[f.Window]; !ok && f.Window != "all" {
		f.Window = "7d"
	}
	if !slices.Contains([]string{"", "success", "error", "blocked", "failed", "cached"}, f.Status) {
		f.Status = ""
	}
	return f
}

func (h *H) logFilter(ctx context.Context, p *auth.Principal, fs filterState) analytics.LogFilter {
	lf := analytics.LogFilter{Status: fs.Status, Model: fs.Model, KeyID: fs.Key, TeamID: fs.Team, UserID: fs.User, EndUser: fs.EndUser, Search: fs.Q}
	if d, ok := windows[fs.Window]; ok {
		lf.Since = time.Now().Add(-d)
	}
	h.scope(ctx, p, &lf)
	return lf
}

func (h *H) scope(ctx context.Context, p *auth.Principal, lf *analytics.LogFilter) {
	if p.CanViewAll() {
		return
	}
	teams := make([]string, 0, len(p.Memberships))
	for _, m := range p.Memberships {
		teams = append(teams, m.TeamID)
	}
	lf.KeyIDs = analytics.UserKeyIDs(ctx, h.d.Store.Pool, p.UserID())
	lf.TeamIDs = teams
	lf.ScopeUserID = p.UserID()
	if lf.ScopeUserID == "" {
		lf.ScopeUserID = "-"
	}
}

// --- page ---

type keyOpt struct{ ID, Label string }

type indexData struct {
	F             filterState
	Models        []string
	Keys          []keyOpt
	Teams         []store.Team
	Users         []store.User
	StorePayloads bool
	CanSettings   bool
	KeyLabel      string
}

func (h *H) index(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := auth.FromContext(ctx)
	fs := parse(r, p)
	data := indexData{F: fs, StorePayloads: h.d.Settings.Current().Logging.StorePayloads, CanSettings: p.CanViewAll()}
	models := h.d.Registry.AllModelNames()
	for _, m := range analytics.RecentModels(ctx, h.d.Store.Pool, time.Now().AddDate(0, 0, -30)) {
		if !slices.Contains(models, m) {
			models = append(models, m)
		}
	}
	slices.Sort(models)
	data.Models = models
	keys, _ := h.d.Store.ListKeys(ctx, store.KeyFilter{Limit: 1000})
	for _, k := range keys {
		if p.CanViewKey(k) {
			data.Keys = append(data.Keys, keyOpt{k.ID, k.Label()})
		}
	}
	// A key linked from its detail page may be deleted (not in the active list).
	if fs.Key != "" && !slices.ContainsFunc(data.Keys, func(k keyOpt) bool { return k.ID == fs.Key }) {
		if k, err := h.d.Store.GetKey(ctx, fs.Key); err == nil && p.CanViewKey(k) {
			data.Keys = append([]keyOpt{{k.ID, k.Label() + " (deleted)"}}, data.Keys...)
		}
	}
	if p.CanViewAll() {
		data.Teams, _ = h.d.Store.ListTeams(ctx, "", "")
		data.Users, _ = h.d.Store.ListUsers(ctx, "", "")
	} else {
		data.Teams, _ = h.d.Store.TeamsForUser(ctx, p.UserID())
	}
	h.d.Render(w, r, "logs/index", "logs", "Request logs", data)
}

// --- table ---

type tableData struct {
	Rows   []analytics.LogEntry
	Stats  analytics.LogStats
	Next   string
	Append bool
	F      filterState
	Live   bool
	Now    time.Time
}

func (h *H) table(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := auth.FromContext(ctx)
	fs := parse(r, p)
	lf := h.logFilter(ctx, p, fs)
	td := tableData{F: fs, Live: r.URL.Query().Get("live") == "on", Now: time.Now()}
	if c := r.URL.Query().Get("cursor"); c != "" {
		if at, id, ok := analytics.ParseCursor(c); ok {
			lf.BeforeAt, lf.BeforeID = at, id
			td.Append = true
		}
	}
	lf.Limit = pageSize + 1
	rows, err := analytics.ListLogs(ctx, h.d.Store.Pool, lf)
	if err != nil {
		ui.Fail(w, 500, err.Error())
		return
	}
	if len(rows) > pageSize {
		rows = rows[:pageSize]
		td.Next = rows[len(rows)-1].Cursor()
	}
	td.Rows = rows
	if !td.Append {
		td.Stats, _ = analytics.GetLogStats(ctx, h.d.Store.Pool, lf)
	}
	name := "logs-table"
	if td.Append {
		name = "logs-rows"
	}
	h.d.Partial(w, r, 200, area, name, td)
}

// --- detail ---

type showData struct {
	L             analytics.LogEntry
	StorePayloads bool
	CanSettings   bool
	Deployment    string
	CanViewKey    bool
}

func (h *H) show(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := auth.FromContext(ctx)
	var lf analytics.LogFilter
	h.scope(ctx, p, &lf)
	l, err := analytics.GetLog(ctx, h.d.Store.Pool, chi.URLParam(r, "id"), lf)
	if err != nil {
		if ui.IsHTMX(r) {
			ui.Fail(w, 404, "Log entry not found")
		} else {
			http.NotFound(w, r)
		}
		return
	}
	sd := showData{L: l, StorePayloads: h.d.Settings.Current().Logging.StorePayloads, CanSettings: p.CanViewAll()}
	if l.DeploymentID != nil {
		if dep := h.d.Registry.Deployment(*l.DeploymentID); dep != nil && p.CanViewAll() {
			sd.Deployment = dep.Name + " · " + dep.APIBase
		}
	}
	if l.KeyID != nil {
		sd.CanViewKey = p.CanViewAll() || slices.Contains(analytics.UserKeyIDs(ctx, h.d.Store.Pool, p.UserID()), *l.KeyID) ||
			(l.TeamID != nil && p.InTeam(*l.TeamID))
	}
	if !ui.IsHTMX(r) {
		h.d.Render(w, r, "logs/show", "logs", "Request "+truncate(l.RequestID, 18), sd, ui.Crumb{Label: "Request logs", Href: "/ui/logs"})
		return
	}
	h.d.Partial(w, r, 200, area, "log-detail", sd)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// Message is one chat turn extracted from a stored payload.
type Message struct{ Role, Content string }

// Conversation extracts chat messages from the stored request body (if any).
func (s showData) Conversation() []Message {
	var req struct {
		Messages []struct {
			Role    string `json:"role"`
			Content any    `json:"content"`
		} `json:"messages"`
		Prompt any `json:"prompt"`
	}
	if len(s.L.RequestBody) == 0 || json.Unmarshal(s.L.RequestBody, &req) != nil {
		return nil
	}
	var out []Message
	for _, m := range req.Messages {
		out = append(out, Message{Role: m.Role, Content: contentText(m.Content)})
	}
	if len(out) == 0 && req.Prompt != nil {
		out = append(out, Message{Role: "prompt", Content: contentText(req.Prompt)})
	}
	return out
}

// Reply extracts the assistant text from the stored response body (if any).
func (s showData) Reply() string {
	var resp struct {
		StreamText *string `json:"stream_text"`
		Choices    []struct {
			Message *struct {
				Content any `json:"content"`
			} `json:"message"`
			Text string `json:"text"`
		} `json:"choices"`
	}
	if len(s.L.ResponseBody) == 0 || json.Unmarshal(s.L.ResponseBody, &resp) != nil {
		return ""
	}
	if resp.StreamText != nil {
		return *resp.StreamText
	}
	var sb strings.Builder
	for _, c := range resp.Choices {
		if c.Message != nil {
			sb.WriteString(contentText(c.Message.Content))
		}
		sb.WriteString(c.Text)
	}
	return sb.String()
}

func contentText(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case []any:
		var parts []string
		for _, p := range x {
			if m, ok := p.(map[string]any); ok {
				if t, ok := m["text"].(string); ok {
					parts = append(parts, t)
				} else if typ, ok := m["type"].(string); ok {
					parts = append(parts, "["+typ+"]")
				}
			} else if s, ok := p.(string); ok {
				parts = append(parts, s)
			}
		}
		return strings.Join(parts, "\n")
	case nil:
		return ""
	}
	b, _ := json.Marshal(v)
	return string(b)
}

// LatencyBar returns the TTFT share of total latency (0-100) for the timing bar.
func (s showData) TTFTPct() float64 {
	if s.L.TTFTMs == nil || s.L.LatencyMs <= 0 {
		return 0
	}
	return min(100, float64(*s.L.TTFTMs)/float64(s.L.LatencyMs)*100)
}
