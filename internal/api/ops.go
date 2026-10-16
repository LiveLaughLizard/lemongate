package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"lemongate/internal/analytics"
	"lemongate/internal/auth"
	"lemongate/internal/settings"
	"lemongate/internal/store"
)

func (h *H) opsRoutes() []route {
	return []route{
		{Method: "GET", Path: "/settings", Tag: "Settings", Summary: "Get settings", Access: accessViewer, Resp: "Settings", handler: h.getSettings},
		{Method: "PATCH", Path: "/settings", Tag: "Settings", Summary: "Update settings", Desc: "Merges the given sections and fields into the current settings, e.g. only `routing.num_retries`.",
			Access: accessViewer, Body: "Settings", Resp: "Settings", Example: `{"routing": {"num_retries": 3}, "alerting": {"budget_thresholds": [50, 90, 100]}}`, handler: h.patchSettings},
		{Method: "GET", Path: "/usage", Tag: "Observability", Summary: "Usage analytics",
			Desc:   "Totals, a daily series and a breakdown from the daily rollups. Members only see usage of their own keys and teams.",
			Access: accessSelf, Resp: "Usage",
			Query: []qparam{{"from", "date", "First day (YYYY-MM-DD, UTC). Default: 29 days before `to`"}, {"to", "date", "Last day (YYYY-MM-DD). Default: today"},
				{"group_by", "string", "model (default), key, team, user, org or end_user"}, {"limit", "integer", "Breakdown rows (default 20, max 200)"},
				{"model", "string", "Filter by model"}, {"key_id", "string", "Filter by key"}, {"team_id", "string", "Filter by team"}, {"user_id", "string", "Filter by user"}},
			handler: h.usage},
		{Method: "GET", Path: "/logs", Tag: "Observability", Summary: "Request logs",
			Desc:   "Newest first. Pass `next_cursor` from a response as `cursor` to fetch the next page. Members only see their own requests and their teams' requests.",
			Access: accessSelf, Resp: "LogPage",
			Query: []qparam{{"model", "string", "Model group"}, {"key_id", "string", ""}, {"team_id", "string", ""}, {"user_id", "string", ""},
				{"end_user", "string", ""}, {"status", "string", "success, error or blocked"}, {"request_id", "string", ""},
				{"from", "string", "RFC 3339 time or YYYY-MM-DD"}, {"to", "string", "RFC 3339 time or YYYY-MM-DD (inclusive day)"},
				{"limit", "integer", "Page size (default 100, max 500)"}, {"cursor", "string", "Opaque pagination cursor"},
				{"include_payloads", "boolean", "Include stored request/response bodies (admins only)"}},
			handler: h.logs},
		{Method: "GET", Path: "/health", Tag: "Observability", Summary: "Deployment health", Desc: "Every routable deployment (database and config) with its last probe, live latency, in-flight requests and cooldown.",
			Access: accessViewer, Resp: "Health", handler: h.health},
		{Method: "GET", Path: "/audit", Tag: "Observability", Summary: "Audit log", Access: accessViewer, Resp: "list:AuditEntry",
			Query: []qparam{{"entity_type", "string", "e.g. key, user, team, deployment"}, {"q", "string", "Search summary, actor or entity id"},
				{"limit", "integer", "Default 100, max 500"}, {"offset", "integer", ""}},
			handler: h.audit},
	}
}

// --- settings ---

func (h *H) getSettings(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, 200, h.d.Settings.Current())
}

// mergeSettings applies a partial JSON document (section → fields) over cur.
func mergeSettings(cur settings.Settings, patch map[string]json.RawMessage) (settings.Settings, error) {
	b, _ := json.Marshal(cur)
	var doc map[string]map[string]json.RawMessage
	if err := json.Unmarshal(b, &doc); err != nil {
		return cur, err
	}
	for section, raw := range patch {
		base, ok := doc[section]
		if !ok {
			return cur, inputErr{fmt.Sprintf("unknown settings section %q", section)}
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(raw, &fields); err != nil {
			return cur, inputErr{fmt.Sprintf("settings section %q must be an object", section)}
		}
		for k, v := range fields {
			if _, ok := base[k]; !ok {
				return cur, inputErr{fmt.Sprintf("unknown setting %s.%s", section, k)}
			}
			base[k] = v
		}
	}
	b, _ = json.Marshal(doc)
	var next settings.Settings
	if err := json.Unmarshal(b, &next); err != nil {
		return cur, inputErr{"invalid setting value: " + err.Error()}
	}
	return next, nil
}

func (h *H) patchSettings(w http.ResponseWriter, r *http.Request) {
	var patch map[string]json.RawMessage
	if !decode(w, r, &patch) {
		return
	}
	before := h.d.Settings.Current()
	next, err := mergeSettings(before, patch)
	if err != nil {
		storeErr(w, err, "settings")
		return
	}
	saved, err := h.d.Settings.Update(r.Context(), func(s *settings.Settings) { *s = next })
	if err != nil {
		storeErr(w, err, "settings")
		return
	}
	sections := make([]string, 0, len(patch))
	for k := range patch {
		sections = append(sections, k)
	}
	h.d.Audit(r, "update", "settings", strings.Join(sections, ","), "Updated settings ("+strings.Join(sections, ", ")+") via API", before, saved)
	writeJSON(w, 200, saved)
}

// --- scoping for members ---

// memberScope returns the key and team ids a non-viewer may see.
func (h *H) memberScope(ctx context.Context, p *auth.Principal) (keys, teams []string) {
	keys, teams = []string{}, []string{}
	if uid := p.UserID(); uid != "" {
		ks, _ := h.d.Store.ListKeys(ctx, store.KeyFilter{UserID: uid, Limit: 5000})
		for _, k := range ks {
			keys = append(keys, k.ID)
		}
	}
	for _, m := range p.Memberships {
		teams = append(teams, m.TeamID)
	}
	if p.Team != nil {
		teams = append(teams, p.Team.ID)
	}
	if p.Key != nil {
		keys = append(keys, p.Key.ID)
	}
	return keys, teams
}

// --- usage ---

func parseDay(s string, def time.Time) (time.Time, error) {
	if s == "" {
		return def, nil
	}
	return time.Parse("2006-01-02", s)
}

type usageTotals struct {
	Requests         int64   `json:"requests"`
	Failures         int64   `json:"failures"`
	CacheHits        int64   `json:"cache_hits"`
	PromptTokens     int64   `json:"prompt_tokens"`
	CompletionTokens int64   `json:"completion_tokens"`
	TotalTokens      int64   `json:"total_tokens"`
	Cost             float64 `json:"cost"`
	AvgLatencyMs     float64 `json:"avg_latency_ms"`
	ErrorRate        float64 `json:"error_rate_pct"`
}

func toUsage(t analytics.Totals) usageTotals {
	return usageTotals{Requests: t.Requests, Failures: t.Failures, CacheHits: t.CacheHits, PromptTokens: t.PromptTokens,
		CompletionTokens: t.CompletionTokens, TotalTokens: t.Tokens(), Cost: t.Cost, AvgLatencyMs: t.AvgLatencyMs, ErrorRate: t.ErrorRate()}
}

type usageDay struct {
	Day string `json:"day"`
	usageTotals
}

type usageRow struct {
	Key   string `json:"key"`
	Label string `json:"label"`
	usageTotals
}

func (h *H) usage(w http.ResponseWriter, r *http.Request) {
	p := principal(r)
	q := r.URL.Query()
	to, err := parseDay(q.Get("to"), time.Now().UTC())
	if err != nil {
		badRequest(w, "to must be YYYY-MM-DD")
		return
	}
	from, err := parseDay(q.Get("from"), to.AddDate(0, 0, -29))
	if err != nil {
		badRequest(w, "from must be YYYY-MM-DD")
		return
	}
	if from.After(to) {
		badRequest(w, "from must not be after to")
		return
	}
	if to.Sub(from) > 366*24*time.Hour {
		badRequest(w, "the range may span at most 366 days")
		return
	}
	groupBy := q.Get("group_by")
	if groupBy == "" {
		groupBy = "model"
	}
	switch groupBy {
	case "model", "key", "team", "user", "org", "end_user":
	default:
		badRequest(w, "group_by must be model, key, team, user, org or end_user")
		return
	}
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit <= 0 {
		limit = 20
	}
	limit = min(limit, 200)
	f := analytics.Filter{From: from, To: to, Model: q.Get("model"), KeyID: q.Get("key_id"), TeamID: q.Get("team_id"), UserID: q.Get("user_id")}
	if !p.CanViewAll() {
		f.KeyIDs, f.TeamIDs = h.memberScope(r.Context(), p)
	}
	ctx := r.Context()
	tot, err := analytics.GetTotals(ctx, h.d.Store.Pool, f)
	if err != nil {
		storeErr(w, err, "usage")
		return
	}
	pts, err := analytics.Daily(ctx, h.d.Store.Pool, f)
	if err != nil {
		storeErr(w, err, "usage")
		return
	}
	rows, err := analytics.Breakdown(ctx, h.d.Store.Pool, f, groupBy, limit)
	if err != nil {
		storeErr(w, err, "usage")
		return
	}
	daily := make([]usageDay, 0, len(pts))
	for _, pt := range pts {
		daily = append(daily, usageDay{Day: pt.Day.Format("2006-01-02"), usageTotals: toUsage(pt.Totals)})
	}
	breakdown := make([]usageRow, 0, len(rows))
	for _, row := range rows {
		breakdown = append(breakdown, usageRow{Key: row.Key, Label: row.Label, usageTotals: toUsage(row.Totals)})
	}
	writeJSON(w, 200, map[string]any{
		"from": from.Format("2006-01-02"), "to": to.Format("2006-01-02"), "group_by": groupBy,
		"totals": toUsage(tot), "daily": daily, "breakdown": breakdown,
	})
}

// --- logs ---

const logCols = `id::text AS id, request_id, created_at, route, model, model_group, deployment_id::text AS deployment_id, api_base,
	key_id::text AS key_id, key_alias, user_id::text AS user_id, team_id::text AS team_id, org_id::text AS org_id, end_user, tags,
	status, http_status, prompt_tokens, completion_tokens, total_tokens, cost, latency_ms, ttft_ms, stream, cache_hit, attempts,
	error, metadata`

func encodeCursor(t time.Time, id string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(t.UTC().Format(time.RFC3339Nano) + "|" + id))
}

func decodeCursor(c string) (time.Time, string, bool) {
	b, err := base64.RawURLEncoding.DecodeString(c)
	if err != nil {
		return time.Time{}, "", false
	}
	ts, id, ok := strings.Cut(string(b), "|")
	if !ok {
		return time.Time{}, "", false
	}
	t, err := time.Parse(time.RFC3339Nano, ts)
	return t, id, err == nil && id != ""
}

func parseTimeArg(s string, endOfDay bool) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	t, err := time.Parse("2006-01-02", s)
	if err == nil && endOfDay {
		t = t.Add(24*time.Hour - time.Microsecond)
	}
	return t, err
}

func (h *H) logs(w http.ResponseWriter, r *http.Request) {
	p := principal(r)
	q := r.URL.Query()
	var args []any
	add := func(v any) string {
		args = append(args, v)
		return fmt.Sprintf("$%d", len(args))
	}
	where := []string{"true"}
	for param, col := range map[string]string{"model": "model_group", "key_id": "key_id::text", "team_id": "team_id::text",
		"user_id": "user_id::text", "end_user": "end_user", "status": "status", "request_id": "request_id"} {
		if v := q.Get(param); v != "" {
			where = append(where, col+" = "+add(v))
		}
	}
	if v := q.Get("from"); v != "" {
		t, err := parseTimeArg(v, false)
		if err != nil {
			badRequest(w, "from must be RFC 3339 or YYYY-MM-DD")
			return
		}
		where = append(where, "created_at >= "+add(t))
	}
	if v := q.Get("to"); v != "" {
		t, err := parseTimeArg(v, true)
		if err != nil {
			badRequest(w, "to must be RFC 3339 or YYYY-MM-DD")
			return
		}
		where = append(where, "created_at <= "+add(t))
	}
	if c := q.Get("cursor"); c != "" {
		t, id, ok := decodeCursor(c)
		if !ok {
			badRequest(w, "invalid cursor")
			return
		}
		where = append(where, "(created_at, id) < ("+add(t)+"::timestamptz, "+add(id)+"::uuid)")
	}
	if !p.CanViewAll() {
		keys, teams := h.memberScope(r.Context(), p)
		cond := "key_id::text = ANY(" + add(keys) + "::text[]) OR team_id::text = ANY(" + add(teams) + "::text[])"
		if uid := p.UserID(); uid != "" {
			cond += " OR user_id::text = " + add(uid)
		}
		where = append(where, "("+cond+")")
	}
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit <= 0 {
		limit = 100
	}
	limit = min(limit, 500)
	cols := logCols
	if q.Get("include_payloads") == "true" && p.IsAdmin() {
		cols += ", request_body, response_body"
	}
	sql := `SELECT ` + cols + ` FROM request_logs WHERE ` + strings.Join(where, " AND ") +
		` ORDER BY created_at DESC, id DESC LIMIT ` + add(limit+1)
	rows, err := h.d.Store.Pool.Query(r.Context(), sql, args...)
	if err != nil {
		storeErr(w, err, "logs")
		return
	}
	items, err := pgx.CollectRows(rows, pgx.RowToMap)
	if err != nil {
		storeErr(w, err, "logs")
		return
	}
	next := ""
	if len(items) > limit {
		items = items[:limit]
		last := items[len(items)-1]
		if t, ok := last["created_at"].(time.Time); ok {
			next = encodeCursor(t, fmt.Sprint(last["id"]))
		}
	}
	if items == nil {
		items = []map[string]any{}
	}
	out := map[string]any{"data": items, "count": len(items), "next_cursor": nil}
	if next != "" {
		out["next_cursor"] = next
	}
	writeJSON(w, 200, out)
}

// --- health ---

type depHealth struct {
	ID                 string     `json:"id"`
	Name               string     `json:"name"`
	APIBase            string     `json:"api_base"`
	UpstreamModel      string     `json:"upstream_model"`
	Mode               string     `json:"mode"`
	Enabled            bool       `json:"enabled"`
	FromConfig         bool       `json:"from_config"`
	Status             string     `json:"status"` // healthy | unhealthy | cooldown | unknown | disabled
	Healthy            *bool      `json:"healthy"`
	CheckedAt          *time.Time `json:"checked_at"`
	ProbeLatencyMs     *int       `json:"probe_latency_ms"`
	Error              string     `json:"error,omitempty"`
	LatencyMs          float64    `json:"latency_ewma_ms"`
	InFlight           int64      `json:"in_flight"`
	CoolingDown        bool       `json:"cooling_down"`
	CooldownRemainingS float64    `json:"cooldown_remaining_sec"`
}

func (h *H) health(w http.ResponseWriter, _ *http.Request) {
	deps := h.d.Registry.AllDeployments()
	out := make([]depHealth, 0, len(deps))
	counts := map[string]int{}
	for _, d := range deps {
		x := depHealth{ID: d.ID, Name: d.Name, APIBase: d.APIBase, UpstreamModel: d.UpstreamModel, Mode: d.Mode, Enabled: d.Enabled,
			FromConfig: d.FromConfig, LatencyMs: d.LatencyMs(), InFlight: d.InFlight(), CoolingDown: d.CoolingDown(), Status: "unknown"}
		if x.CoolingDown {
			x.CooldownRemainingS = d.CooldownRemaining().Seconds()
		}
		if hl := d.Health(); hl != nil {
			ok, at, lat := hl.Healthy, hl.Checked, hl.LatencyMs
			x.Healthy, x.CheckedAt, x.ProbeLatencyMs, x.Error = &ok, &at, &lat, hl.Error
			x.Status = map[bool]string{true: "healthy", false: "unhealthy"}[ok]
		}
		switch {
		case !d.Enabled:
			x.Status = "disabled"
		case x.CoolingDown:
			x.Status = "cooldown"
		}
		counts[x.Status]++
		out = append(out, x)
	}
	writeJSON(w, 200, map[string]any{"deployments": out, "count": len(out), "summary": counts})
}

// --- audit ---

func (h *H) audit(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit <= 0 {
		limit = 100
	}
	limit = min(limit, 500)
	offset, _ := strconv.Atoi(q.Get("offset"))
	entries, err := h.d.Store.ListAudit(r.Context(), q.Get("entity_type"), q.Get("q"), limit, max(offset, 0))
	if err != nil {
		storeErr(w, err, "audit log")
		return
	}
	writeJSON(w, 200, list(entries))
}
