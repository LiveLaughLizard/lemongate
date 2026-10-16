// Package usage is the analytics area: spend, requests and tokens over a date range,
// broken down by model, key, team, user, end user or tag, with CSV export.
package usage

import (
	"context"
	"encoding/csv"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"lemongate/internal/analytics"
	"lemongate/internal/auth"
	"lemongate/internal/store"
	"lemongate/internal/ui"
)

const area = "usage"

type H struct{ d *ui.Deps }

func Mount(r chi.Router, d *ui.Deps) {
	h := &H{d}
	r.Get("/ui/usage", h.index)
	r.Get("/ui/usage/data", h.data)
	r.Get("/ui/usage/export.csv", h.export)
}

// Groups are the breakdown dimensions in display order.
var Groups = []Option{
	{"model", "Model", "boxes"}, {"key", "API key", "key-round"}, {"team", "Team", "users"},
	{"user", "User", "user-round"}, {"end_user", "End user", "contact"}, {"tag", "Tag", "tag"},
}

type Option struct{ Value, Label, Icon string }

// params is the parsed, validated filter state shared by the page, data and export.
type params struct {
	Preset  string // 7 | 30 | 90 | custom
	From    time.Time
	To      time.Time
	Model   string
	Team    string
	Key     string
	User    string
	EndUser string
	Group   string
	Metric  string
	Sort    string
	Dir     string
}

func (p params) Days() int { return int(p.To.Sub(p.From).Hours()/24) + 1 }

func (p params) Query() string {
	v := url.Values{}
	v.Set("days", p.Preset)
	if p.Preset == "custom" {
		v.Set("from", p.From.Format("2006-01-02"))
		v.Set("to", p.To.Format("2006-01-02"))
	}
	for k, s := range map[string]string{"model": p.Model, "team": p.Team, "key": p.Key, "user": p.User, "end_user": p.EndUser,
		"group": p.Group, "metric": p.Metric, "sort": p.Sort, "dir": p.Dir} {
		if s != "" {
			v.Set(k, s)
		}
	}
	return v.Encode()
}

func parse(r *http.Request, p *auth.Principal) params {
	q := r.URL.Query()
	ps := params{Preset: q.Get("days"), Model: q.Get("model"), Team: q.Get("team"), Key: q.Get("key"), EndUser: strings.TrimSpace(q.Get("end_user")),
		Group: q.Get("group"), Metric: q.Get("metric"), Sort: q.Get("sort"), Dir: q.Get("dir")}
	if p.CanViewAll() {
		ps.User = q.Get("user")
	}
	today := time.Now().UTC()
	switch ps.Preset {
	case "1", "7", "30", "90", "365":
		n, _ := strconv.Atoi(ps.Preset)
		ps.From, ps.To = today.AddDate(0, 0, -(n-1)), today
	case "custom":
		from, err1 := time.Parse("2006-01-02", q.Get("from"))
		to, err2 := time.Parse("2006-01-02", q.Get("to"))
		if err1 != nil || err2 != nil {
			ps.Preset = "30"
			ps.From, ps.To = today.AddDate(0, 0, -29), today
			break
		}
		if to.Before(from) {
			from, to = to, from
		}
		if to.Sub(from) > 366*24*time.Hour {
			from = to.AddDate(-1, 0, 0)
		}
		ps.From, ps.To = from, to
	default:
		ps.Preset = "30"
		ps.From, ps.To = today.AddDate(0, 0, -29), today
	}
	if !slices.ContainsFunc(Groups, func(o Option) bool { return o.Value == ps.Group }) {
		ps.Group = "model"
	}
	if ps.Metric != "requests" && ps.Metric != "tokens" {
		ps.Metric = "cost"
	}
	if !slices.Contains([]string{"label", "requests", "tokens", "cost", "errors", "latency", "cache"}, ps.Sort) {
		ps.Sort = "cost"
	}
	if ps.Dir != "asc" {
		ps.Dir = "desc"
	}
	return ps
}

func (h *H) filter(ctx context.Context, p *auth.Principal, ps params) analytics.Filter {
	f := analytics.Range(ps.From, ps.To)
	f.Model, f.TeamID, f.KeyID, f.UserID, f.EndUser = ps.Model, ps.Team, ps.Key, ps.User, ps.EndUser
	if !p.CanViewAll() {
		teams := make([]string, 0, len(p.Memberships))
		for _, m := range p.Memberships {
			teams = append(teams, m.TeamID)
		}
		f.RestrictToUser(ctx, h.d.Store.Pool, p.UserID(), teams)
	}
	return f
}

// --- page ---

type keyOpt struct{ ID, Label string }

type indexData struct {
	Params  params
	Groups  []Option
	Models  []string
	Teams   []store.Team
	Keys    []keyOpt
	Users   []store.User
	Scoped  bool
	Presets []Option
}

func (h *H) index(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := auth.FromContext(ctx)
	ps := parse(r, p)
	data := indexData{Params: ps, Groups: Groups, Scoped: !p.CanViewAll(),
		Presets: []Option{{"7", "7 days", ""}, {"30", "30 days", ""}, {"90", "90 days", ""}, {"365", "1 year", ""}, {"custom", "Custom", ""}}}
	models := h.d.Registry.AllModelNames()
	for _, m := range analytics.RecentModels(ctx, h.d.Store.Pool, time.Now().AddDate(0, 0, -90)) {
		if !slices.Contains(models, m) {
			models = append(models, m)
		}
	}
	slices.Sort(models)
	data.Models = models
	if p.CanViewAll() {
		data.Teams, _ = h.d.Store.ListTeams(ctx, "", "")
		data.Users, _ = h.d.Store.ListUsers(ctx, "", "")
	} else {
		data.Teams, _ = h.d.Store.TeamsForUser(ctx, p.UserID())
	}
	keys, _ := h.d.Store.ListKeys(ctx, store.KeyFilter{Limit: 1000})
	for _, k := range keys {
		if p.CanViewKey(k) {
			data.Keys = append(data.Keys, keyOpt{k.ID, k.Label()})
		}
	}
	h.d.Render(w, r, "usage/index", "usage", "Usage", data)
}

// --- results ---

type resultData struct {
	Params    params
	GroupName string
	Totals    analytics.Totals
	Prev      analytics.Totals
	Chart     analytics.ChartSpec
	Rows      []analytics.Row
	MaxMetric float64
	Scoped    bool
	Error     string
	Tiles     []tile
}

type tile struct {
	Label, Value, Icon, Tone, Hint string
	Delta                          float64
	HasDelta, Good                 bool
}

func mkTile(label, value, icon, tone, hint string, cur, prev float64, higherGood bool) tile {
	t := tile{Label: label, Value: value, Icon: icon, Tone: tone, Hint: hint}
	if prev > 0 {
		t.HasDelta = true
		t.Delta = (cur - prev) / prev * 100
		t.Good = (t.Delta >= 0) == higherGood || (t.Delta < 0.05 && t.Delta > -0.05)
	}
	return t
}

func (d resultData) Share(r analytics.Row) float64 {
	if d.MaxMetric <= 0 {
		return 0
	}
	return analytics.MetricValue(r.Totals, d.Params.Metric) / d.MaxMetric * 100
}

// Href links a breakdown row to its detail page where one exists.
func (d resultData) Href(r analytics.Row) string {
	switch d.Params.Group {
	case "key":
		return "/ui/keys/" + r.Key
	case "team":
		return "/ui/teams/" + r.Key
	case "user":
		return "/ui/users/" + r.Key
	}
	return ""
}

// Drill returns the usage query narrowed to a breakdown row.
func (d resultData) Drill(r analytics.Row) string {
	ps := d.Params
	switch ps.Group {
	case "model":
		ps.Model, ps.Group = r.Key, "key"
	case "key":
		ps.Key, ps.Group = r.Key, "model"
	case "team":
		ps.Team, ps.Group = r.Key, "key"
	case "user":
		ps.User, ps.Group = r.Key, "key"
	case "end_user":
		ps.EndUser, ps.Group = r.Key, "model"
	default:
		return ""
	}
	return "/ui/usage?" + ps.Query()
}

// Logs links to request logs for a breakdown row.
func (d resultData) Logs(r analytics.Row) string {
	v := url.Values{}
	switch d.Params.Group {
	case "model":
		v.Set("model", r.Key)
	case "key":
		v.Set("key", r.Key)
	case "team":
		v.Set("team", r.Key)
	case "user":
		v.Set("user", r.Key)
	case "end_user":
		v.Set("end_user", r.Key)
	default:
		return ""
	}
	return "/ui/logs?" + v.Encode()
}

func (h *H) rows(ctx context.Context, f analytics.Filter, ps params) ([]analytics.Row, error) {
	if ps.Group == "tag" {
		return analytics.TagBreakdown(ctx, h.d.Store.Pool, f, 1000)
	}
	return analytics.Breakdown(ctx, h.d.Store.Pool, f, ps.Group, 1000)
}

func (h *H) data(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := auth.FromContext(ctx)
	ps := parse(r, p)
	f := h.filter(ctx, p, ps)
	pool := h.d.Store.Pool
	rd := resultData{Params: ps, Scoped: !p.CanViewAll()}
	for _, g := range Groups {
		if g.Value == ps.Group {
			rd.GroupName = g.Label
		}
	}
	rd.Totals, _ = analytics.GetTotals(ctx, pool, f)
	rd.Prev, _ = analytics.GetTotals(ctx, pool, f.Previous())
	c, pv := rd.Totals, rd.Prev
	rd.Tiles = []tile{
		mkTile("Spend", ui.Money(c.Cost), "wallet", "primary", fmt.Sprintf("%s / day", ui.Money(c.Cost/float64(ps.Days()))), c.Cost, pv.Cost, true),
		mkTile("Requests", ui.Num(c.Requests), "activity", "secondary", fmt.Sprintf("%.2f%% errors", c.ErrorRate()), float64(c.Requests), float64(pv.Requests), true),
		mkTile("Tokens", ui.Compact(c.Tokens()), "coins", "accent", fmt.Sprintf("%s in · %s out", ui.Compact(c.PromptTokens), ui.Compact(c.CompletionTokens)), float64(c.Tokens()), float64(pv.Tokens()), true),
		mkTile("Avg latency", ui.Num(c.AvgLatencyMs)+" ms", "timer", "info", fmt.Sprintf("%s cache hits", ui.Compact(c.CacheHits)), c.AvgLatencyMs, pv.AvgLatencyMs, false),
	}
	var err error
	if ps.Group == "tag" {
		pts, _ := analytics.Daily(ctx, pool, f)
		label := map[string]string{"cost": "Spend", "requests": "Requests", "tokens": "Tokens"}[ps.Metric]
		rd.Chart = analytics.DailyChart(pts, "bar", analytics.MetricFormat(ps.Metric), map[string]func(analytics.DayPoint) float64{
			label: func(p analytics.DayPoint) float64 { return analytics.MetricValue(p.Totals, ps.Metric) },
		}, label)
	} else {
		rd.Chart, err = analytics.DailyByDim(ctx, pool, f, ps.Group, ps.Metric, "bar", 6)
	}
	if err == nil {
		rd.Rows, err = h.rows(ctx, f, ps)
	}
	if err != nil {
		rd.Error = err.Error()
	}
	analytics.SortRows(rd.Rows, ps.Sort, ps.Dir == "asc")
	for _, row := range rd.Rows {
		rd.MaxMetric = max(rd.MaxMetric, analytics.MetricValue(row.Totals, ps.Metric))
	}
	h.d.Partial(w, r, 200, area, "usage-results", rd)
}

func (h *H) export(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := auth.FromContext(ctx)
	ps := parse(r, p)
	f := h.filter(ctx, p, ps)
	rows, err := h.rows(ctx, f, ps)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	analytics.SortRows(rows, ps.Sort, ps.Dir == "asc")
	name := fmt.Sprintf("lemongate-usage-%s-%s-to-%s.csv", ps.Group, ps.From.Format("20060102"), ps.To.Format("20060102"))
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{ps.Group + "_id", ps.Group, "from", "to", "requests", "failures", "error_rate_pct", "cache_hits",
		"prompt_tokens", "completion_tokens", "total_tokens", "cost_usd", "avg_latency_ms"})
	from, to := ps.From.Format("2006-01-02"), ps.To.Format("2006-01-02")
	for _, row := range rows {
		_ = cw.Write([]string{csvSafe(row.Key), csvSafe(row.Label), from, to, strconv.FormatInt(row.Requests, 10), strconv.FormatInt(row.Failures, 10),
			strconv.FormatFloat(row.ErrorRate(), 'f', 2, 64), strconv.FormatInt(row.CacheHits, 10),
			strconv.FormatInt(row.PromptTokens, 10), strconv.FormatInt(row.CompletionTokens, 10), strconv.FormatInt(row.Tokens(), 10),
			strconv.FormatFloat(row.Cost, 'f', 6, 64), strconv.FormatFloat(row.AvgLatencyMs, 'f', 1, 64)})
	}
	cw.Flush()
}

// csvSafe neutralizes values that spreadsheet apps would evaluate as formulas.
func csvSafe(s string) string {
	if t := strings.TrimLeft(s, " "); t != "" && strings.ContainsRune("=+-@\t\r", rune(t[0])) {
		return "'" + s
	}
	return s
}
