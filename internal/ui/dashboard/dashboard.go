// Package dashboard is the console home: KPIs, traffic charts, top spenders and
// deployment health. Admins and viewers see the whole gateway; members see the
// traffic of their own keys and teams.
package dashboard

import (
	"context"
	"fmt"
	"math"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"lemongate/internal/analytics"
	"lemongate/internal/auth"
	"lemongate/internal/ui"
)

const area = "dashboard"

type H struct{ d *ui.Deps }

func Mount(r chi.Router, d *ui.Deps) {
	h := &H{d}
	r.Get("/ui", h.index)
	r.Get("/ui/", h.index)
	r.Get("/ui/dashboard/health", h.health)
}

// KPI is one stat tile with a period-over-period delta and a sparkline.
type KPI struct {
	Label    string
	Value    string
	Icon     string
	Tone     string
	Hint     string
	Delta    float64 // percent change vs previous period
	HasDelta bool
	Good     bool   // whether the change is favourable
	Spark    string // SVG path ("" = none)
	Area     string // SVG area path
}

// Budgeted is a top-spender row with its budget state.
type Budgeted struct {
	analytics.Row
	ID     string
	Href   string
	Sub    string
	Spend  float64
	Max    *float64
	Period string
	Share  float64 // 0-100 share of the period's spend
}

// DeploymentHealth is a live snapshot of one deployment.
type DeploymentHealth struct {
	ID         string
	Model      string
	APIBase    string
	Upstream   string
	Status     string // healthy | unhealthy | cooldown | unknown
	Enabled    bool
	LatencyMs  float64
	ProbeMs    int
	Checked    time.Time
	InFlight   int64
	RPM        int
	CooldownIn string
	Error      string
	FromConfig bool
}

type indexData struct {
	Name        string
	Greeting    string
	Days        int
	Scoped      bool
	Totals      analytics.Totals
	KPIs        []KPI
	SpendChart  analytics.ChartSpec
	ModelChart  analytics.ChartSpec
	ShareChart  analytics.ChartSpec
	HasModelMix bool
	TopKeys     []Budgeted
	TopTeams    []Budgeted
	TopModels   []analytics.Row
	Health      healthData
	Checklist   checklist
	CanViewAll  bool
	IsAdmin     bool
	CanCreate   bool
	P95         float64
}

type checklist struct {
	HasModels  bool
	HasKeys    bool
	HasTraffic bool
	Done       int
	Show       bool
	CanModels  bool
}

type healthData struct {
	Deployments []DeploymentHealth
	Healthy     int
	Total       int
	ShowBase    bool
	Models      int
}

func (h *H) scope(ctx context.Context, p *auth.Principal, f *analytics.Filter) bool {
	if p.CanViewAll() {
		return false
	}
	teams := make([]string, 0, len(p.Memberships))
	for _, m := range p.Memberships {
		teams = append(teams, m.TeamID)
	}
	f.RestrictToUser(ctx, h.d.Store.Pool, p.UserID(), teams)
	return true
}

func (h *H) index(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := auth.FromContext(ctx)
	days, _ := strconv.Atoi(r.URL.Query().Get("days"))
	if days != 7 && days != 30 && days != 90 {
		days = 30
	}
	f := analytics.LastDays(days)
	scoped := h.scope(ctx, p, &f)
	pool := h.d.Store.Pool

	data := indexData{Days: days, Scoped: scoped, CanViewAll: p.CanViewAll(), IsAdmin: p.IsAdmin(), CanCreate: !p.ReadOnly()}
	data.Name = "there"
	if p.User != nil {
		data.Name = strings.Fields(p.User.DisplayName() + " ")[0]
		if i := strings.IndexByte(data.Name, '@'); i > 0 {
			data.Name = data.Name[:i]
		}
	} else if p.IsAdmin() {
		data.Name = "admin"
	}
	data.Greeting = greeting(time.Now())

	cur, _ := analytics.GetTotals(ctx, pool, f)
	prev, _ := analytics.GetTotals(ctx, pool, f.Previous())
	data.Totals = cur
	pts, _ := analytics.Daily(ctx, pool, f)
	stats, _ := analytics.GetLogStats(ctx, pool, analytics.LogsFor(f))
	data.P95 = stats.P95LatencyMs

	series := func(fn func(analytics.DayPoint) float64) []float64 {
		out := make([]float64, len(pts))
		for i, pt := range pts {
			out[i] = fn(pt)
		}
		return out
	}
	mk := func(label, value, icon, tone string, c, pv float64, higherIsGood bool, hint string, vals []float64) KPI {
		k := KPI{Label: label, Value: value, Icon: icon, Tone: tone, Hint: hint}
		if pv > 0 {
			k.HasDelta = true
			k.Delta = (c - pv) / pv * 100
			k.Good = (k.Delta >= 0) == higherIsGood
			if math.Abs(k.Delta) < 0.05 {
				k.Good = true
			}
		}
		k.Spark, k.Area = sparkPaths(vals)
		return k
	}
	hitRate := func(t analytics.Totals) float64 {
		if t.Requests == 0 {
			return 0
		}
		return float64(t.CacheHits) / float64(t.Requests) * 100
	}
	data.KPIs = []KPI{
		mk("Spend", ui.Money(cur.Cost), "wallet", "primary", cur.Cost, prev.Cost, true,
			fmt.Sprintf("%s / day avg", ui.Money(cur.Cost/float64(days))), series(func(p analytics.DayPoint) float64 { return p.Cost })),
		mk("Requests", ui.Compact(cur.Requests), "activity", "secondary", float64(cur.Requests), float64(prev.Requests), true,
			fmt.Sprintf("%s / day avg", ui.Compact(float64(cur.Requests)/float64(days))), series(func(p analytics.DayPoint) float64 { return float64(p.Requests) })),
		mk("Tokens", ui.Compact(cur.Tokens()), "coins", "accent", float64(cur.Tokens()), float64(prev.Tokens()), true,
			fmt.Sprintf("%s in · %s out", ui.Compact(cur.PromptTokens), ui.Compact(cur.CompletionTokens)), series(func(p analytics.DayPoint) float64 { return float64(p.Tokens()) })),
		mk("Error rate", fmt.Sprintf("%.2f%%", cur.ErrorRate()), "triangle-alert", "error", cur.ErrorRate(), prev.ErrorRate(), false,
			fmt.Sprintf("%s failed requests", ui.Compact(cur.Failures)), series(func(p analytics.DayPoint) float64 { return p.ErrorRate() })),
		mk("Avg latency", fmt.Sprintf("%s ms", ui.Num(cur.AvgLatencyMs)), "timer", "info", cur.AvgLatencyMs, prev.AvgLatencyMs, false,
			fmt.Sprintf("p95 %s ms", ui.Num(stats.P95LatencyMs)), series(func(p analytics.DayPoint) float64 { return p.AvgLatencyMs })),
		mk("Cache hits", ui.Compact(cur.CacheHits), "database-zap", "success", float64(cur.CacheHits), float64(prev.CacheHits), true,
			fmt.Sprintf("%.1f%% hit rate", hitRate(cur)), series(func(p analytics.DayPoint) float64 { return float64(p.CacheHits) })),
	}

	data.SpendChart = analytics.DailyChart(pts, "line", "money", map[string]func(analytics.DayPoint) float64{
		"Spend": func(p analytics.DayPoint) float64 { return p.Cost },
	}, "Spend")
	data.ModelChart, _ = analytics.DailyByDim(ctx, pool, f, "model", "requests", "bar", 5)
	data.TopModels, _ = analytics.Breakdown(ctx, pool, f, "model", 6)
	data.ShareChart = analytics.BreakdownChart(data.TopModels, "cost", "doughnut")
	data.HasModelMix = len(data.TopModels) > 0

	keyRows, _ := analytics.Breakdown(ctx, pool, f, "key", 5)
	teamRows, _ := analytics.Breakdown(ctx, pool, f, "team", 5)
	data.TopKeys = h.keyBudgets(ctx, keyRows, cur.Cost)
	data.TopTeams = h.teamBudgets(ctx, teamRows, cur.Cost)

	data.Health = h.healthSnapshot(p)

	// Getting started.
	cl := checklist{HasModels: len(h.d.Registry.AllModelNames()) > 0, CanModels: p.CanViewAll()}
	var keyCount int
	if scoped {
		_ = pool.QueryRow(ctx, `SELECT count(*) FROM api_keys WHERE deleted_at IS NULL AND (user_id = $1::uuid OR team_id = ANY($2::uuid[]))`,
			nullUUID(p.UserID()), teamUUIDs(p)).Scan(&keyCount)
	} else {
		_ = pool.QueryRow(ctx, `SELECT count(*) FROM api_keys WHERE deleted_at IS NULL`).Scan(&keyCount)
	}
	cl.HasKeys = keyCount > 0
	cl.HasTraffic = cur.Requests > 0 || prev.Requests > 0
	if !cl.HasTraffic {
		lf := analytics.LogsFor(f)
		lf.Since, lf.Until, lf.Limit = time.Time{}, time.Time{}, 1
		if rows, err := analytics.ListLogs(ctx, pool, lf); err == nil && len(rows) > 0 {
			cl.HasTraffic = true
		}
	}
	for _, b := range []bool{cl.HasModels, cl.HasKeys, cl.HasTraffic} {
		if b {
			cl.Done++
		}
	}
	cl.Show = cl.Done < 3
	data.Checklist = cl

	h.d.Render(w, r, "dashboard/index", "dashboard", "Dashboard", data)
}

func (h *H) health(w http.ResponseWriter, r *http.Request) {
	p := auth.FromContext(r.Context())
	h.d.Partial(w, r, 200, area, "health-strip", h.healthSnapshot(p))
}

func (h *H) healthSnapshot(p *auth.Principal) healthData {
	allowed := p.AllowedModels(h.d.Registry)
	hd := healthData{ShowBase: p.CanViewAll()}
	models := map[string]bool{}
	for _, dep := range h.d.Registry.AllDeployments() {
		if allowed != nil && !slices.Contains(allowed, dep.Name) {
			continue
		}
		models[dep.Name] = true
		dh := DeploymentHealth{ID: dep.ID, Model: dep.Name, APIBase: dep.APIBase, Upstream: dep.UpstreamModel, Enabled: dep.Enabled,
			LatencyMs: dep.LatencyMs(), InFlight: dep.InFlight(), FromConfig: dep.FromConfig}
		dh.RPM, _ = dep.MinuteUsage()
		hl := dep.Health()
		switch {
		case !dep.Enabled:
			dh.Status = "unknown"
		case dep.CoolingDown():
			dh.Status = "cooldown"
			dh.CooldownIn = dep.CooldownRemaining().Round(time.Second).String()
		case hl == nil:
			dh.Status = "unknown"
		case hl.Healthy:
			dh.Status = "healthy"
		default:
			dh.Status = "unhealthy"
		}
		if hl != nil {
			dh.ProbeMs, dh.Checked, dh.Error = hl.LatencyMs, hl.Checked, hl.Error
		}
		if dh.Status == "healthy" || (dh.Status == "unknown" && dep.Enabled) {
			hd.Healthy++
		}
		hd.Deployments = append(hd.Deployments, dh)
	}
	hd.Total = len(hd.Deployments)
	hd.Models = len(models)
	return hd
}

func (h *H) keyBudgets(ctx context.Context, rows []analytics.Row, total float64) []Budgeted {
	out := make([]Budgeted, 0, len(rows))
	ids := make([]string, 0, len(rows))
	for _, r := range rows {
		if analytics.IsUUID(r.Key) {
			ids = append(ids, r.Key)
		}
	}
	type kinfo struct {
		alias, hint, period, owner string
		spend                      float64
		max                        *float64
	}
	info := map[string]kinfo{}
	if len(ids) > 0 {
		q, err := h.d.Store.Pool.Query(ctx, `SELECT k.id::text, k.alias, k.key_hint, k.spend, k.max_budget, k.budget_period,
			COALESCE(t.name, u.email, '') FROM api_keys k LEFT JOIN teams t ON t.id = k.team_id LEFT JOIN users u ON u.id = k.user_id
			WHERE k.id = ANY($1::uuid[])`, ids)
		if err == nil {
			for q.Next() {
				var id string
				var ki kinfo
				if q.Scan(&id, &ki.alias, &ki.hint, &ki.spend, &ki.max, &ki.period, &ki.owner) == nil {
					info[id] = ki
				}
			}
			q.Close()
		}
	}
	for _, r := range rows {
		b := Budgeted{Row: r, ID: r.Key, Href: "/ui/keys/" + r.Key, Share: share(r.Cost, total)}
		if ki, ok := info[r.Key]; ok {
			b.Sub, b.Spend, b.Max, b.Period = ki.hint, ki.spend, ki.max, ki.period
			if ki.owner != "" {
				b.Sub = ki.hint + " · " + ki.owner
			}
		} else {
			b.Label, b.Href = "Deleted key", ""
			b.Sub = r.Key
			if len(b.Sub) > 8 {
				b.Sub = b.Sub[:8] + "…"
			}
		}
		out = append(out, b)
	}
	return out
}

func (h *H) teamBudgets(ctx context.Context, rows []analytics.Row, total float64) []Budgeted {
	out := make([]Budgeted, 0, len(rows))
	ids := make([]string, 0, len(rows))
	for _, r := range rows {
		if analytics.IsUUID(r.Key) {
			ids = append(ids, r.Key)
		}
	}
	type tinfo struct {
		period  string
		spend   float64
		max     *float64
		members int
	}
	info := map[string]tinfo{}
	if len(ids) > 0 {
		q, err := h.d.Store.Pool.Query(ctx, `SELECT t.id::text, t.spend, t.max_budget, t.budget_period,
			(SELECT count(*) FROM team_members m WHERE m.team_id = t.id)::int FROM teams t WHERE t.id = ANY($1::uuid[])`, ids)
		if err == nil {
			for q.Next() {
				var id string
				var ti tinfo
				if q.Scan(&id, &ti.spend, &ti.max, &ti.period, &ti.members) == nil {
					info[id] = ti
				}
			}
			q.Close()
		}
	}
	for _, r := range rows {
		b := Budgeted{Row: r, ID: r.Key, Href: "/ui/teams/" + r.Key, Share: share(r.Cost, total)}
		if ti, ok := info[r.Key]; ok {
			b.Spend, b.Max, b.Period = ti.spend, ti.max, ti.period
			b.Sub = fmt.Sprintf("%d member%s", ti.members, plural(ti.members))
		}
		out = append(out, b)
	}
	return out
}

func share(v, total float64) float64 {
	if total <= 0 {
		return 0
	}
	return math.Min(100, v/total*100)
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

func nullUUID(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func teamUUIDs(p *auth.Principal) []string {
	out := []string{}
	for _, m := range p.Memberships {
		out = append(out, m.TeamID)
	}
	return out
}

func greeting(t time.Time) string {
	switch h := t.Hour(); {
	case h < 5:
		return "Working late"
	case h < 12:
		return "Good morning"
	case h < 18:
		return "Good afternoon"
	}
	return "Good evening"
}

// sparkPaths renders values as an SVG line path and area path in a 100x32 box.
func sparkPaths(vals []float64) (string, string) {
	if len(vals) < 2 {
		return "", ""
	}
	maxV := 0.0
	for _, v := range vals {
		maxV = math.Max(maxV, v)
	}
	if maxV == 0 {
		return "M0,30 L100,30", ""
	}
	var line strings.Builder
	step := 100.0 / float64(len(vals)-1)
	for i, v := range vals {
		x := float64(i) * step
		y := 30 - (v/maxV)*26
		if i == 0 {
			fmt.Fprintf(&line, "M%.2f,%.2f", x, y)
		} else {
			fmt.Fprintf(&line, " L%.2f,%.2f", x, y)
		}
	}
	return line.String(), line.String() + " L100,32 L0,32 Z"
}
