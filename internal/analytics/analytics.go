// Package analytics answers usage questions from the daily rollups and request logs.
package analytics

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Filter scopes a query. Empty fields are unconstrained.
type Filter struct {
	From, To time.Time // inclusive dates (UTC days)
	KeyID    string
	UserID   string
	TeamID   string
	OrgID    string
	Model    string
	EndUser  string
	// KeyIDs/TeamIDs restrict to a set (used for member-scoped views); nil = no restriction.
	KeyIDs  []string
	TeamIDs []string
	// ScopeUserID additionally admits rows attributed to this user when the
	// filter is scoped (KeyIDs/TeamIDs/ScopeUserID set). See RestrictToUser.
	ScopeUserID string
}

// LastDays returns a filter covering the last n days including today.
func LastDays(n int) Filter {
	to := time.Now().UTC()
	return Filter{From: to.AddDate(0, 0, -(n - 1)), To: to}
}

func (f Filter) where(args *[]any) string {
	add := func(v any) string {
		*args = append(*args, v)
		return fmt.Sprintf("$%d", len(*args))
	}
	w := "day BETWEEN " + add(f.From.Format("2006-01-02")) + "::date AND " + add(f.To.Format("2006-01-02")) + "::date"
	for col, v := range map[string]string{"key_id": f.KeyID, "user_id": f.UserID, "team_id": f.TeamID, "org_id": f.OrgID, "model": f.Model, "end_user": f.EndUser} {
		if v != "" {
			w += " AND " + col + " = " + add(v)
		}
	}
	if f.Scoped() {
		keys, teams := f.KeyIDs, f.TeamIDs
		if keys == nil {
			keys = []string{}
		}
		if teams == nil {
			teams = []string{}
		}
		cond := "key_id = ANY(" + add(keys) + "::text[]) OR team_id = ANY(" + add(teams) + "::text[])"
		if f.ScopeUserID != "" {
			cond += " OR user_id = " + add(f.ScopeUserID)
		}
		w += " AND (" + cond + ")"
	}
	return w
}

type Totals struct {
	Requests         int64
	Failures         int64
	CacheHits        int64
	PromptTokens     int64
	CompletionTokens int64
	Cost             float64
	AvgLatencyMs     float64
}

func (t Totals) Tokens() int64 { return t.PromptTokens + t.CompletionTokens }

func (t Totals) ErrorRate() float64 {
	if t.Requests == 0 {
		return 0
	}
	return float64(t.Failures) / float64(t.Requests) * 100
}

func GetTotals(ctx context.Context, pool *pgxpool.Pool, f Filter) (Totals, error) {
	var args []any
	var t Totals
	var lat int64
	err := pool.QueryRow(ctx, `SELECT COALESCE(sum(requests),0)::bigint, COALESCE(sum(failures),0)::bigint, COALESCE(sum(cache_hits),0)::bigint,
		COALESCE(sum(prompt_tokens),0)::bigint, COALESCE(sum(completion_tokens),0)::bigint, COALESCE(sum(cost),0), COALESCE(sum(latency_ms_sum),0)::bigint
		FROM daily_spend WHERE `+f.where(&args), args...).Scan(&t.Requests, &t.Failures, &t.CacheHits, &t.PromptTokens, &t.CompletionTokens, &t.Cost, &lat)
	if t.Requests > 0 {
		t.AvgLatencyMs = float64(lat) / float64(t.Requests)
	}
	return t, err
}

type DayPoint struct {
	Day time.Time
	Totals
}

// Daily returns one point per day in the range (zero-filled).
func Daily(ctx context.Context, pool *pgxpool.Pool, f Filter) ([]DayPoint, error) {
	var args []any
	rows, err := pool.Query(ctx, `SELECT day, sum(requests)::bigint, sum(failures)::bigint, sum(cache_hits)::bigint, sum(prompt_tokens)::bigint,
		sum(completion_tokens)::bigint, sum(cost), sum(latency_ms_sum)::bigint FROM daily_spend WHERE `+f.where(&args)+` GROUP BY day ORDER BY day`, args...)
	if err != nil {
		return nil, err
	}
	byDay := map[string]DayPoint{}
	for rows.Next() {
		var p DayPoint
		var lat int64
		if err := rows.Scan(&p.Day, &p.Requests, &p.Failures, &p.CacheHits, &p.PromptTokens, &p.CompletionTokens, &p.Cost, &lat); err != nil {
			rows.Close()
			return nil, err
		}
		if p.Requests > 0 {
			p.AvgLatencyMs = float64(lat) / float64(p.Requests)
		}
		byDay[p.Day.Format("2006-01-02")] = p
	}
	rows.Close()
	var out []DayPoint
	for d := truncDay(f.From); !d.After(truncDay(f.To)); d = d.AddDate(0, 0, 1) {
		p, ok := byDay[d.Format("2006-01-02")]
		if !ok {
			p = DayPoint{Day: d}
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func truncDay(t time.Time) time.Time {
	t = t.UTC()
	return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC)
}

type Row struct {
	Key   string
	Label string
	Totals
}

var breakdownCols = map[string]string{"model": "model", "key": "key_id", "team": "team_id", "user": "user_id", "org": "org_id", "end_user": "end_user"}

// Breakdown groups totals by a dimension: model | key | team | user | org | end_user.
// Labels are resolved to human-readable names where possible.
func Breakdown(ctx context.Context, pool *pgxpool.Pool, f Filter, by string, limit int) ([]Row, error) {
	col, ok := breakdownCols[by]
	if !ok {
		return nil, fmt.Errorf("unknown breakdown %q", by)
	}
	if limit <= 0 {
		limit = 10
	}
	var args []any
	where := f.where(&args)
	args = append(args, limit)
	label := col
	join := ""
	switch by {
	case "key":
		join = ` LEFT JOIN api_keys k ON k.id::text = s.key_id`
		label = `COALESCE(NULLIF(k.alias,''), k.key_hint, s.key_id)`
	case "team":
		join = ` LEFT JOIN teams t ON t.id::text = s.team_id`
		label = `COALESCE(t.name, s.team_id)`
	case "user":
		join = ` LEFT JOIN users u ON u.id::text = s.user_id`
		label = `COALESCE(u.email, s.user_id)`
	case "org":
		join = ` LEFT JOIN organizations o ON o.id::text = s.org_id`
		label = `COALESCE(o.name, s.org_id)`
	default:
		label = "s." + col
	}
	q := `SELECT s.` + col + `, max(` + label + `), sum(requests)::bigint, sum(failures)::bigint, sum(cache_hits)::bigint, sum(prompt_tokens)::bigint,
		sum(completion_tokens)::bigint, sum(cost), sum(latency_ms_sum)::bigint
		FROM (SELECT * FROM daily_spend WHERE ` + where + `) s` + join + ` WHERE s.` + col + ` <> '' GROUP BY s.` + col + ` ORDER BY sum(cost) DESC, sum(requests) DESC LIMIT $` + fmt.Sprint(len(args))
	rows, err := pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Row, error) {
		var x Row
		var lat int64
		err := r.Scan(&x.Key, &x.Label, &x.Requests, &x.Failures, &x.CacheHits, &x.PromptTokens, &x.CompletionTokens, &x.Cost, &lat)
		if x.Requests > 0 {
			x.AvgLatencyMs = float64(lat) / float64(x.Requests)
		}
		return x, err
	})
}

// ChartSpec is the JSON consumed by the console's chart helper (canvas[data-chart]).
type ChartSpec struct {
	Type       string    `json:"type"` // line | bar | doughnut
	Labels     []string  `json:"labels"`
	Datasets   []Dataset `json:"datasets"`
	Format     string    `json:"format,omitempty"` // money | num | ms | pct
	Stacked    bool      `json:"stacked,omitempty"`
	Horizontal bool      `json:"horizontal,omitempty"`
	Legend     *bool     `json:"legend,omitempty"`
}

type Dataset struct {
	Label      string    `json:"label"`
	Data       []float64 `json:"data"`
	ColorIndex *int      `json:"colorIndex,omitempty"`
}

// DailyChart builds a chart from daily points using the selector for values.
func DailyChart(points []DayPoint, typ, format string, series map[string]func(DayPoint) float64, order ...string) ChartSpec {
	spec := ChartSpec{Type: typ, Format: format}
	for _, p := range points {
		spec.Labels = append(spec.Labels, p.Day.Format("Jan 2"))
	}
	for _, name := range order {
		fn := series[name]
		ds := Dataset{Label: name}
		for _, p := range points {
			ds.Data = append(ds.Data, fn(p))
		}
		spec.Datasets = append(spec.Datasets, ds)
	}
	return spec
}
