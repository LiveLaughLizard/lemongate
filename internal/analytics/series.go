package analytics

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Metric selects the value plotted by series helpers: cost | requests | tokens | failures.
func metricExpr(metric string) string {
	switch metric {
	case "requests":
		return "sum(requests)::float8"
	case "tokens":
		return "sum(prompt_tokens + completion_tokens)::float8"
	case "failures":
		return "sum(failures)::float8"
	}
	return "sum(cost)"
}

// MetricFormat maps a metric to a ChartSpec format.
func MetricFormat(metric string) string {
	if metric == "cost" || metric == "" {
		return "money"
	}
	return "num"
}

// MetricValue extracts a metric from totals.
func MetricValue(t Totals, metric string) float64 {
	switch metric {
	case "requests":
		return float64(t.Requests)
	case "tokens":
		return float64(t.Tokens())
	case "failures":
		return float64(t.Failures)
	}
	return t.Cost
}

// DailyByDim builds a stacked daily chart split by a dimension (model | key | team |
// user | org | end_user). The top N values get their own series; the rest are "Other".
func DailyByDim(ctx context.Context, pool *pgxpool.Pool, f Filter, by, metric, typ string, top int) (ChartSpec, error) {
	spec := ChartSpec{Type: typ, Format: MetricFormat(metric), Stacked: true}
	for d := truncDay(f.From); !d.After(truncDay(f.To)); d = d.AddDate(0, 0, 1) {
		spec.Labels = append(spec.Labels, d.Format("Jan 2"))
	}
	col, ok := breakdownCols[by]
	if !ok {
		return spec, fmt.Errorf("unknown dimension %q", by)
	}
	if top <= 0 {
		top = 6
	}
	heads, err := Breakdown(ctx, pool, f, by, top)
	if err != nil {
		return spec, err
	}
	var args []any
	q := `SELECT day, ` + col + `, ` + metricExpr(metric) + ` FROM daily_spend WHERE ` + f.where(&args) + ` GROUP BY day, ` + col
	rows, err := pool.Query(ctx, q, args...)
	if err != nil {
		return spec, err
	}
	index := map[string]int{}
	for i, h := range heads {
		index[h.Key] = i
	}
	n := len(spec.Labels)
	series := make([][]float64, len(heads)+1)
	for i := range series {
		series[i] = make([]float64, n)
	}
	base := truncDay(f.From)
	hasOther := false
	for rows.Next() {
		var day time.Time
		var key string
		var v float64
		if err := rows.Scan(&day, &key, &v); err != nil {
			rows.Close()
			return spec, err
		}
		i := int(truncDay(day).Sub(base).Hours() / 24)
		if i < 0 || i >= n {
			continue
		}
		si, ok := index[key]
		if !ok {
			si = len(heads)
			if v != 0 {
				hasOther = true
			}
		}
		series[si][i] += v
	}
	rows.Close()
	for i, h := range heads {
		label := h.Label
		if label == "" {
			label = h.Key
		}
		spec.Datasets = append(spec.Datasets, Dataset{Label: label, Data: series[i]})
	}
	if hasOther {
		spec.Datasets = append(spec.Datasets, Dataset{Label: "Other", Data: series[len(heads)]})
	}
	return spec, rows.Err()
}

// BreakdownChart turns breakdown rows into a doughnut (or horizontal bar) chart.
func BreakdownChart(rows []Row, metric, typ string) ChartSpec {
	spec := ChartSpec{Type: typ, Format: MetricFormat(metric), Horizontal: typ == "bar"}
	ds := Dataset{Label: metricLabel(metric)}
	for _, r := range rows {
		spec.Labels = append(spec.Labels, r.Label)
		ds.Data = append(ds.Data, MetricValue(r.Totals, metric))
	}
	spec.Datasets = []Dataset{ds}
	return spec
}

func metricLabel(metric string) string {
	switch metric {
	case "requests":
		return "Requests"
	case "tokens":
		return "Tokens"
	case "failures":
		return "Errors"
	}
	return "Spend"
}

// TagBreakdown groups usage by request tag. Unscoped queries read the daily tag
// rollup; queries narrowed by key/team/user/org/end user (or member scope) fall
// back to request logs, since the tag rollup is not attributed to owners.
func TagBreakdown(ctx context.Context, pool *pgxpool.Pool, f Filter, limit int) ([]Row, error) {
	if limit <= 0 {
		limit = 10
	}
	var rows pgx.Rows
	var err error
	if !f.Scoped() && f.KeyID == "" && f.TeamID == "" && f.UserID == "" && f.OrgID == "" && f.EndUser == "" {
		args := []any{f.From.Format("2006-01-02"), f.To.Format("2006-01-02"), f.Model, limit}
		rows, err = pool.Query(ctx, `SELECT tag, sum(requests)::bigint, sum(failures)::bigint, 0::bigint, sum(prompt_tokens)::bigint,
			sum(completion_tokens)::bigint, sum(cost), 0::bigint FROM daily_tag_spend
			WHERE day BETWEEN $1::date AND $2::date AND ($3 = '' OR model = $3)
			GROUP BY tag ORDER BY sum(cost) DESC, sum(requests) DESC LIMIT $4`, args...)
	} else {
		lf := logFilterFrom(f)
		var args []any
		where := lf.where(&args)
		args = append(args, limit)
		rows, err = pool.Query(ctx, `SELECT tag, count(*)::bigint, count(*) FILTER (WHERE l.status <> 'success')::bigint,
			count(*) FILTER (WHERE l.cache_hit)::bigint, sum(l.prompt_tokens)::bigint, sum(l.completion_tokens)::bigint, sum(l.cost),
			sum(l.latency_ms)::bigint FROM request_logs l CROSS JOIN LATERAL unnest(l.tags) AS tag WHERE `+where+`
			GROUP BY tag ORDER BY sum(l.cost) DESC, count(*) DESC LIMIT $`+fmt.Sprint(len(args)), args...)
	}
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Row, error) {
		var x Row
		var lat int64
		err := r.Scan(&x.Key, &x.Requests, &x.Failures, &x.CacheHits, &x.PromptTokens, &x.CompletionTokens, &x.Cost, &lat)
		x.Label = x.Key
		if x.Requests > 0 {
			x.AvgLatencyMs = float64(lat) / float64(x.Requests)
		}
		return x, err
	})
}

// SortRows orders breakdown rows by a column: label | requests | tokens | cost |
// errors | latency.
func SortRows(rows []Row, by string, asc bool) {
	less := func(a, b Row) bool {
		switch by {
		case "label":
			return a.Label < b.Label
		case "requests":
			return a.Requests < b.Requests
		case "tokens":
			return a.Tokens() < b.Tokens()
		case "errors":
			return a.ErrorRate() < b.ErrorRate()
		case "latency":
			return a.AvgLatencyMs < b.AvgLatencyMs
		case "cache":
			return a.CacheHits < b.CacheHits
		}
		return a.Cost < b.Cost
	}
	sort.SliceStable(rows, func(i, j int) bool {
		if asc {
			return less(rows[i], rows[j])
		}
		return less(rows[j], rows[i])
	})
}
