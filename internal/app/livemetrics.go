package app

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"lemongate/internal/metrics"
	"lemongate/internal/routing"
)

// liveCollector reports state at scrape time: deployments, cache, the log queue
// and (when enabled) per-entity spend and budgets.
type liveCollector struct {
	a *App

	mu       sync.Mutex
	entities []prometheus.Metric
	loaded   time.Time
}

// entityTTL bounds how often a scrape hits Postgres for spend gauges.
const entityTTL = 15 * time.Second

// entityLimit caps series per entity kind (largest spenders first).
const entityLimit = 2000

var (
	depLabels    = []string{"model", "api_base", "deployment"}
	descInFlight = prometheus.NewDesc(metrics.DeploymentInFlightName, "Requests currently in flight.", depLabels, nil)
	descHealthy  = prometheus.NewDesc(metrics.DeploymentHealthyName, "1 if the deployment passed its last health check.", depLabels, nil)
	descCooling  = prometheus.NewDesc(metrics.DeploymentCoolingName, "1 while the deployment is in cooldown.", depLabels, nil)
	descEWMA     = prometheus.NewDesc(metrics.DeploymentLatencyName, "Smoothed (EWMA) response latency.", depLabels, nil)
	descDeps     = prometheus.NewDesc(metrics.DeploymentsName, "Enabled deployments per model group.", []string{"model"}, nil)
	descEntries  = prometheus.NewDesc(metrics.CacheEntriesName, "Entries held in the response cache.", nil, nil)
	descBytes    = prometheus.NewDesc(metrics.CacheBytesName, "Bytes held in the response cache.", nil, nil)
	descQueue    = prometheus.NewDesc(metrics.SpendQueueName, "Request log records waiting to be written.", nil, nil)
)

type entityQuery struct {
	spend, budget *prometheus.Desc
	prefix        string // spend.Writer pending-entity prefix
	withTeam      bool   // the query returns a fifth column: team name
	sql           string
}

var entityQueries = []entityQuery{
	{
		spend:  prometheus.NewDesc("lemongate_key_spend_usd", "Current-period spend per API key.", []string{"key_id", "key_alias", "team"}, nil),
		budget: prometheus.NewDesc("lemongate_key_budget_usd", "Budget per API key.", []string{"key_id", "key_alias", "team"}, nil),
		prefix: "key:", withTeam: true,
		sql: `SELECT k.id::text, k.spend, k.max_budget, k.alias, coalesce(t.name, '')
			FROM api_keys k LEFT JOIN teams t ON t.id = k.team_id ORDER BY k.spend DESC LIMIT $1`,
	},
	{
		spend:  prometheus.NewDesc("lemongate_team_spend_usd", "Current-period spend per team.", []string{"team_id", "team"}, nil),
		budget: prometheus.NewDesc("lemongate_team_budget_usd", "Budget per team.", []string{"team_id", "team"}, nil),
		prefix: "team:",
		sql:    `SELECT id::text, spend, max_budget, name FROM teams ORDER BY spend DESC LIMIT $1`,
	},
	{
		spend:  prometheus.NewDesc("lemongate_user_spend_usd", "Current-period spend per user.", []string{"user_id", "user"}, nil),
		budget: prometheus.NewDesc("lemongate_user_budget_usd", "Budget per user.", []string{"user_id", "user"}, nil),
		prefix: "user:",
		sql:    `SELECT id::text, spend, max_budget, email FROM users ORDER BY spend DESC LIMIT $1`,
	},
	{
		spend:  prometheus.NewDesc("lemongate_org_spend_usd", "Current-period spend per organization.", []string{"org_id", "org"}, nil),
		budget: prometheus.NewDesc("lemongate_org_budget_usd", "Budget per organization.", []string{"org_id", "org"}, nil),
		prefix: "org:",
		sql:    `SELECT id::text, spend, max_budget, name FROM organizations ORDER BY spend DESC LIMIT $1`,
	},
}

func (c *liveCollector) Describe(chan<- *prometheus.Desc) {}

func (c *liveCollector) Collect(ch chan<- prometheus.Metric) {
	a := c.a
	perGroup := map[string]int{}
	for _, d := range a.Registry.AllDeployments() {
		if !d.Enabled {
			continue
		}
		perGroup[d.Name]++
		lv := []string{d.Name, routing.RedactBase(d.APIBase), d.ID}
		ch <- prometheus.MustNewConstMetric(descInFlight, prometheus.GaugeValue, float64(d.InFlight()), lv...)
		ch <- prometheus.MustNewConstMetric(descCooling, prometheus.GaugeValue, b2f(d.CoolingDown()), lv...)
		if ms := d.LatencyMs(); ms > 0 {
			ch <- prometheus.MustNewConstMetric(descEWMA, prometheus.GaugeValue, ms/1000, lv...)
		}
		if h := d.Health(); h != nil {
			ch <- prometheus.MustNewConstMetric(descHealthy, prometheus.GaugeValue, b2f(h.Healthy), lv...)
		}
	}
	for g, n := range perGroup {
		ch <- prometheus.MustNewConstMetric(descDeps, prometheus.GaugeValue, float64(n), g)
	}
	if a.Cache != nil {
		st := a.Cache.Stats(0)
		ch <- prometheus.MustNewConstMetric(descEntries, prometheus.GaugeValue, float64(st.Entries))
		ch <- prometheus.MustNewConstMetric(descBytes, prometheus.GaugeValue, float64(st.Bytes))
	}
	if a.Spend != nil {
		ch <- prometheus.MustNewConstMetric(descQueue, prometheus.GaugeValue, float64(a.Spend.QueueDepth()))
	}
	if a.Settings.Current().Metrics.EntityMetrics {
		for _, m := range c.entityMetrics() {
			ch <- m
		}
	}
}

// entityMetrics returns cached spend/budget gauges, refreshing them when stale.
func (c *liveCollector) entityMetrics() []prometheus.Metric {
	c.mu.Lock()
	defer c.mu.Unlock()
	if time.Since(c.loaded) < entityTTL {
		return c.entities
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var out []prometheus.Metric
	for _, q := range entityQueries {
		rows, err := c.a.Pool.Query(ctx, q.sql, entityLimit)
		if err != nil {
			slog.Warn("metrics: entity query", "err", err)
			return c.entities // keep serving the last good set
		}
		for rows.Next() {
			var id, name, team string
			var spend float64
			var budget *float64
			dst := []any{&id, &spend, &budget, &name}
			if q.withTeam {
				dst = append(dst, &team)
			}
			if err := rows.Scan(dst...); err != nil {
				continue
			}
			labels := []string{id, name}
			if q.withTeam {
				labels = append(labels, team)
			}
			spend += c.a.Spend.Pending(q.prefix + id)
			out = append(out, prometheus.MustNewConstMetric(q.spend, prometheus.GaugeValue, spend, labels...))
			if budget != nil {
				out = append(out, prometheus.MustNewConstMetric(q.budget, prometheus.GaugeValue, *budget, labels...))
			}
		}
		rows.Close()
	}
	c.entities, c.loaded = out, time.Now()
	return out
}

func b2f(b bool) float64 {
	if b {
		return 1
	}
	return 0
}
