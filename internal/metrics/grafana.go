package metrics

import (
	"encoding/json"
	"strings"
)

// GrafanaDashboard returns an importable Grafana dashboard for the exported
// metrics. It asks for a Prometheus data source on import and filters by model
// through the $model variable.
func GrafanaDashboard(title string) []byte {
	if title == "" {
		title = "LemonGate"
	}
	b := &dash{}
	m := `model=~"$model"`

	b.row("Overview")
	b.stat("Requests / s", `sum(rate(lemongate_requests_total{`+m+`}[$__rate_interval]))`, "reqps", 4)
	b.stat("Error rate", `sum(rate(lemongate_requests_total{`+m+`,status!="success"}[$__rate_interval])) / clamp_min(sum(rate(lemongate_requests_total{`+m+`}[$__rate_interval])), 1e-9)`, "percentunit", 4)
	b.stat("p95 latency", `histogram_quantile(0.95, sum by (le) (rate(lemongate_request_duration_seconds_bucket{`+m+`}[$__rate_interval])))`, "s", 4)
	b.stat("Tokens / s", `sum(rate(lemongate_tokens_total{`+m+`}[$__rate_interval]))`, "short", 4)
	b.stat("Spend (range)", `sum(increase(lemongate_cost_usd_total{`+m+`}[$__range]))`, "currencyUSD", 4)
	b.stat("Healthy deployments", `sum(lemongate_deployment_healthy{`+m+`}) / clamp_min(count(lemongate_deployment_healthy{`+m+`}), 1)`, "percentunit", 4)

	b.row("Traffic")
	b.series("Requests / s by model", "reqps", 12, q(`sum by (model) (rate(lemongate_requests_total{`+m+`}[$__rate_interval]))`, "{{model}}"))
	b.series("Requests / s by status", "reqps", 12, q(`sum by (status) (rate(lemongate_requests_total{`+m+`}[$__rate_interval]))`, "{{status}}"))
	b.series("Latency", "s", 12,
		q(`histogram_quantile(0.5, sum by (le) (rate(lemongate_request_duration_seconds_bucket{`+m+`}[$__rate_interval])))`, "p50"),
		q(`histogram_quantile(0.95, sum by (le) (rate(lemongate_request_duration_seconds_bucket{`+m+`}[$__rate_interval])))`, "p95"),
		q(`histogram_quantile(0.99, sum by (le) (rate(lemongate_request_duration_seconds_bucket{`+m+`}[$__rate_interval])))`, "p99"))
	b.series("Time to first token (p95) by model", "s", 12,
		q(`histogram_quantile(0.95, sum by (le, model) (rate(lemongate_time_to_first_token_seconds_bucket{`+m+`}[$__rate_interval])))`, "{{model}}"))
	b.series("Tokens / s", "short", 12, q(`sum by (model, direction) (rate(lemongate_tokens_total{`+m+`}[$__rate_interval]))`, "{{model}} {{direction}}"))
	b.series("Spend per hour by model", "currencyUSD", 12, q(`sum by (model) (increase(lemongate_cost_usd_total{`+m+`}[1h]))`, "{{model}}"))

	b.row("Deployments")
	b.series("Upstream attempts / s by outcome", "reqps", 12, q(`sum by (model, api_base, code) (rate(lemongate_upstream_requests_total{`+m+`}[$__rate_interval]))`, "{{model}} {{api_base}} {{code}}"))
	b.series("Upstream response time (p95)", "s", 12, q(`histogram_quantile(0.95, sum by (le, model, api_base) (rate(lemongate_upstream_response_seconds_bucket{`+m+`}[$__rate_interval])))`, "{{model}} {{api_base}}"))
	b.series("In-flight requests", "short", 8, q(`sum by (model, api_base) (lemongate_deployment_inflight{`+m+`})`, "{{model}} {{api_base}}"))
	b.series("Health (1 = up)", "short", 8, q(`lemongate_deployment_healthy{`+m+`}`, "{{model}} {{api_base}}"))
	b.series("Cooling down", "short", 8, q(`lemongate_deployment_cooling_down{`+m+`}`, "{{model}} {{api_base}}"))
	b.series("Retries & fallbacks / s", "reqps", 12,
		q(`sum by (model) (rate(lemongate_retries_total{`+m+`}[$__rate_interval]))`, "retry {{model}}"),
		q(`sum by (from, to) (rate(lemongate_fallbacks_total[$__rate_interval]))`, "fallback {{from}} → {{to}}"))
	b.series("Failures / s by deployment", "reqps", 12, q(`sum by (model, api_base) (rate(lemongate_deployment_failures_total{`+m+`}[$__rate_interval]))`, "{{model}} {{api_base}}"))

	b.row("Limits, cache & extensions")
	b.series("Rejected by limits / s", "reqps", 8,
		q(`sum by (kind) (rate(lemongate_rate_limited_total[$__rate_interval]))`, "rate limit {{kind}}"),
		q(`sum(rate(lemongate_budget_rejected_total[$__rate_interval]))`, "budget"))
	b.series("Cache hit ratio", "percentunit", 8, q(`sum(rate(lemongate_cache_lookups_total{result="hit"}[$__rate_interval])) / clamp_min(sum(rate(lemongate_cache_lookups_total[$__rate_interval])), 1e-9)`, "hit ratio"))
	b.series("Guardrail actions / s", "reqps", 8, q(`sum by (guardrail, action) (rate(lemongate_guardrail_actions_total[$__rate_interval]))`, "{{guardrail}} {{action}}"))
	b.series("MCP tool calls / s", "reqps", 8, q(`sum by (server, status) (rate(lemongate_mcp_tool_calls_total[$__rate_interval]))`, "{{server}} {{status}}"))
	b.series("Alerts sent", "short", 8, q(`sum by (kind, result) (increase(lemongate_alerts_sent_total[$__rate_interval]))`, "{{kind}} {{result}}"))
	b.series("Request log queue", "short", 8,
		q(`lemongate_spend_log_queue_depth`, "queued"),
		q(`increase(lemongate_spend_log_dropped_total[$__rate_interval])`, "dropped"))

	b.row("Spend & budgets (requires per-entity metrics)")
	b.bars("Top keys by spend", 12, q(`topk(10, lemongate_key_spend_usd)`, "{{key_alias}} ({{team}})"))
	b.bars("Top teams by spend", 12, q(`topk(10, lemongate_team_spend_usd)`, "{{team}}"))
	b.bars("Keys closest to budget", 12, q(`topk(10, lemongate_key_spend_usd / on (key_id) lemongate_key_budget_usd)`, "{{key_alias}}"))
	b.bars("Teams closest to budget", 12, q(`topk(10, lemongate_team_spend_usd / on (team_id) lemongate_team_budget_usd)`, "{{team}}"))

	doc := map[string]any{
		"__inputs": []any{map[string]any{"name": "DS_PROMETHEUS", "label": "Prometheus", "type": "datasource",
			"pluginId": "prometheus", "pluginName": "Prometheus"}},
		"title":         title,
		"uid":           "lemongate-gateway",
		"tags":          []string{"lemongate", "llm", "vllm"},
		"timezone":      "browser",
		"schemaVersion": 39,
		"version":       1,
		"editable":      true,
		"refresh":       "30s",
		"time":          map[string]any{"from": "now-6h", "to": "now"},
		"panels":        b.panels,
		"templating": map[string]any{"list": []any{
			map[string]any{"name": "datasource", "label": "Data source", "type": "datasource", "query": "prometheus",
				"current": map[string]any{"text": "${DS_PROMETHEUS}", "value": "${DS_PROMETHEUS}"}},
			map[string]any{"name": "model", "label": "Model", "type": "query", "datasource": ds,
				"query":   map[string]any{"query": "label_values(lemongate_requests_total, model)", "refId": "model"},
				"refresh": 2, "includeAll": true, "multi": true, "allValue": ".*",
				"current": map[string]any{"text": "All", "value": "$__all"}},
		}},
	}
	out, _ := json.MarshalIndent(doc, "", "  ")
	return out
}

var ds = map[string]any{"type": "prometheus", "uid": "${datasource}"}

type target struct{ expr, legend string }

func q(expr, legend string) target { return target{expr, legend} }

type dash struct {
	panels []any
	x, y   int
	rowH   int
	id     int
}

func (b *dash) place(w, h int) map[string]any {
	if b.x+w > 24 {
		b.x, b.y = 0, b.y+b.rowH
		b.rowH = 0
	}
	pos := map[string]any{"x": b.x, "y": b.y, "w": w, "h": h}
	b.x += w
	b.rowH = max(b.rowH, h)
	return pos
}

func (b *dash) add(p map[string]any) {
	b.id++
	p["id"] = b.id
	b.panels = append(b.panels, p)
}

func (b *dash) row(title string) {
	b.x, b.y, b.rowH = 0, b.y+b.rowH, 0
	b.add(map[string]any{"type": "row", "title": title, "collapsed": false, "panels": []any{}, "gridPos": b.place(24, 1)})
	b.x, b.y, b.rowH = 0, b.y+1, 0
}

func targets(ts []target) []any {
	out := make([]any, len(ts))
	for i, t := range ts {
		out[i] = map[string]any{"datasource": ds, "expr": t.expr, "legendFormat": t.legend, "refId": string(rune('A' + i))}
	}
	return out
}

func (b *dash) stat(title, expr, unit string, w int) {
	b.add(map[string]any{"type": "stat", "title": title, "datasource": ds, "gridPos": b.place(w, 4),
		"targets":     targets([]target{{expr, ""}}),
		"fieldConfig": map[string]any{"defaults": map[string]any{"unit": unit, "decimals": 2}, "overrides": []any{}},
		"options": map[string]any{"reduceOptions": map[string]any{"calcs": []string{"lastNotNull"}},
			"colorMode": "value", "graphMode": "area", "textMode": "value"}})
}

func (b *dash) series(title, unit string, w int, ts ...target) {
	b.add(map[string]any{"type": "timeseries", "title": title, "datasource": ds, "gridPos": b.place(w, 8),
		"targets": targets(ts),
		"fieldConfig": map[string]any{"defaults": map[string]any{"unit": unit,
			"custom": map[string]any{"fillOpacity": 12, "lineWidth": 2, "showPoints": "never"}}, "overrides": []any{}},
		"options": map[string]any{"legend": map[string]any{"displayMode": "list", "placement": "bottom"},
			"tooltip": map[string]any{"mode": "multi", "sort": "desc"}}})
}

func (b *dash) bars(title string, w int, ts ...target) {
	unit := "currencyUSD"
	if strings.Contains(ts[0].expr, "/") {
		unit = "percentunit"
	}
	b.add(map[string]any{"type": "bargauge", "title": title, "datasource": ds, "gridPos": b.place(w, 8),
		"targets":     []any{map[string]any{"datasource": ds, "expr": ts[0].expr, "legendFormat": ts[0].legend, "refId": "A", "instant": true}},
		"fieldConfig": map[string]any{"defaults": map[string]any{"unit": unit, "min": 0}, "overrides": []any{}},
		"options": map[string]any{"orientation": "horizontal", "displayMode": "gradient",
			"reduceOptions": map[string]any{"calcs": []string{"lastNotNull"}}}})
}
