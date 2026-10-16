// Package metrics exposes Prometheus metrics for the gateway.
//
// Event metrics (counters and histograms) are updated inline as requests flow.
// State metrics (deployment in-flight, health, cooldown, cache size, queue depth,
// spend and budgets) are read at scrape time through the collector installed with
// SetLive, so they never go stale and disappear when the thing they describe does.
package metrics

import (
	"sync/atomic"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
)

// Deployment labels shared by every per-deployment metric.
var depLabels = []string{"model", "api_base", "deployment"}

var (
	Registry = prometheus.NewRegistry()

	BuildInfo = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "lemongate_build_info", Help: "Always 1; labelled with the running version.",
	}, []string{"version", "goversion"})

	Requests = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "lemongate_requests_total", Help: "Gateway requests by route, model and status.",
	}, []string{"route", "model", "status"})
	Tokens = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "lemongate_tokens_total", Help: "Tokens processed by model and direction.",
	}, []string{"model", "direction"})
	Cost = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "lemongate_cost_usd_total", Help: "Computed cost in USD by model.",
	}, []string{"model"})
	Latency = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name: "lemongate_request_duration_seconds", Help: "End-to-end request latency.",
		Buckets: []float64{.05, .1, .25, .5, 1, 2, 5, 10, 20, 40, 80, 160},
	}, []string{"route", "model"})
	TTFT = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name: "lemongate_time_to_first_token_seconds", Help: "Time to first streamed token.",
		Buckets: []float64{.025, .05, .1, .25, .5, 1, 2, 5, 10},
	}, []string{"model"})

	UpstreamRequests = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "lemongate_upstream_requests_total", Help: "Attempts sent to each deployment by outcome (2xx, 4xx, 5xx, error).",
	}, append(depLabels, "code"))
	UpstreamLatency = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name: "lemongate_upstream_response_seconds", Help: "Time until a deployment returned response headers.",
		Buckets: []float64{.025, .05, .1, .25, .5, 1, 2, 5, 10, 20, 40, 80},
	}, depLabels)
	DeploymentFailures = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "lemongate_deployment_failures_total", Help: "Failed attempts (connection errors, 429, 5xx) per deployment.",
	}, depLabels)
	Retries = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "lemongate_retries_total", Help: "Retried attempts within a model group.",
	}, []string{"model"})
	Fallbacks = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "lemongate_fallbacks_total", Help: "Requests moved to a fallback model group.",
	}, []string{"from", "to", "kind"})

	RateLimited = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "lemongate_rate_limited_total", Help: "Requests rejected by rate limits.",
	}, []string{"kind"})
	BudgetRejected = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "lemongate_budget_rejected_total", Help: "Requests rejected because a budget was exhausted.",
	})
	CacheLookups = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "lemongate_cache_lookups_total", Help: "Response cache lookups by result.",
	}, []string{"result"})
	GuardrailActions = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "lemongate_guardrail_actions_total", Help: "Guardrail interventions.",
	}, []string{"guardrail", "action"})
	MCPCalls = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "lemongate_mcp_tool_calls_total", Help: "MCP tool calls through the gateway.",
	}, []string{"server", "status"})
	AlertsSent = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "lemongate_alerts_sent_total", Help: "Alert deliveries by channel kind and result.",
	}, []string{"kind", "result"})
	SpendDropped = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "lemongate_spend_log_dropped_total", Help: "Request log records dropped because the write queue was full.",
	})
)

// live is the scrape-time collector installed by SetLive.
var live atomic.Pointer[prometheus.Collector]

type liveProxy struct{}

// Describe sends nothing: the live collector is unchecked, so the metrics it
// emits may change between scrapes (deployments and entities come and go).
func (liveProxy) Describe(chan<- *prometheus.Desc) {}

func (liveProxy) Collect(ch chan<- prometheus.Metric) {
	if c := live.Load(); c != nil {
		(*c).Collect(ch)
	}
}

// SetLive installs the collector that reports state at scrape time. The last call wins.
func SetLive(c prometheus.Collector) { live.Store(&c) }

func init() {
	Registry.MustRegister(collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
		BuildInfo, Requests, Tokens, Cost, Latency, TTFT, UpstreamRequests, UpstreamLatency, DeploymentFailures,
		Retries, Fallbacks, RateLimited, BudgetRejected, CacheLookups, GuardrailActions, MCPCalls, AlertsSent,
		SpendDropped, liveProxy{})
}

// CodeClass buckets an upstream HTTP status for lemongate_upstream_requests_total.
func CodeClass(status int) string {
	switch {
	case status <= 0:
		return "error"
	case status < 300:
		return "2xx"
	case status < 400:
		return "3xx"
	case status < 500:
		return "4xx"
	}
	return "5xx"
}
