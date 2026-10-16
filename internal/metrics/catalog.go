package metrics

// Info describes one exported metric for the console's reference table.
type Info struct {
	Name   string
	Type   string // counter | gauge | histogram
	Labels string
	Help   string
	Group  string
	// Optional is set for metrics only exported when per-entity metrics are enabled.
	Optional bool
}

// Live (scrape-time) metric names, shared with the collector in package app.
const (
	DeploymentInFlightName = "lemongate_deployment_inflight"
	DeploymentHealthyName  = "lemongate_deployment_healthy"
	DeploymentCoolingName  = "lemongate_deployment_cooling_down"
	DeploymentLatencyName  = "lemongate_deployment_latency_ewma_seconds"
	DeploymentsName        = "lemongate_deployments"
	CacheEntriesName       = "lemongate_cache_entries"
	CacheBytesName         = "lemongate_cache_bytes"
	SpendQueueName         = "lemongate_spend_log_queue_depth"
)

// Catalog lists every lemongate_* metric. A test keeps it in sync with the registry.
var Catalog = []Info{
	{"lemongate_build_info", "gauge", "version, goversion", "Always 1; labelled with the running version.", "Process", false},

	{"lemongate_requests_total", "counter", "route, model, status", "Gateway requests by route, model and status (success, error, blocked, …).", "Traffic", false},
	{"lemongate_request_duration_seconds", "histogram", "route, model", "End-to-end request latency, including retries and guardrails.", "Traffic", false},
	{"lemongate_time_to_first_token_seconds", "histogram", "model", "Time to the first streamed token.", "Traffic", false},
	{"lemongate_tokens_total", "counter", "model, direction", "Prompt and completion tokens.", "Traffic", false},
	{"lemongate_cost_usd_total", "counter", "model", "Computed cost in USD (pass-through routes use the route name).", "Traffic", false},

	{"lemongate_upstream_requests_total", "counter", "model, api_base, deployment, code", "Attempts sent to each deployment by outcome: 2xx, 4xx, 5xx or error (no response).", "Deployments", false},
	{"lemongate_upstream_response_seconds", "histogram", "model, api_base, deployment", "Time until a deployment returned response headers.", "Deployments", false},
	{"lemongate_deployment_failures_total", "counter", "model, api_base, deployment", "Failed attempts (connection errors, 429, 5xx).", "Deployments", false},
	{DeploymentInFlightName, "gauge", "model, api_base, deployment", "Requests currently in flight.", "Deployments", false},
	{DeploymentHealthyName, "gauge", "model, api_base, deployment", "1 if the last health probe passed, 0 if it failed (absent until probed).", "Deployments", false},
	{DeploymentCoolingName, "gauge", "model, api_base, deployment", "1 while the deployment is in cooldown after repeated failures.", "Deployments", false},
	{DeploymentLatencyName, "gauge", "model, api_base, deployment", "Smoothed (EWMA) response latency used by the lowest-latency strategy.", "Deployments", false},
	{DeploymentsName, "gauge", "model", "Enabled deployments per model group.", "Deployments", false},
	{"lemongate_retries_total", "counter", "model", "Retried attempts within a model group.", "Deployments", false},
	{"lemongate_fallbacks_total", "counter", "from, to, kind", "Requests moved to a fallback group (kind: general or context_window).", "Deployments", false},

	{"lemongate_rate_limited_total", "counter", "kind", "Requests rejected by rpm, tpm or parallel limits.", "Limits", false},
	{"lemongate_budget_rejected_total", "counter", "", "Requests rejected because a budget was exhausted.", "Limits", false},

	{"lemongate_cache_lookups_total", "counter", "result", "Response cache lookups (hit, miss).", "Cache", false},
	{CacheEntriesName, "gauge", "", "Entries currently held in the response cache.", "Cache", false},
	{CacheBytesName, "gauge", "", "Bytes of response bodies held in the cache.", "Cache", false},

	{"lemongate_guardrail_actions_total", "counter", "guardrail, action", "Guardrail interventions (blocked, masked, flagged, error).", "Extensions", false},
	{"lemongate_mcp_tool_calls_total", "counter", "server, status", "MCP tool calls through the gateway.", "Extensions", false},
	{"lemongate_alerts_sent_total", "counter", "kind, result", "Alert deliveries by channel kind (slack, mattermost, webhook, email) and result.", "Extensions", false},

	{SpendQueueName, "gauge", "", "Request log records waiting to be written to Postgres.", "Internals", false},
	{"lemongate_spend_log_dropped_total", "counter", "", "Request log records dropped because the write queue was full.", "Internals", false},

	{"lemongate_key_spend_usd", "gauge", "key_id, key_alias, team", "Current-period spend per API key.", "Spend & budgets", true},
	{"lemongate_key_budget_usd", "gauge", "key_id, key_alias, team", "Budget per API key (keys with a budget only).", "Spend & budgets", true},
	{"lemongate_team_spend_usd", "gauge", "team_id, team", "Current-period spend per team.", "Spend & budgets", true},
	{"lemongate_team_budget_usd", "gauge", "team_id, team", "Budget per team.", "Spend & budgets", true},
	{"lemongate_user_spend_usd", "gauge", "user_id, user", "Current-period spend per user.", "Spend & budgets", true},
	{"lemongate_user_budget_usd", "gauge", "user_id, user", "Budget per user.", "Spend & budgets", true},
	{"lemongate_org_spend_usd", "gauge", "org_id, org", "Current-period spend per organization.", "Spend & budgets", true},
	{"lemongate_org_budget_usd", "gauge", "org_id, org", "Budget per organization.", "Spend & budgets", true},
}
