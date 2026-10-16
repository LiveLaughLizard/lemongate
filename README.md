# LemonGate

**A self-hosted AI gateway and admin console for vLLM.**

Point your OpenAI-compatible clients at LemonGate and get virtual API keys, budgets, rate
limits, load balancing, fallbacks, usage analytics, request logs, guardrails, response
caching, pass-through routes, an MCP tool gateway, alerting and SSO. It ships as one Go
binary, and Postgres is the only dependency.

```
 OpenAI SDKs / curl / agents                         ┌──────────────────────────┐
 ───────────────────────────►  ┌─────────────────┐   │ vLLM replica  (model A)  │
   Authorization: Bearer lg-…  │                 ├──►│ vLLM replica  (model A)  │
                               │    LemonGate    │   │ vLLM server   (model B)  │
 Browser ── /ui ─────────────► │  gateway + UI   │   └──────────────────────────┘
                               │                 ├──► upstream MCP servers  (/mcp)
 Prometheus ── /metrics ─────► │                 ├──► any HTTP API          (/pt/<name>)
                               └────────┬────────┘
                                        │
                                   PostgreSQL
                     keys, spend, logs, settings, audit, …
```

---

## Contents

- [Features](#features)
- [Quick start (Docker)](#quick-start-docker)
- [Kubernetes (Helm)](#kubernetes-helm)
- [Calling the gateway](#calling-the-gateway)
- [Configuration](#configuration)
- [Models, routing and reliability](#models-routing-and-reliability)
- [Access control, budgets and limits](#access-control-budgets-and-limits)
- [Guardrails](#guardrails)
- [Response cache](#response-cache)
- [Pass-through routes](#pass-through-routes)
- [MCP gateway](#mcp-gateway)
- [Alerting](#alerting)
- [Single sign-on (OIDC)](#single-sign-on-oidc)
- [Admin API](#admin-api)
- [Observability](#observability)
- [Admin console](#admin-console)
- [CLI](#cli)
- [Running in production](#running-in-production)
- [Development](#development)

---

## Features

**Gateway** (OpenAI-compatible, under `/v1`)
- `chat/completions` and `completions` with SSE streaming, `embeddings`, `rerank`, `score`,
  `responses`, `audio/transcriptions`, `audio/translations`, `models`, plus `/tokenize` and
  `/detokenize`.
- Model groups: one public model name maps to many vLLM replicas. Routing strategies:
  weighted, least-busy, lowest-latency (EWMA) and lowest-usage.
- Retries with backoff, cooldowns after repeated failures, background health probes,
  general and context-window fallbacks, aliases and access groups.
- Virtual keys (`lg-…`, stored hashed) with model access, budgets, rpm/tpm/parallel limits,
  expiry, tags, guardrails and MCP server grants.
- A hierarchy of organizations, teams, users and keys, plus end users (the request `user`
  field) and tags, each with its own budget.
- Cost tracking from per-model token prices, with async batched request logs and daily rollups.

**Extensions**
- **Guardrails:** PII detection and masking by region, content categories, blocklists, regex,
  prompt-injection heuristics, dangerous-code detection, tool policies, known-attack
  similarity, self-hosted guard models and an LLM judge. A one-click preset gallery installs
  them as policies.
- **Response cache:** in-memory exact-match cache with TTL and per-key isolation.
- **Pass-through routes:** `/pt/<name>/*` to any upstream with injected credentials, key
  auth, budgets, rate limits and per-request cost.
- **MCP gateway:** aggregates upstream MCP servers behind `/mcp`, with per-key and per-team
  access control and call logs.
- **Alerts:** Slack, Mattermost, signed webhooks and email.
- **OIDC single sign-on** with role mapping and auto-provisioning.
- **JSON admin API** at `/api/v1` with an OpenAPI 3.1 document and an HTML reference.
- **Prometheus metrics** at `/metrics` and a downloadable Grafana dashboard.

**Console** (`/ui`): dashboard, playground, model hub, usage analytics, live request logs,
and management screens for every entity above. It has light and dark themes, a command
palette (Ctrl+K) and a responsive layout.

---

## Quick start (Docker)

Requirements: Docker with Compose v2.

```bash
git clone git@github.com:LiveLaughLizard/lemongate.git && cd lemongate
export LEMONGATE_MASTER_KEY=$(openssl rand -hex 24)
export LEMONGATE_SECRET_KEY=$(openssl rand -hex 32)
docker compose up -d --build
```

Open <http://localhost:4000/ui> and sign in with the master key.

The compose stack runs three services:

| Service | Purpose |
|---|---|
| `postgres` | Postgres 17. Bound to `127.0.0.1:55432` on the host |
| `mockvllm` | A fake vLLM server serving `mock-llama` and `mock-embed`, so you can try LemonGate without GPUs |
| `lemongate` | The gateway and console on port `4000`, configured by `deploy/lemongate.compose.yaml` |

Send a request:

```bash
curl http://localhost:4000/v1/chat/completions \
  -H "Authorization: Bearer $LEMONGATE_MASTER_KEY" \
  -H "Content-Type: application/json" \
  -d '{"model": "llama-3.1-8b", "messages": [{"role": "user", "content": "Hello"}]}'
```

To use real models, edit `deploy/lemongate.compose.yaml` to point `api_base` at your vLLM
servers, or add deployments in the console under **Models**. Then create a virtual key under
**Keys** and give it to your application instead of the master key.

---

## Kubernetes (Helm)

A Helm chart lives in [`deploy/helm/lemongate`](deploy/helm/lemongate). It runs hardened
by default (non-root, read-only root filesystem, no capabilities). It supports an external
database or a bundled single-instance Postgres, ingress, a ServiceMonitor and a
NetworkPolicy.

```bash
kubectl create namespace lemongate
kubectl -n lemongate create secret generic lemongate-secrets \
  --from-literal=master-key="$(openssl rand -hex 24)" \
  --from-literal=secret-key="$(openssl rand -hex 32)"

helm install lemongate deploy/helm/lemongate -n lemongate \
  --set image.repository=ghcr.io/<you>/lemongate \
  --set secrets.existingSecret=lemongate-secrets \
  --set postgresql.enabled=true \
  --set postgresql.auth.password="$(openssl rand -hex 16)"
```

See the [chart README](deploy/helm/lemongate/README.md) for production values, secrets and
every option.

---

## Calling the gateway

Any OpenAI SDK works. Set the base URL to `http://<host>:4000/v1` and use a LemonGate key as
the API key.

```python
from openai import OpenAI

client = OpenAI(base_url="http://localhost:4000/v1", api_key="lg-...")

resp = client.chat.completions.create(
    model="llama-3.1-8b",
    messages=[{"role": "user", "content": "Write a haiku about lemons"}],
    stream=True,
)
for chunk in resp:
    print(chunk.choices[0].delta.content or "", end="")
```

```ts
import OpenAI from "openai";

const client = new OpenAI({ baseURL: "http://localhost:4000/v1", apiKey: "lg-..." });
const emb = await client.embeddings.create({ model: "bge-m3", input: "hello" });
```

Routes are also served without the `/v1` prefix (`/chat/completions`, `/embeddings`, …) for
clients that expect a bare base URL.

### Endpoints

| Method | Path | Notes |
|---|---|---|
| `GET` | `/v1/models`, `/v1/models/{model}` | Lists model groups and aliases the key can access |
| `POST` | `/v1/chat/completions` | Streaming supported |
| `POST` | `/v1/completions` | Streaming supported |
| `POST` | `/v1/responses` | Streaming supported |
| `POST` | `/v1/embeddings` | |
| `POST` | `/v1/rerank`, `/v1/score` | |
| `POST` | `/v1/audio/transcriptions`, `/v1/audio/translations` | Multipart upload |
| `POST` | `/tokenize`, `/detokenize` | Forwarded to vLLM. Not billed or logged |

When a streaming request doesn't ask for usage, LemonGate adds
`stream_options.include_usage` itself, so streamed tokens are still metered and billed.

### Request extensions

LemonGate reads these optional fields and removes them before the request reaches vLLM:

| Field / header | Effect |
|---|---|
| `"user": "customer-42"` | Attributes the call to an end user, who can have their own budget. The user is created on first use |
| `"tags": ["billing"]` or `x-lemongate-tags: billing,prod` | Adds spend tags, which can have budgets. The key's own tags are always added |
| `"metadata": {...}` | Stored with the request log. `metadata.tags` is also read as tags |
| `"guardrails": ["policy-name"]` | Runs extra guardrail policies for this request |
| `Cache-Control: no-cache` | Skips cache lookup |
| `Cache-Control: no-store` | Doesn't store the response in the cache |
| `x-lemongate-cache-ttl: 60` | Per-request cache TTL in seconds, capped at 24 hours |

### Response headers

| Header | Meaning |
|---|---|
| `x-lemongate-request-id` | ID of the request log entry |
| `x-lemongate-model` | Model group that served the request after aliases and fallbacks |
| `x-lemongate-deployment` | Deployment (replica) that served it |
| `x-lemongate-cost` | Cost of the call in USD |
| `x-lemongate-cache` | `hit` or `miss` when caching applies |
| `x-ratelimit-remaining-requests`, `x-ratelimit-remaining-tokens` | Remaining capacity under the tightest applicable limit |
| `Retry-After` | Sent with `429` rate-limit responses |

Errors use the OpenAI error shape (`{"error": {"message", "type", "code"}}`). Budget
exhaustion and rate limits return `429` with type `budget_exceeded` or `rate_limit_exceeded`.

---

## Configuration

LemonGate is configured in three layers:

1. **Environment variables**: process-level settings such as the database, master key and
   SSO.
2. **An optional YAML file** (`LEMONGATE_CONFIG`): models, aliases, fallbacks and access
   groups declared as code, plus overrides for runtime settings.
3. **Runtime settings** edited in the console under **Settings** and stored in Postgres.

### Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `DATABASE_URL` | (required) | Postgres connection string (Postgres 14+) |
| `LEMONGATE_MASTER_KEY` | (required) | Bootstrap admin credential for the gateway, API and console. Must be at least 16 characters, and placeholders such as `change-me` are rejected (unless `LEMONGATE_DEV=1`). Changing it signs out sessions opened with the old key |
| `LEMONGATE_SECRET_KEY` | master key | Encrypts stored secrets (AES-GCM). Same strength rules. Set it separately so the master key can be rotated. **Keep it stable:** changing it makes stored credentials unreadable |
| `LEMONGATE_LISTEN` | `:4000` | Listen address |
| `LEMONGATE_BASE_URL` | `http://localhost:4000` | Public URL, used for links, cookies and SSO redirects |
| `LEMONGATE_CONFIG` | none | Path to a YAML config file |
| `LEMONGATE_SESSION_HOURS` | `12` | Console session lifetime |
| `LEMONGATE_METRICS_TOKEN` | none | Static bearer token for `/metrics`. Setting it forces scrape auth |
| `LEMONGATE_DEBUG` | none | Set to `1` for debug logging |
| `LEMONGATE_DEV` | none | Set to `1` to read templates and static files from disk and allow weak keys (development only) |

OIDC single sign-on:

| Variable | Default | Purpose |
|---|---|---|
| `LEMONGATE_OIDC_ISSUER` | none | Issuer URL. SSO is enabled when issuer and client ID are set |
| `LEMONGATE_OIDC_CLIENT_ID` / `_CLIENT_SECRET` | none | OAuth client credentials |
| `LEMONGATE_OIDC_SCOPES` | `openid,email,profile` | Comma-separated scopes |
| `LEMONGATE_OIDC_ROLE_CLAIM` | `groups` | Claim used for role mapping |
| `LEMONGATE_OIDC_ADMIN_VALUES` | none | Claim values that grant the admin role (comma-separated) |
| `LEMONGATE_OIDC_DEFAULT_ROLE` | `member` | Role for auto-provisioned users |
| `LEMONGATE_OIDC_DEFAULT_TEAM` | none | Team that new users join automatically |
| `LEMONGATE_OIDC_BUTTON_LABEL` | `Continue with SSO` | Login button text |
| `LEMONGATE_OIDC_TRUST_EMAIL` | none | Set to `1` to link existing accounts by email even when the provider doesn't assert `email_verified` |

Email (for the email alert channel):

| Variable | Default | Purpose |
|---|---|---|
| `LEMONGATE_SMTP_HOST` | none | SMTP server. Email is enabled when host and from are set |
| `LEMONGATE_SMTP_PORT` | `587` | |
| `LEMONGATE_SMTP_USERNAME` / `_PASSWORD` | none | |
| `LEMONGATE_SMTP_FROM` | none | Sender address |
| `LEMONGATE_SMTP_STARTTLS` | `1` | Set to `0` to disable STARTTLS |

### YAML config file

Models declared in YAML are read-only in the console. Models added in the console are stored
in Postgres. Both kinds are merged into the same model groups. `${VAR}` and
`${VAR:-default}` are expanded from the environment, so secrets don't need to live in the
file. See [`lemongate.example.yaml`](lemongate.example.yaml).

```yaml
models:
  - name: llama-3.1-8b                  # public model name clients request
    api_base: http://vllm-1:8000/v1     # vLLM OpenAI-compatible base URL
    upstream_model: meta-llama/Llama-3.1-8B-Instruct   # vLLM --served-model-name
    api_key: ${VLLM_API_KEY:-}          # if vLLM was started with --api-key
    context_window: 131072
    input_cost_per_m: 0.10              # USD per 1M prompt tokens
    output_cost_per_m: 0.20             # USD per 1M completion tokens
    tags: [chat, general]
  - name: llama-3.1-8b                  # same name = second replica in the same group
    api_base: http://vllm-2:8000/v1
    upstream_model: meta-llama/Llama-3.1-8B-Instruct
    weight: 2
  - name: bge-m3
    api_base: http://vllm-embed:8000/v1
    upstream_model: BAAI/bge-m3
    mode: embedding
    input_cost_per_m: 0.01

aliases:
  default: llama-3.1-8b

fallbacks:                    # on errors, try these groups in order
  llama-3.1-70b: [llama-3.1-8b]

context_fallbacks:            # on context-window overflow
  llama-3.1-8b: [llama-3.1-8b-128k]

access_groups:                # named sets of models to grant to keys and teams
  starter: [llama-3.1-8b]

settings:                     # overrides for runtime settings (win over the console, not persisted)
  routing:
    strategy: least_busy
    num_retries: 2
```

Model fields:

| Field | Purpose |
|---|---|
| `name` | Public model name. Replicas with the same name form one group (required) |
| `api_base` | vLLM base URL, usually ending in `/v1` (required) |
| `upstream_model` | Model ID on the vLLM server. Defaults to `name` |
| `api_key` | Bearer token for the vLLM server |
| `mode` | `chat` (default), `completion`, `embedding`, `rerank` or `audio` |
| `weight` | Relative weight for the weighted strategy |
| `rpm_limit`, `tpm_limit`, `max_parallel` | Per-deployment limits |
| `timeout_seconds` | Upstream timeout |
| `context_window`, `max_output_tokens` | Used for context-window fallbacks and shown in the hub |
| `input_cost_per_m`, `output_cost_per_m` | USD per 1M tokens, used for spend tracking and chargeback |
| `description`, `tags` | Shown in the model hub |
| `extra_headers` | Headers added to every upstream request |

### Runtime settings

These are edited under **Settings** in the console. The YAML `settings:` block can override
them.

| Section | Setting | Default |
|---|---|---|
| `routing` | `strategy` (`weighted` · `least_busy` · `latency` · `usage`) | `weighted` |
| | `num_retries` / `retry_backoff_ms` | `2` / `250` |
| | `default_timeout_sec` | `600` |
| | `cooldown_failures` (per minute) / `cooldown_seconds` | `3` / `30` |
| | `health_check_sec` (`0` disables probes) | `60` |
| | `latency_ewma_alpha` | `0.3` |
| `logging` | `store_payloads` | `false` |
| | `redact_payloads` (PII masking of stored payloads) | `true` |
| | `retention_days` / `max_payload_bytes` | `30` / `65536` |
| `cache` | `enabled` / `ttl_seconds` / `max_entries` / `per_key` | `false` / `600` / `5000` / `true` |
| `general` | `default_key_budget`, `default_key_duration` (e.g. `30d`) | unset |
| | `allow_member_keys` / `track_end_users` | `true` / `true` |
| | `max_request_bytes` | 32 MiB |
| `alerting` | `budget_thresholds` (%) | `[50, 80, 100]` |
| | `error_rate_percent` / `slow_response_sec` | `25` / `60` |
| | `dedupe_minutes` / `key_expiry_days` | `60` / `7` |
| | `daily_report` / `daily_report_hour_utc` | `false` / `8` |
| `metrics` | `enabled` / `require_auth` / `entity_metrics` | `true` / `false` / `false` |
| `branding` | `app_name` / `logo_url` / `tagline` | `LemonGate` |

---

## Models, routing and reliability

- **Model groups.** Every deployment (a vLLM endpoint plus an upstream model ID) has a public
  `name`. Deployments that share a name form a group, and LemonGate balances requests across
  it.
- **Strategies.** `weighted` uses random selection by `weight`. `least_busy` picks the fewest
  in-flight requests. `latency` picks the lowest EWMA response time. `usage` picks the lowest
  recent token usage.
- **Retries and cooldowns.** Failed attempts are retried on other replicas with backoff. A
  deployment that fails `cooldown_failures` times within a minute is taken out of rotation for
  `cooldown_seconds`.
- **Health probes.** Deployments are probed in the background. Their state appears on the
  Models page and in metrics, and changes can trigger alerts.
- **Fallbacks.** General fallbacks apply when a whole group fails. Context fallbacks apply
  when a prompt exceeds the group's context window.
- **Aliases** map extra names onto a group (for example `default` → `llama-3.1-8b`).
- **Access groups** are named sets of models you can grant to keys and teams instead of
  listing models one by one.
- **Credentials** store upstream secrets encrypted at rest. Deployments, pass-through routes
  and MCP servers reference them by name, and the secrets are never shown again.

---

## Access control, budgets and limits

### Principals and roles

| Role | Can do |
|---|---|
| `admin` | Everything |
| `admin_viewer` | Read everything, change nothing |
| `member` | Manage their own keys, and their teams' keys if they are a team admin. Sees only their own and their teams' data |
| `member_viewer` | Read-only member |

Team membership adds `team_admin` or `team_member` within a team. The master key acts as an
admin. Console users sign in with a password, an invite link or SSO.

### Hierarchy

```
Organization ─► Team ─► User ─► Key
                     └────────► Key (team-owned)
End users (request "user" field) and tags are tracked alongside.
```

Each level can have a **budget** (USD, with a `daily`, `weekly` or `monthly` period, or for
the lifetime) and **rate limits** (`rpm`, `tpm` and parallel requests). A request must fit
within every applicable budget and limit: key, user, team, org, end user and each tag.
Budgets reset automatically at the end of each period. **Budget presets** let you apply a
standard budget-and-limit package in one click.

### Virtual keys

Keys look like `lg-…` and are stored only as hashes. The plaintext is shown once when a key
is created or regenerated. A key can have:

- an allow-list of models or access groups
- a budget and period, rpm/tpm/parallel limits, and an expiry (e.g. `90d`)
- tags, guardrail policies and MCP server grants
- an owner user or team

Keys can be blocked, unblocked, regenerated or soft-deleted, and every change is recorded in
the audit log.

A few key actions are restricted:

- Only admins can grant MCP servers on a key, or create management and admin keys.
- Team admins manage their team's inference keys, but not management or admin keys
  attached to the team.
- Owners can block their own keys, but only an admin (or a team admin, for team keys) can
  lift a block.
- Deleting a user also deletes their keys. Deleting a team disables its keys until the team
  is restored.

---

## Guardrails

Guardrails inspect requests (**pre-call**), responses (**post-call**) or both. Each one
**blocks**, **masks** or only **logs** what it finds.

| Kind | What it does |
|---|---|
| `pii` | Detects PII and secrets, with regional packs (US, EU/GDPR, UK, Canada, Australia, financial, health, secrets) and checksum validation for IDs and card numbers |
| `blocklist` | Keyword lists and content categories (profanity, NSFW, harmful content) |
| `regex` | Custom patterns |
| `max_length` | Rejects oversized inputs |
| `prompt_injection` | Heuristics for jailbreaks and instruction overrides |
| `code_execution` | Detects dangerous shell, SQL and code payloads |
| `tool_policy` | Allow and deny lists for tool and function calls |
| `semantic` | Embedding similarity to known attacks, using one of your embedding models |
| `guard_model` | Self-hosted guard models on vLLM: Llama Guard, Granite Guardian, Qwen3Guard, ShieldGemma, Prompt Guard |
| `llm_judge` | Any of your chat models evaluating a custom policy |

**Presets and policies.** The gallery under **Guardrails → Presets** installs ready-made
bundles: PII by region, content safety, prompt-injection defense and compliance (HIPAA-style
health data, PCI card data, EU AI Act prohibited practices, financial services, competitor
mentions, strict customer-facing). Installed bundles become **policies**, which are named
groups of guardrails that apply:

- to every call, if the policy is on by default
- to the keys and teams that attach it
- to a single request via `"guardrails": ["<policy>"]` in the body

The console includes a **test bench** for trying text against your guardrails and an
**event log** of every action they take. Blocked requests return `400` with type
`guardrail_violation` and code `content_blocked`.

> **Streaming and output guardrails.** A streamed response reaches the client as it is
> generated, so post-call guardrails on streamed responses can only **log**. They can't
> block or mask. If output masking is mandatory, have those clients call without
> `stream: true`.

---

## Response cache

Enable the cache under **Settings → Cache**. It is an in-memory, exact-match cache keyed on
the normalized request, scoped per key by default, with a TTL and a maximum entry count.
Streaming requests are not cached. Cache hits cost `0` and return `x-lemongate-cache: hit`.
Clients can opt out with `Cache-Control: no-cache` or `no-store`, or set a shorter TTL with
`x-lemongate-cache-ttl`. The **Cache** page shows hit rates and can flush the cache.

---

## Pass-through routes

Pass-through routes expose any HTTP upstream at `/pt/<name>/*`. A route can:

- inject an upstream credential (header name and prefix, e.g. `Authorization: Bearer …`)
- add extra headers
- require a LemonGate key, which enforces that key's budgets and rate limits
- charge a fixed `cost_per_request`

Calls appear in usage and request logs like any other traffic. Hop-by-hop headers and the
caller's credentials are stripped before forwarding.

---

## MCP gateway

LemonGate aggregates upstream [Model Context Protocol](https://modelcontextprotocol.io)
servers (Streamable HTTP or SSE transport) behind a single endpoint, `/mcp`. Tools are
exposed as `<server>__<tool>`. Each MCP client sees only the servers its key or team was
granted, or servers marked available to all. Upstream credentials are injected server side,
and every tool call is logged.

Example client configuration:

```json
{
  "mcpServers": {
    "lemongate": {
      "type": "http",
      "url": "http://localhost:4000/mcp",
      "headers": { "Authorization": "Bearer lg-..." }
    }
  }
}
```

---

## Alerting

Configure channels under **Alerts**: Slack, Mattermost, email (SMTP) or a generic webhook.
Alert types:

- budget thresholds (default 50/80/100%) for keys, users, teams, orgs, end users and tags
- deployment down and recovered
- error-rate spikes and slow responses
- keys about to expire
- an optional daily spend report

Repeated alerts are deduplicated within a configurable window. Every delivery is recorded,
and channels can be test-sent from the console.

**Webhook signing.** When a channel has a signing secret, each request carries
`X-LemonGate-Timestamp` (unix seconds) and `X-LemonGate-Signature: sha256=<hex>`, where
`hex = HMAC-SHA256(secret, timestamp + "." + body)`. Verify it and reject stale timestamps.

---

## Single sign-on (OIDC)

Set `LEMONGATE_OIDC_ISSUER`, `LEMONGATE_OIDC_CLIENT_ID` and `LEMONGATE_OIDC_CLIENT_SECRET`,
and register this redirect URI with your identity provider:

```
<LEMONGATE_BASE_URL>/ui/sso/callback
```

Users are provisioned on first login with `LEMONGATE_OIDC_DEFAULT_ROLE`. If the
`LEMONGATE_OIDC_ROLE_CLAIM` claim contains a value listed in `LEMONGATE_OIDC_ADMIN_VALUES`,
the user becomes an admin.

An existing account is linked to an SSO identity by email only when the provider asserts
`email_verified`. If your directory omits that claim but doesn't let users change their
email, set `LEMONGATE_OIDC_TRUST_EMAIL=1`. Accounts that sign in with SSO can't set a local
password.

---

## Admin API

Everything in the console is also available as JSON under `/api/v1`. Authenticate with the
master key or a virtual key. The key owner's role decides access, so members can manage their
own keys through the API.

- **Reference:** `GET /api/docs` (HTML, with examples)
- **OpenAPI 3.1:** `GET /api/openapi.json`

Sections: Me, Keys, Users, Teams, Organizations, Models (deployments, aliases, access groups,
fallbacks), Credentials, Budgets (tags, end users, presets), Extensions (guardrails, policies,
presets, MCP servers, pass-through routes), Alerts, Settings and Observability (usage, logs,
health, audit).

```bash
# Create a key with a monthly budget that expires in 90 days
curl -X POST http://localhost:4000/api/v1/keys \
  -H "Authorization: Bearer $LEMONGATE_MASTER_KEY" \
  -H "Content-Type: application/json" \
  -d '{"alias": "support-bot", "models": ["llama-3.1-8b"], "max_budget": 25,
       "budget_period": "monthly", "expires_in": "90d"}'

# Add a vLLM replica to a model group
curl -X POST http://localhost:4000/api/v1/deployments \
  -H "Authorization: Bearer $LEMONGATE_MASTER_KEY" \
  -H "Content-Type: application/json" \
  -d '{"name": "llama-3.1-8b", "api_base": "http://vllm-3:8000/v1",
       "upstream_model": "meta-llama/Llama-3.1-8B-Instruct",
       "input_cost_per_m": 0.1, "output_cost_per_m": 0.2}'
```

---

## Observability

### Health

- `GET /health/live`: the process is up
- `GET /health/ready`: the database is reachable (returns `503` otherwise)

### Prometheus metrics

`GET /metrics` exposes, among others:

| Metric | Description |
|---|---|
| `lemongate_requests_total` | Requests by route, model and status |
| `lemongate_request_duration_seconds` | End-to-end latency histogram |
| `lemongate_time_to_first_token_seconds` | TTFT for streamed responses |
| `lemongate_tokens_total`, `lemongate_cost_usd_total` | Tokens and spend per model |
| `lemongate_upstream_requests_total`, `lemongate_upstream_response_seconds` | Per-deployment attempts and response time |
| `lemongate_deployment_healthy`, `_inflight`, `_cooling_down`, `_latency_ewma_seconds` | Live deployment state |
| `lemongate_retries_total`, `lemongate_fallbacks_total` | Reliability events |
| `lemongate_rate_limited_total`, `lemongate_budget_rejected_total` | Rejections |
| `lemongate_cache_lookups_total`, `_entries`, `_bytes` | Cache effectiveness |
| `lemongate_guardrail_actions_total`, `lemongate_mcp_tool_calls_total`, `lemongate_alerts_sent_total` | Extensions |
| `lemongate_spend_log_queue_depth`, `lemongate_spend_log_dropped_total` | Log pipeline health |
| `lemongate_{key,team,user,org}_{spend,budget}_usd` | Per-entity spend and budget gauges (opt-in via `entity_metrics`) |

To require auth on `/metrics`, set `LEMONGATE_METRICS_TOKEN` or generate a token under
**Settings → Metrics**, then scrape with `Authorization: Bearer <token>`. You can download a
ready-made Grafana dashboard from the same page.

### Usage, logs and audit

- **Usage:** spend, tokens and requests over time, broken down by model, key, team, user, org,
  end user and tag, with CSV export.
- **Logs:** every request with its status, latency, tokens, cost, deployment and tags, plus a
  live tail. Request and response payloads are stored only if you enable
  `logging.store_payloads`. PII is redacted from stored payloads by default, and logs are
  purged after `retention_days`.
- **Audit log:** every administrative change, with before and after snapshots.

---

## Admin console

Sign in at `/ui` with the master key, a user account, an invite link or SSO.

| Area | What's there |
|---|---|
| Dashboard | Traffic, spend, latency and error overview, plus deployment health |
| Playground | Chat with any model the user can access, through the real gateway path |
| Model hub | Browsable catalog of model groups, with context windows, prices and tags |
| Models | Deployments, routing, aliases, access groups, fallbacks and health |
| Keys | Create, scope, limit, block, regenerate and delete keys |
| Usage / Logs | Analytics with CSV export, and request logs with live tail |
| Teams / Organizations / Users / End users | Hierarchy, membership, invites, budgets and limits |
| Budgets / Tags | Budget presets and tag budgets |
| Guardrails | Presets gallery, policies, guardrails, test bench and events |
| MCP / Pass-through / Cache | Extension management |
| Alerts / Credentials / Settings / Audit | Operations |

---

## CLI

```
lemongate serve     # run the server (default)
lemongate migrate   # apply database migrations and exit
lemongate new-key   # print a new random key and its hash
lemongate version   # print the build version
```

Migrations are embedded in the binary and also run automatically on `serve`.

---

## Running in production

- **Use strong, stable secrets.** Generate `LEMONGATE_MASTER_KEY` and `LEMONGATE_SECRET_KEY`
  randomly and store them in your secret manager. Use the master key only for bootstrap and
  automation. Give people accounts and applications virtual keys.
- **Terminate TLS** in front of LemonGate and set `LEMONGATE_BASE_URL` to the public HTTPS
  URL, because it is used for cookies and SSO redirects.
- **Run a single replica.** Rate-limit counters, the response cache and deployment cooldowns
  are held in memory. With several replicas, each one enforces limits on its own. Spend,
  budgets and everything else live in Postgres.
- **Back up Postgres.** It holds keys, spend history, logs, settings and the audit log.
- **Payload logging is off by default.** Turn it on deliberately, and keep redaction enabled
  if prompts may contain personal data.
- **Restrict `/metrics`** with a scrape token if it is reachable from untrusted networks.
- **Browser hardening is built in.** Every response carries `X-Frame-Options: DENY`, a
  `frame-ancestors 'none'` CSP, `nosniff` and `Referrer-Policy`, plus HSTS when the base URL
  is https. Pass-through responses are sandboxed and can't set cookies. Console sign-in is
  rate-limited per IP and per account, in memory on each replica.
- **Client IPs** come from `X-Forwarded-For` / `X-Real-IP`. Put LemonGate behind a proxy
  that overwrites these headers, so logged and rate-limited IPs can't be spoofed.
- The container image is `distroless/static` and runs as non-root on port `4000`. Build it
  with `docker build --build-arg VERSION=$(git describe --tags --always) -t lemongate .`

---

## Development

Requirements: Go 1.27+, Node 22+ (for building console assets), Postgres 14+, and Chromium
for the browser smoke test.

```bash
docker compose up -d postgres            # or any Postgres 14+
make assets mock                         # build CSS/JS/icons and the mock servers
cp .env.example .env.dev && source .env.dev
make dev                                 # build and (re)start on :4000 (logs in tmp/)
```

| Command | What it does |
|---|---|
| `make build` | Build assets and a static `bin/lemongate` |
| `make test` | Unit tests |
| `TEST_DATABASE_URL=postgres://… make test-integration` | Integration tests against a disposable database |
| `make e2e` | Headless-browser smoke test in an isolated throwaway database and server |
| `make vet` | `go vet` |
| `make lint-brand` | Repository naming check |
| `make up` / `make down` | Start or stop the full Docker stack |

Console assets (`web/static/dist`) are generated rather than committed, so run `make assets`
before a plain `go build`. With `LEMONGATE_DEV=1`, templates are read from disk, so template
edits only need a browser refresh.

The repository includes two mock servers for local work and tests:

- `cmd/mockvllm` is a fake vLLM server with flags for latency, failure rate, context window
  and API key. Model IDs that contain `llama-guard`, `granite-guardian`, `qwen3guard`,
  `shieldgemma` or `prompt-guard` behave as guard models.
- `cmd/mockmcp` is a fake MCP server with the tools `lemon_facts`, `add_numbers`, `echo` and
  `always_fail`.

### Project layout

```
cmd/lemongate        server binary
cmd/mockvllm         fake vLLM server
cmd/mockmcp          fake MCP server
internal/app         wiring and HTTP router
internal/gateway     /v1 data plane
internal/routing     model groups, deployment selection, cooldowns, health probes
internal/auth        key hashing, principals, roles, sessions
internal/limits      in-process rpm/tpm/parallel limiter
internal/spend       async request-log and spend writer, budget resets
internal/guardrails  guardrail engine, presets, policies, guard model families
internal/cache       response cache
internal/passthrough pass-through routes
internal/mcpgw       MCP gateway
internal/alerting    alert channels and watchers
internal/metrics     Prometheus collectors and Grafana dashboard
internal/api         JSON admin API and OpenAPI generation
internal/ui/...      console, one package per area
internal/db          pgx pool and embedded goose migrations
web/                 templates, static assets, Tailwind/daisyUI build
e2e/                 headless-browser smoke test
```

The console is server-rendered with HTMX, Alpine.js, Tailwind CSS v4 and daisyUI 5. See
[docs/DEVELOPING.md](docs/DEVELOPING.md) for conventions, the template system, interaction
patterns and how to add console areas and guardrail kinds.
