# Developing LemonGate

LemonGate is a single Go binary: an OpenAI-compatible gateway for self-hosted vLLM servers
plus a server-rendered admin console (HTMX + Alpine.js + Tailwind CSS v4 + daisyUI 5).
Postgres is the only dependency.

## Layout

```
cmd/lemongate          server binary (serve | migrate | new-key | version)
cmd/mockvllm           fake vLLM server for local dev and tests
cmd/mockmcp            fake upstream MCP server (tools: lemon_facts, add_numbers, echo, always_fail)
internal/app           wiring: builds every component and the HTTP router
internal/config        env + YAML config
internal/db            pgx pool + goose migrations (internal/db/migrations/*.sql, embedded)
internal/store         typed CRUD for core entities (keys, users, teams, orgs, deployments, ...)
internal/settings      runtime settings persisted in the `settings` table (Current(), Update())
internal/secret        AES-GCM box for secrets at rest (credentials, webhook URLs)
internal/auth          key hashing, Principal, roles, model access, sessions
internal/hooks         extension interfaces the gateway calls (Guardrails, Cache, Alerter)
internal/routing       model groups, deployment selection, cooldowns, health prober
internal/limits        in-process rpm/tpm/parallel limiter
internal/spend         async batched writer: request_logs, daily rollups, spend counters
internal/analytics     usage queries over daily_spend + ChartSpec helpers
internal/gateway       /v1/* data plane
internal/metrics       Prometheus collectors
internal/guardrails, cache, passthrough, mcpgw, alerting, api   optional modules
internal/ui            console framework (renderer, layout data, middleware, form helpers)
internal/ui/<area>     one package per console area; each exposes Mount(r chi.Router, d *ui.Deps, ...)
web/                   templates, static assets, Tailwind input, npm build
```

## Running locally

```bash
docker compose up -d postgres            # or any Postgres 14+
(cd web && npm install && npm run build) # CSS, vendored JS, icons
source .env.dev                          # DATABASE_URL, LEMONGATE_MASTER_KEY, LEMONGATE_CONFIG, LEMONGATE_DEV=1
scripts/dev-restart.sh 4000              # builds + (re)starts on :4000, logs in tmp/lemongate-4000.log
```

With `LEMONGATE_DEV=1` templates and static files are read from disk, so template edits
need only a browser refresh. **Icons and CSS classes are discovered at build time**: after
adding a new `{{icon "name"}}` or new Tailwind classes, run `cd web && npm run build`.
Icons are found from `{{icon "x"}}`, `"Icon" "x"` (dict args), `data-icon="x"` and `Icon("x")`/`icon("x")`
calls in Go. An icon name chosen at runtime from a Go string must appear in one of those forms
(e.g. wrap the literal: `ui.IconName("x")` is not scanned, but `icon("x")` in nav.go style is).

Sign in at `/ui/login` with the master key.

## Browser smoke test

`make e2e` runs `scripts/e2e.sh`: it creates a throwaway database (`lemongate_e2e`), starts a
mock vLLM and a LemonGate server on :4999, drives headless Chromium through the console
(login form, every page as admin and as an invited member, every modal and create form,
the playground, mobile layouts), then stops everything and drops the database. It never
touches your dev or production data. Set `CHROME` if Chromium isn't at `/usr/bin/chromium`.

## Console conventions

### Areas, pages and partials

- Templates live in `web/templates/pages/<area>/`.
- A **page** file (`index.html`, `show.html`, …) defines exactly one `{{define "content"}}`.
  Render it with `d.Render(w, r, "<area>/<page>", "<navKey>", "<Title>", data, crumbs...)`.
- **Partials** (HTMX fragments, modal forms) go in files named `_*.html` in the same folder.
  They are available to every page of the area and are rendered alone with
  `d.Partial(w, r, status, "<area>", "<templateName>", data)`.
- Inside templates, data is wrapped in `ui.Page`: use `.Data` for your struct, `.P` for the
  principal (`.P.IsAdmin`, `.P.CanViewAll`, `.P.ReadOnly`), `.CSRF`.
  Inside `{{with .Data}}` remember `$` is the Page (`$.P`, `$.Data`).
- Shared components (see `templates/components/components.html`): `page-header`, `stat`,
  `empty`, `budget`, `health-dot`, `chips`, `modal-head`, `modal-actions`, `form-error`,
  `limit-fields`, `model-picker`, `copy-field`, `role-badge`.
- Template funcs (see `internal/ui/funcs.go`): `icon`, `money`, `num`, `compact`, `ago`, `dt`,
  `inputDate`, `val`, `has`, `dict`, `list`, `json`, `pretty`, `truncate`, `pct`, `pctClass`,
  `initials`, `statusClass`, `roleLabel`, `joinc`, `deref`, `derefF`, `derefI`, `isNil`, `divf`, `mulf`, `seq`, `title`.

### Interaction patterns (copy `internal/ui/keys` — it is the reference area)

- Page header: wrap `{{template "page-header" dict "Title" … "Sub" … "Icon" …}}` together with
  action buttons in `<div class="mb-6 flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">`.
- Lists load as a partial: `<div hx-get="/ui/x/table" hx-trigger="load, refresh-x from:body">` with
  a skeleton placeholder. Filters are a form with `hx-get` + `hx-target`.
- Create/edit opens in the global modal: `hx-get="/ui/x/new" hx-target="#modal-body"`.
  Form posts back with `hx-post` + `hx-target="#modal-body"`.
  - Validation error → re-render the form partial with status **422** and `.Error` set.
  - Success → `ui.Done(w, "Saved", "refresh-x")` (toast + close modal + fire refresh event, 204).
- Row actions: `hx-post` with `hx-confirm="…"` (rendered as a styled dialog).
- A wrapper that refreshes itself (`hx-get` + `hx-trigger` with its own `hx-target`/`hx-swap`/`hx-select`)
  must also set `hx-disinherit="*"`; otherwise buttons inside it (e.g. Edit → `#modal-body`) inherit
  the wrapper's swap settings and replace the modal container instead of filling it.
- Values inside Alpine attributes (`x-data`, `x-show`, `:class`, `@click`) must be JSON-encoded with
  `{{json .X}}` — html/template only HTML-escapes those attributes, so `'{{.X}}'` is injectable.
- Errors without swapping: `ui.Fail(w, status, msg)`. Toasts: `ui.Toast(w, kind, msg)`.
- After mutating keys/users/teams/orgs/tags/end users call `d.Changed()` (invalidates auth +
  budget caches). After mutating deployments/aliases/access groups/fallbacks/credentials call
  `d.ReloadModels(ctx)`. Record every mutation with `d.Audit(r, action, entityType, id, summary, before, after)`.
- Permissions: wrap admin-only areas with `r.With(ui.AdminWrites)` (viewers read, admins write) or
  `ui.RequireAdmin`. Members see only their own / their teams' data.
- Charts: `<div class="h-64"><canvas data-chart="{{json .Chart}}"></canvas></div>` with an
  `analytics.ChartSpec` (types: line, bar, doughnut; format: money, num, ms, pct). Charts
  re-theme automatically.
- Cards: `glass-card` (+ `card-hover`), tables: wrap in `<div class="table-lg-wrap"><table>`.
- Use daisyUI 5 components (`btn`, `badge`, `input`, `select`, `fieldset`, `tabs tabs-box`,
  `dropdown`, `join`, `progress`, `alert alert-soft`, `toggle`, `skeleton`, `loading`).
  Inputs: `<label class="input w-full">{{icon "x" "opacity-50"}}<input …></label>`.
  Form fields: `<fieldset class="fieldset"><legend class="fieldset-legend">Label</legend>…</fieldset>`.

### Guardrails area

- Engine: `internal/guardrails` (kinds, presets in `presets.go`, policies in `policies.go`,
  guard model families in `guardmodel*.go`). The console (`internal/ui/guardrailsui`) and the
  API (`internal/api/guardrails.go`) only call the `*guardrails.Engine`; the API gets it through
  `api.SetHooks(api.Hooks{Guardrails: eng, ...})`.
- Tabs of `/ui/guardrails`: `presets` (default), `policies`, `list`, `bench`, `events`.
  Templates: `index.html`, `_partials.html` (table, bench, events), `_form.html` (guardrail form,
  one Alpine component; kind-specific fields use distinct input names), `_presets.html`,
  `_policies.html`.
- After any change to presets, policies or guardrails fire all of `refresh-guardrails`,
  `refresh-policies` and `refresh-presets` (`refreshAll`) and call `d.Changed()` for policy changes.
- Preset and pack icons come from Go strings; list new ones in the `icon("…")` slice at the top
  of `guardrailsui/presets.go` so the asset build embeds them.
- New guardrail kinds: add them to `guardrailsui.Kinds` (label, icon, blurb, `ModelBacked`) and give
  their fields a section in `_form.html` plus a case in `bind` and `summary`.
- `make e2e` serves mock guard models (`e2e-llama-guard`, chat; `e2e-prompt-guard`, classify) and
  installs presets through the gallery; see `guardrailFlow` in `e2e/smoke.mjs`.

### Product rules

- Never reference any other gateway product or vendor by name anywhere (code, comments,
  templates, docs, commit messages). `make lint-brand` enforces this.
- Upstreams are vLLM OpenAI-compatible servers only; do not add cloud-provider adapters.
- Money is USD (float64); token prices are per 1M tokens.
- All schema changes are new goose migration files in `internal/db/migrations/`.
