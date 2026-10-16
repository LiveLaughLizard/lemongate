-- +goose Up
CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE settings (
    key        text PRIMARY KEY,
    value      jsonb NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE organizations (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name            text NOT NULL UNIQUE,
    description     text NOT NULL DEFAULT '',
    models          text[] NOT NULL DEFAULT '{}',
    max_budget      double precision,
    budget_period   text NOT NULL DEFAULT '',
    budget_reset_at timestamptz,
    spend           double precision NOT NULL DEFAULT 0,
    rpm_limit       integer,
    tpm_limit       integer,
    metadata        jsonb NOT NULL DEFAULT '{}',
    blocked         boolean NOT NULL DEFAULT false,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE budget_presets (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name          text NOT NULL UNIQUE,
    max_budget    double precision,
    budget_period text NOT NULL DEFAULT '',
    rpm_limit     integer,
    tpm_limit     integer,
    max_parallel  integer,
    created_at    timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE users (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    email           text NOT NULL UNIQUE,
    name            text NOT NULL DEFAULT '',
    role            text NOT NULL DEFAULT 'member',
    password_hash   text NOT NULL DEFAULT '',
    sso_subject     text UNIQUE,
    org_id          uuid REFERENCES organizations(id) ON DELETE SET NULL,
    models          text[] NOT NULL DEFAULT '{}',
    max_budget      double precision,
    budget_period   text NOT NULL DEFAULT '',
    budget_reset_at timestamptz,
    spend           double precision NOT NULL DEFAULT 0,
    rpm_limit       integer,
    tpm_limit       integer,
    max_parallel    integer,
    metadata        jsonb NOT NULL DEFAULT '{}',
    blocked         boolean NOT NULL DEFAULT false,
    last_login_at   timestamptz,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE teams (
    id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name              text NOT NULL,
    description       text NOT NULL DEFAULT '',
    org_id            uuid REFERENCES organizations(id) ON DELETE SET NULL,
    models            text[] NOT NULL DEFAULT '{}',
    max_budget        double precision,
    budget_period     text NOT NULL DEFAULT '',
    budget_reset_at   timestamptz,
    spend             double precision NOT NULL DEFAULT 0,
    member_max_budget double precision,
    rpm_limit         integer,
    tpm_limit         integer,
    max_parallel      integer,
    guardrails        text[] NOT NULL DEFAULT '{}',
    mcp_servers       text[] NOT NULL DEFAULT '{}',
    metadata          jsonb NOT NULL DEFAULT '{}',
    blocked           boolean NOT NULL DEFAULT false,
    created_at        timestamptz NOT NULL DEFAULT now(),
    updated_at        timestamptz NOT NULL DEFAULT now(),
    deleted_at        timestamptz
);

CREATE TABLE team_members (
    team_id    uuid NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    user_id    uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role       text NOT NULL DEFAULT 'team_member',
    spend      double precision NOT NULL DEFAULT 0,
    max_budget double precision,
    joined_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (team_id, user_id)
);

CREATE TABLE org_members (
    org_id    uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id   uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role      text NOT NULL DEFAULT 'org_member',
    joined_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, user_id)
);

CREATE TABLE credentials (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name        text NOT NULL UNIQUE,
    description text NOT NULL DEFAULT '',
    secret_enc  bytea NOT NULL,
    hint        text NOT NULL DEFAULT '',
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now()
);

-- One row per deployment. Rows sharing `name` form a model group.
CREATE TABLE deployments (
    id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name              text NOT NULL,
    api_base          text NOT NULL,
    upstream_model    text NOT NULL,
    credential_id     uuid REFERENCES credentials(id) ON DELETE SET NULL,
    mode              text NOT NULL DEFAULT 'chat',
    weight            integer NOT NULL DEFAULT 1,
    rpm_limit         integer,
    tpm_limit         integer,
    max_parallel      integer,
    timeout_seconds   integer NOT NULL DEFAULT 600,
    context_window    integer,
    max_output_tokens integer,
    input_cost_per_m  double precision NOT NULL DEFAULT 0,
    output_cost_per_m double precision NOT NULL DEFAULT 0,
    description       text NOT NULL DEFAULT '',
    tags              text[] NOT NULL DEFAULT '{}',
    extra_headers     jsonb NOT NULL DEFAULT '{}',
    enabled           boolean NOT NULL DEFAULT true,
    created_at        timestamptz NOT NULL DEFAULT now(),
    updated_at        timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX deployments_name_idx ON deployments(name);

CREATE TABLE model_aliases (
    alias      text PRIMARY KEY,
    target     text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE access_groups (
    name        text PRIMARY KEY,
    description text NOT NULL DEFAULT '',
    models      text[] NOT NULL DEFAULT '{}',
    created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE model_fallbacks (
    model   text NOT NULL,
    kind    text NOT NULL DEFAULT 'general', -- general | context
    targets text[] NOT NULL DEFAULT '{}',
    PRIMARY KEY (model, kind)
);

CREATE TABLE api_keys (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    key_hash        text NOT NULL UNIQUE,
    key_hint        text NOT NULL,
    alias           text NOT NULL DEFAULT '',
    scope           text NOT NULL DEFAULT 'inference', -- inference | management | admin
    user_id         uuid REFERENCES users(id) ON DELETE SET NULL,
    team_id         uuid REFERENCES teams(id) ON DELETE SET NULL,
    models          text[] NOT NULL DEFAULT '{}',
    access_groups   text[] NOT NULL DEFAULT '{}',
    max_budget      double precision,
    budget_period   text NOT NULL DEFAULT '',
    budget_reset_at timestamptz,
    spend           double precision NOT NULL DEFAULT 0,
    rpm_limit       integer,
    tpm_limit       integer,
    max_parallel    integer,
    expires_at      timestamptz,
    metadata        jsonb NOT NULL DEFAULT '{}',
    tags            text[] NOT NULL DEFAULT '{}',
    guardrails      text[] NOT NULL DEFAULT '{}',
    mcp_servers     text[] NOT NULL DEFAULT '{}',
    blocked         boolean NOT NULL DEFAULT false,
    last_used_at    timestamptz,
    created_by      text NOT NULL DEFAULT '',
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    deleted_at      timestamptz
);
CREATE INDEX api_keys_user_idx ON api_keys(user_id);
CREATE INDEX api_keys_team_idx ON api_keys(team_id);

CREATE TABLE end_users (
    id              text PRIMARY KEY,
    alias           text NOT NULL DEFAULT '',
    max_budget      double precision,
    budget_period   text NOT NULL DEFAULT '',
    budget_reset_at timestamptz,
    spend           double precision NOT NULL DEFAULT 0,
    blocked         boolean NOT NULL DEFAULT false,
    first_seen_at   timestamptz NOT NULL DEFAULT now(),
    last_seen_at    timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE tags (
    name            text PRIMARY KEY,
    description     text NOT NULL DEFAULT '',
    color           text NOT NULL DEFAULT '',
    max_budget      double precision,
    budget_period   text NOT NULL DEFAULT '',
    budget_reset_at timestamptz,
    spend           double precision NOT NULL DEFAULT 0,
    created_at      timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE request_logs (
    id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    request_id        text NOT NULL,
    created_at        timestamptz NOT NULL DEFAULT now(),
    route             text NOT NULL,
    model             text NOT NULL DEFAULT '',
    model_group       text NOT NULL DEFAULT '',
    deployment_id     uuid,
    api_base          text NOT NULL DEFAULT '',
    key_id            uuid,
    key_alias         text NOT NULL DEFAULT '',
    user_id           uuid,
    team_id           uuid,
    org_id            uuid,
    end_user          text NOT NULL DEFAULT '',
    tags              text[] NOT NULL DEFAULT '{}',
    status            text NOT NULL, -- success | error | blocked
    http_status       integer NOT NULL DEFAULT 200,
    prompt_tokens     integer NOT NULL DEFAULT 0,
    completion_tokens integer NOT NULL DEFAULT 0,
    total_tokens      integer NOT NULL DEFAULT 0,
    cost              double precision NOT NULL DEFAULT 0,
    latency_ms        integer NOT NULL DEFAULT 0,
    ttft_ms           integer,
    stream            boolean NOT NULL DEFAULT false,
    cache_hit         boolean NOT NULL DEFAULT false,
    attempts          integer NOT NULL DEFAULT 1,
    error             text NOT NULL DEFAULT '',
    request_body      jsonb,
    response_body     jsonb,
    metadata          jsonb NOT NULL DEFAULT '{}'
);
CREATE INDEX request_logs_created_idx ON request_logs(created_at DESC);
CREATE INDEX request_logs_key_idx ON request_logs(key_id, created_at DESC);
CREATE INDEX request_logs_team_idx ON request_logs(team_id, created_at DESC);
CREATE INDEX request_logs_user_idx ON request_logs(user_id, created_at DESC);
CREATE INDEX request_logs_model_idx ON request_logs(model_group, created_at DESC);
CREATE INDEX request_logs_reqid_idx ON request_logs(request_id);

-- Daily rollups. Empty string means "not attributed" so the composite key stays NOT NULL.
CREATE TABLE daily_spend (
    day               date NOT NULL,
    key_id            text NOT NULL DEFAULT '',
    user_id           text NOT NULL DEFAULT '',
    team_id           text NOT NULL DEFAULT '',
    org_id            text NOT NULL DEFAULT '',
    end_user          text NOT NULL DEFAULT '',
    model             text NOT NULL DEFAULT '',
    requests          bigint NOT NULL DEFAULT 0,
    failures          bigint NOT NULL DEFAULT 0,
    cache_hits        bigint NOT NULL DEFAULT 0,
    prompt_tokens     bigint NOT NULL DEFAULT 0,
    completion_tokens bigint NOT NULL DEFAULT 0,
    cost              double precision NOT NULL DEFAULT 0,
    latency_ms_sum    bigint NOT NULL DEFAULT 0,
    PRIMARY KEY (day, key_id, user_id, team_id, org_id, end_user, model)
);
CREATE INDEX daily_spend_team_idx ON daily_spend(team_id, day);
CREATE INDEX daily_spend_user_idx ON daily_spend(user_id, day);
CREATE INDEX daily_spend_key_idx ON daily_spend(key_id, day);

CREATE TABLE daily_tag_spend (
    day               date NOT NULL,
    tag               text NOT NULL,
    model             text NOT NULL DEFAULT '',
    requests          bigint NOT NULL DEFAULT 0,
    failures          bigint NOT NULL DEFAULT 0,
    prompt_tokens     bigint NOT NULL DEFAULT 0,
    completion_tokens bigint NOT NULL DEFAULT 0,
    cost              double precision NOT NULL DEFAULT 0,
    PRIMARY KEY (day, tag, model)
);

CREATE TABLE health_checks (
    id            bigserial PRIMARY KEY,
    deployment_id uuid NOT NULL,
    checked_at    timestamptz NOT NULL DEFAULT now(),
    ok            boolean NOT NULL,
    latency_ms    integer NOT NULL DEFAULT 0,
    error         text NOT NULL DEFAULT ''
);
CREATE INDEX health_checks_dep_idx ON health_checks(deployment_id, checked_at DESC);

CREATE TABLE audit_log (
    id          bigserial PRIMARY KEY,
    at          timestamptz NOT NULL DEFAULT now(),
    actor_id    text NOT NULL DEFAULT '',
    actor_label text NOT NULL DEFAULT '',
    action      text NOT NULL,
    entity_type text NOT NULL,
    entity_id   text NOT NULL DEFAULT '',
    summary     text NOT NULL DEFAULT '',
    before      jsonb,
    after       jsonb
);
CREATE INDEX audit_log_at_idx ON audit_log(at DESC);

CREATE TABLE sessions (
    token_hash text PRIMARY KEY,
    user_id    uuid REFERENCES users(id) ON DELETE CASCADE,
    is_master  boolean NOT NULL DEFAULT false,
    csrf_token text NOT NULL,
    ip         text NOT NULL DEFAULT '',
    user_agent text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL
);

CREATE TABLE invites (
    token_hash text PRIMARY KEY,
    user_id    uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_by text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    used_at    timestamptz
);

-- Guardrails
CREATE TABLE guardrails (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name        text NOT NULL UNIQUE,
    kind        text NOT NULL,            -- pii | blocklist | regex | max_length | llm_judge
    mode        text NOT NULL DEFAULT 'pre', -- pre | post | both
    action      text NOT NULL DEFAULT 'block', -- block | mask | log
    config      jsonb NOT NULL DEFAULT '{}',
    default_on  boolean NOT NULL DEFAULT false,
    enabled     boolean NOT NULL DEFAULT true,
    description text NOT NULL DEFAULT '',
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE guardrail_events (
    id         bigserial PRIMARY KEY,
    at         timestamptz NOT NULL DEFAULT now(),
    guardrail  text NOT NULL,
    request_id text NOT NULL DEFAULT '',
    key_id     uuid,
    phase      text NOT NULL,
    action     text NOT NULL,
    detail     text NOT NULL DEFAULT ''
);
CREATE INDEX guardrail_events_at_idx ON guardrail_events(at DESC);

-- MCP gateway
CREATE TABLE mcp_servers (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name          text NOT NULL UNIQUE,
    url           text NOT NULL,
    transport     text NOT NULL DEFAULT 'http', -- http | sse
    credential_id uuid REFERENCES credentials(id) ON DELETE SET NULL,
    auth_header   text NOT NULL DEFAULT 'Authorization',
    auth_prefix   text NOT NULL DEFAULT 'Bearer ',
    description   text NOT NULL DEFAULT '',
    available_to_all boolean NOT NULL DEFAULT false,
    enabled       boolean NOT NULL DEFAULT true,
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE mcp_tool_calls (
    id          bigserial PRIMARY KEY,
    at          timestamptz NOT NULL DEFAULT now(),
    server      text NOT NULL,
    tool        text NOT NULL,
    key_id      uuid,
    user_id     uuid,
    duration_ms integer NOT NULL DEFAULT 0,
    ok          boolean NOT NULL,
    error       text NOT NULL DEFAULT ''
);
CREATE INDEX mcp_tool_calls_at_idx ON mcp_tool_calls(at DESC);

-- Pass-through routes
CREATE TABLE passthrough_routes (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name          text NOT NULL UNIQUE,
    target_url    text NOT NULL,
    credential_id uuid REFERENCES credentials(id) ON DELETE SET NULL,
    auth_header   text NOT NULL DEFAULT 'Authorization',
    auth_prefix   text NOT NULL DEFAULT 'Bearer ',
    extra_headers jsonb NOT NULL DEFAULT '{}',
    require_key   boolean NOT NULL DEFAULT true,
    cost_per_request double precision NOT NULL DEFAULT 0,
    description   text NOT NULL DEFAULT '',
    enabled       boolean NOT NULL DEFAULT true,
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now()
);

-- Alerting
CREATE TABLE alert_channels (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name       text NOT NULL UNIQUE,
    kind       text NOT NULL,          -- slack | webhook | email
    config_enc bytea NOT NULL,         -- encrypted JSON (urls/addresses)
    events     text[] NOT NULL DEFAULT '{}', -- empty = all events
    min_severity text NOT NULL DEFAULT 'info',
    enabled    boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE alert_history (
    id         bigserial PRIMARY KEY,
    at         timestamptz NOT NULL DEFAULT now(),
    event      text NOT NULL,
    severity   text NOT NULL,
    title      text NOT NULL,
    body       text NOT NULL DEFAULT '',
    dedupe_key text NOT NULL DEFAULT '',
    channel    text NOT NULL DEFAULT '',
    ok         boolean NOT NULL DEFAULT true,
    error      text NOT NULL DEFAULT ''
);
CREATE INDEX alert_history_at_idx ON alert_history(at DESC);
CREATE INDEX alert_history_dedupe_idx ON alert_history(dedupe_key, at DESC);

-- +goose Down
DROP TABLE IF EXISTS alert_history, alert_channels, passthrough_routes, mcp_tool_calls, mcp_servers,
  guardrail_events, guardrails, invites, sessions, audit_log, health_checks, daily_tag_spend, daily_spend,
  request_logs, tags, end_users, api_keys, model_fallbacks, access_groups, model_aliases, deployments,
  credentials, org_members, team_members, teams, users, budget_presets, organizations, settings CASCADE;
