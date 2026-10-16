-- +goose Up
CREATE TABLE guardrail_policies (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name        text NOT NULL UNIQUE,
    description text NOT NULL DEFAULT '',
    guardrails  text[] NOT NULL DEFAULT '{}',
    preset      text NOT NULL DEFAULT '',
    default_on  boolean NOT NULL DEFAULT false,
    enabled     boolean NOT NULL DEFAULT true,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE guardrails ADD COLUMN preset text NOT NULL DEFAULT '';
ALTER TABLE api_keys ADD COLUMN policies text[] NOT NULL DEFAULT '{}';
ALTER TABLE teams ADD COLUMN policies text[] NOT NULL DEFAULT '{}';

-- +goose Down
ALTER TABLE teams DROP COLUMN policies;
ALTER TABLE api_keys DROP COLUMN policies;
ALTER TABLE guardrails DROP COLUMN preset;
DROP TABLE guardrail_policies;
