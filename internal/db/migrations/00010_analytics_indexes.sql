-- +goose Up
-- Indexes backing the dashboard, usage and request-log views.
CREATE INDEX IF NOT EXISTS daily_spend_day_model_idx ON daily_spend(day, model);
CREATE INDEX IF NOT EXISTS daily_spend_end_user_idx ON daily_spend(end_user, day) WHERE end_user <> '';
CREATE INDEX IF NOT EXISTS request_logs_failed_idx ON request_logs(created_at DESC) WHERE status <> 'success';
CREATE INDEX IF NOT EXISTS request_logs_end_user_idx ON request_logs(end_user, created_at DESC) WHERE end_user <> '';
CREATE INDEX IF NOT EXISTS daily_tag_spend_tag_idx ON daily_tag_spend(tag, day);

-- +goose Down
DROP INDEX IF EXISTS daily_spend_day_model_idx;
DROP INDEX IF EXISTS daily_spend_end_user_idx;
DROP INDEX IF EXISTS request_logs_failed_idx;
DROP INDEX IF EXISTS request_logs_end_user_idx;
DROP INDEX IF EXISTS daily_tag_spend_tag_idx;
