-- +goose Up
CREATE INDEX IF NOT EXISTS mcp_tool_calls_server_at_idx ON mcp_tool_calls(server, at DESC);

-- +goose Down
DROP INDEX IF EXISTS mcp_tool_calls_server_at_idx;
