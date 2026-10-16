#!/usr/bin/env bash
# Runs the browser smoke test in an isolated, throwaway environment: its own database
# (lemongate_e2e, recreated each run), its own mock vLLM, and its own server on :4999.
# Nothing touches your dev or production data. Requires Postgres reachable via ADMIN_DATABASE_URL.
set -euo pipefail
cd "$(dirname "$0")/.."
ADMIN_URL="${ADMIN_DATABASE_URL:-postgres://lemongate:lemongate@localhost:55432/postgres?sslmode=disable}"
E2E_DB="lemongate_e2e"
E2E_URL="${ADMIN_URL%/*}/$E2E_DB?sslmode=disable"
PORT=4999 MOCK_PORT=18001
WORK=$(mktemp -d)
cleanup() {
  [[ -n "${LG_PID:-}" ]] && kill "$LG_PID" 2>/dev/null || true
  [[ -n "${MOCK_PID:-}" ]] && kill "$MOCK_PID" 2>/dev/null || true
  sleep 0.5
  psql -q "$ADMIN_URL" -c "DROP DATABASE IF EXISTS $E2E_DB WITH (FORCE)" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

psql -q "$ADMIN_URL" -c "DROP DATABASE IF EXISTS $E2E_DB WITH (FORCE)" -c "CREATE DATABASE $E2E_DB" >/dev/null
go build -o "$WORK/lemongate" ./cmd/lemongate
go build -o "$WORK/mockvllm" ./cmd/mockvllm
"$WORK/mockvllm" -addr ":$MOCK_PORT" -models mock-llama,mock-embed,mock-llama-guard,mock-prompt-guard-2 >"$WORK/mock.log" 2>&1 &
MOCK_PID=$!
cat >"$WORK/config.yaml" <<YAML
models:
  - name: e2e-chat
    api_base: http://localhost:$MOCK_PORT/v1
    upstream_model: mock-llama
    input_cost_per_m: 0.1
    output_cost_per_m: 0.2
  - name: e2e-embed
    api_base: http://localhost:$MOCK_PORT/v1
    upstream_model: mock-embed
    mode: embedding
  # Guard models (the mock answers like Llama Guard / Prompt Guard; see cmd/mockvllm/guard.go).
  - name: e2e-llama-guard
    api_base: http://localhost:$MOCK_PORT/v1
    upstream_model: mock-llama-guard
    mode: chat
  - name: e2e-prompt-guard
    api_base: http://localhost:$MOCK_PORT/v1
    upstream_model: mock-prompt-guard-2
    mode: classify
YAML
MASTER="e2e-master-$RANDOM$RANDOM"
DATABASE_URL="$E2E_URL" LEMONGATE_MASTER_KEY="$MASTER" LEMONGATE_CONFIG="$WORK/config.yaml" \
  LEMONGATE_LISTEN=":$PORT" LEMONGATE_BASE_URL="http://localhost:$PORT" \
  "$WORK/lemongate" serve >"$WORK/lemongate.log" 2>&1 &
LG_PID=$!
for _ in $(seq 1 60); do curl -sf "localhost:$PORT/health/ready" >/dev/null && break; sleep 0.25; done
(cd e2e && npm install --silent && BASE="http://localhost:$PORT" MASTER_KEY="$MASTER" node smoke.mjs) || {
  echo "--- server log ---"; tail -30 "$WORK/lemongate.log"; exit 1; }
