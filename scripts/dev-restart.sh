#!/usr/bin/env bash
# Rebuilds and restarts a local LemonGate instance in the background.
# Usage: scripts/dev-restart.sh [port]   (logs: tmp/lemongate-<port>.log)
# DEV_DATABASE_URL / DEV_CONFIG override the database and config from .env.dev.
set -euo pipefail
cd "$(dirname "$0")/.."
PORT="${1:-4000}"
mkdir -p tmp bin
PIDFILE="tmp/lemongate-$PORT.pid"
if [[ -f "$PIDFILE" ]] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
  kill "$(cat "$PIDFILE")" && sleep 0.5
fi
go build -o "bin/lemongate-$PORT" ./cmd/lemongate
[[ -f .env.dev ]] && source .env.dev
[[ -n "${DEV_DATABASE_URL:-}" ]] && export DATABASE_URL="$DEV_DATABASE_URL"
[[ -n "${DEV_CONFIG:-}" ]] && export LEMONGATE_CONFIG="$DEV_CONFIG"
export LEMONGATE_LISTEN=":$PORT" LEMONGATE_BASE_URL="http://localhost:$PORT"
nohup "bin/lemongate-$PORT" serve > "tmp/lemongate-$PORT.log" 2>&1 &
echo $! > "$PIDFILE"
for _ in $(seq 1 40); do
  curl -sf "localhost:$PORT/health/live" >/dev/null && { echo "lemongate up on :$PORT (pid $(cat "$PIDFILE"))"; exit 0; }
  sleep 0.25
done
echo "lemongate failed to start; see tmp/lemongate-$PORT.log" >&2
tail -20 "tmp/lemongate-$PORT.log" >&2
exit 1
