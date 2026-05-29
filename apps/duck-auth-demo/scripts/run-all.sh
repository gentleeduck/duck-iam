#!/usr/bin/env bash
# Boot Postgres + the duck-auth-demo backend + Storybook together.
# Ctrl+C stops backend + Storybook (Postgres stays up).

set -uo pipefail

cd "$(dirname "$0")/.."
DEMO_DIR="$(pwd)"
LOG_DIR="$DEMO_DIR/.logs"
mkdir -p "$LOG_DIR"

BACKEND_PORT="${PORT:-8787}"
STORYBOOK_PORT="${STORYBOOK_PORT:-6006}"

PIDS=()
cleanup() {
  echo
  echo "[run-all] stopping backend + storybook..."
  for pid in "${PIDS[@]}"; do
    kill "$pid" 2>/dev/null || true
  done
  wait 2>/dev/null || true
}
trap cleanup EXIT INT TERM

free_port() {
  local port="$1"
  local label="$2"
  local pids
  pids="$(lsof -ti tcp:"$port" 2>/dev/null || true)"
  if [[ -n "$pids" ]]; then
    echo "[run-all] port $port is in use ($label); killing PIDs: $pids"
    # shellcheck disable=SC2086
    kill -9 $pids 2>/dev/null || true
    sleep 1
  fi
}

free_port "$BACKEND_PORT" "backend"
free_port "$STORYBOOK_PORT" "storybook"

echo "[run-all] 1/4  bringing up Postgres..."
docker compose -f "$DEMO_DIR/docker-compose.yml" up -d postgres >/dev/null

echo "[run-all] 2/4  waiting for Postgres health..."
until docker exec duck-auth-demo-pg pg_isready -U duck -d duck_auth_demo >/dev/null 2>&1; do
  sleep 1
done

echo "[run-all] 3/4  applying schema..."
if ! (cd "$DEMO_DIR" && bun run db:migrate >"$LOG_DIR/migrate.log" 2>&1); then
  echo "[run-all] db:migrate failed — see $LOG_DIR/migrate.log"
  exit 1
fi

echo "[run-all] 4a/4 starting backend on :$BACKEND_PORT..."
(cd "$DEMO_DIR" && PORT="$BACKEND_PORT" bun src/server.ts) \
  >"$LOG_DIR/server.log" 2>&1 &
BACKEND_PID=$!
PIDS+=("$BACKEND_PID")

echo "[run-all] 4b/4 starting Storybook on :$STORYBOOK_PORT..."
(cd "$DEMO_DIR" && PATH="$DEMO_DIR/../../node_modules/.bin:$PATH" \
   storybook dev -p "$STORYBOOK_PORT" --quiet --no-open) \
  >"$LOG_DIR/storybook.log" 2>&1 &
SB_PID=$!
PIDS+=("$SB_PID")

# Wait for backend to bind. Give it 30s; bail with the tail of its log on timeout.
echo "[run-all] waiting for backend..."
for _ in $(seq 1 60); do
  if curl -sf -o /dev/null "http://localhost:$BACKEND_PORT/"; then
    backend_ok=1
    break
  fi
  if ! kill -0 "$BACKEND_PID" 2>/dev/null; then
    echo "[run-all] backend died during startup. Last log lines:"
    tail -20 "$LOG_DIR/server.log"
    exit 1
  fi
  sleep 0.5
done
if [[ -z "${backend_ok:-}" ]]; then
  echo "[run-all] backend never bound to :$BACKEND_PORT. Last log lines:"
  tail -20 "$LOG_DIR/server.log"
  exit 1
fi

echo "[run-all] waiting for Storybook..."
for _ in $(seq 1 240); do
  if curl -sf -o /dev/null "http://localhost:$STORYBOOK_PORT/iframe.html"; then
    sb_ok=1
    break
  fi
  if ! kill -0 "$SB_PID" 2>/dev/null; then
    echo "[run-all] storybook died during startup. Last log lines:"
    tail -30 "$LOG_DIR/storybook.log"
    exit 1
  fi
  sleep 0.5
done
if [[ -z "${sb_ok:-}" ]]; then
  echo "[run-all] storybook never bound to :$STORYBOOK_PORT. Last log lines:"
  tail -30 "$LOG_DIR/storybook.log"
  exit 1
fi

cat <<EOF

[run-all] all systems go:
          backend     http://localhost:$BACKEND_PORT
          storybook   http://localhost:$STORYBOOK_PORT
          db logs     docker logs -f duck-auth-demo-pg
          server logs tail -f $LOG_DIR/server.log
          sb logs     tail -f $LOG_DIR/storybook.log

[run-all] Ctrl+C to stop. Postgres stays running (use \`bun run db:down\` to remove).
EOF

# Poll for either child dying. macOS ships Bash 3.2 which has no
# `wait -n`, so we busy-wait with a 1s interval — cheap given we are
# only watching two pids.
while :; do
  if ! kill -0 "$BACKEND_PID" 2>/dev/null; then
    echo "[run-all] backend exited. Last log lines:"
    tail -30 "$LOG_DIR/server.log"
    break
  fi
  if ! kill -0 "$SB_PID" 2>/dev/null; then
    echo "[run-all] storybook exited. Last log lines:"
    tail -30 "$LOG_DIR/storybook.log"
    break
  fi
  sleep 1
done
