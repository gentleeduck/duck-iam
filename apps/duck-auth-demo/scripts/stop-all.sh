#!/usr/bin/env bash
# Stop the demo backend + Storybook (Postgres stays up).
set -euo pipefail
pkill -f "bun src/server.ts" 2>/dev/null || true
pkill -f "storybook dev" 2>/dev/null || true
echo "[stop-all] killed backend + storybook. Use \`bun run db:down\` to drop Postgres."
