#!/usr/bin/env bash
# Call xinru CLI through the running agent-compose container (exam-friendly).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BASE_URL="${XINRU_BASE_URL:-http://127.0.0.1:8000}"
CONTAINER="${XINRU_CONTAINER:-xinru-agent}"

if ! command -v docker >/dev/null 2>&1; then
  echo "docker not found" >&2
  exit 1
fi
if ! docker ps --format '{{.Names}}' | grep -qx "$CONTAINER"; then
  echo "container $CONTAINER not running. try: agent-compose -f agent-compose.yaml up -d" >&2
  exit 1
fi
exec docker exec -e XINRU_BASE_URL="$BASE_URL" "$CONTAINER" python /app/cli.py --base "$BASE_URL" "$@"
