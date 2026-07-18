#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
if [[ ! -f .env ]]; then
  cp .env.example .env
  echo "created .env from .env.example — fill OPENAI_API_KEY"
fi
export EXAM_MODE=1 XINRU_UNATTENDED=1
if command -v agent-compose >/dev/null 2>&1; then
  agent-compose -f agent-compose.yaml up -d --build
elif command -v docker >/dev/null 2>&1; then
  docker compose -f docker-compose.yaml up -d --build
else
  echo "docker/agent-compose missing; local uvicorn"
  export DATA_DIR="$ROOT/data" REPORTS_DIR="$ROOT/reports" DATABASE_PATH="$ROOT/data/xinru.db"
  mkdir -p "$DATA_DIR" "$REPORTS_DIR"
  if [[ -x "$ROOT/venv/bin/uvicorn" ]]; then
    exec "$ROOT/venv/bin/uvicorn" web.main:app --host 0.0.0.0 --port 8000
  fi
  exec uvicorn web.main:app --host 0.0.0.0 --port 8000
fi
sleep 3
curl -fsS http://127.0.0.1:8000/healthz || true
