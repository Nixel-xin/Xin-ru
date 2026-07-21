#!/usr/bin/env bash
set -euo pipefail
BASE_URL="${XINRU_BASE_URL:-http://127.0.0.1:8000}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"


echo "== 0) agent-compose runtime =="
if command -v agent-compose >/dev/null 2>&1; then
  agent-compose -f agent-compose.yaml ps || sudo agent-compose -f agent-compose.yaml ps
else
  echo "WARN: agent-compose not in PATH (ok if platform injects it)"
fi
if command -v docker >/dev/null 2>&1; then
  docker ps --filter name=xinru-agent --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}' || true
fi

echo "== 1) healthz =="
curl -fsS "$BASE_URL/healthz" | tee /tmp/xinru_health.json
python3 - <<'PY'
import json
d=json.load(open('/tmp/xinru_health.json'))
assert d.get('ok') is True, d
print('health ok')
PY

echo "== 2) create unattended task =="
TARGET="${EXAM_DEMO_TARGET:-https://example.com}"
curl -fsS -X POST "$BASE_URL/api/tasks" \
  -F "target=$TARGET" \
  -F "brief=exam verify unattended" \
  -F "unattended=true" \
  -F "subdomain_discovery=false" \
  -F "path_brute=false" \
  -F "allow_register=false" \
  -F "allow_brute=false" \
  -F "waf_authorized=true" | tee /tmp/xinru_task.json
TASK_ID=$(python3 -c 'import json;print(json.load(open("/tmp/xinru_task.json"))["id"])')
echo "task_id=$TASK_ID"

echo "== 3) poll status =="
for i in $(seq 1 12); do
  ST=$(curl -fsS "$BASE_URL/api/tasks/$TASK_ID")
  echo "$ST" | python3 -c 'import sys,json;d=json.load(sys.stdin);print(d.get("status"), d.get("progress"))'
  STATUS=$(echo "$ST" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("status"))')
  case "$STATUS" in
    completed|failed|auditing|collecting|authenticating|paused|verifying_chain|generating_report)
      echo "status reached: $STATUS"; break ;;
  esac
  sleep 5
done

echo "== 4) logs tail =="
curl -fsS "$BASE_URL/api/tasks/$TASK_ID/logs?limit=20" | python3 -c 'import sys,json;logs=json.load(sys.stdin);print("logs",len(logs));
[print(x.get("log_type"), (x.get("message") or "")[:120]) for x in logs[-5:]]'

echo "== 5) CLI health (host + agent-compose container) =="
if [[ -x "$ROOT/venv/bin/python" ]]; then
  PY="$ROOT/venv/bin/python"
else
  PY="python3"
fi
"$PY" "$ROOT/cli.py" --base "$BASE_URL" health || true
if command -v docker >/dev/null 2>&1 && docker ps --format '{{.Names}}' | grep -qx xinru-agent; then
  echo "-- container cli --"
  docker exec -e XINRU_BASE_URL="$BASE_URL" xinru-agent python /app/cli.py --base "$BASE_URL" health
  echo "-- scripts/agent_cli.sh --"
  "$ROOT/scripts/agent_cli.sh" health
fi
echo "VERIFY_BASIC_OK task_id=$TASK_ID"
echo "Full loop: $PY cli.py --base $BASE_URL run --target <url> --wait --timeout 1800"
echo "Or: ./scripts/agent_cli.sh run --target <url> --wait --timeout 1800"
