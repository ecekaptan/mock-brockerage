#!/usr/bin/env bash
# Capture a fresh sample log by running the scenarios + all four exploits
# against a running stack, then run the detections on it.
#
#   ./generate_sample.sh main          # stack started from the repo root
#   COMPOSE_DIR=/path/to/vulnerable-checkout ./generate_sample.sh vulnerable
#
# Start from a fresh database (docker compose down -v) so balances are known.
# For the fixed app, start it with TRUSTED_PROXY_HOPS=1 so scenarios.py can give
# each actor its own IP via X-Forwarded-For:
#   TRUSTED_PROXY_HOPS=1 docker compose up -d --build
set -euo pipefail

LABEL="${1:?usage: generate_sample.sh <label>}"
HERE="$(cd "$(dirname "$0")" && pwd)"
COMPOSE_DIR="${COMPOSE_DIR:-$HERE/..}"
PY="${PYTHON:-$HERE/../.venv/bin/python}"
OUT="$HERE/samples/$LABEL.jsonl"
export TARGET="${TARGET:-http://localhost:8000}"

curl -sf "$TARGET/health" >/dev/null || { echo "app not reachable at $TARGET" >&2; exit 1; }
SINCE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
sleep 1

"$PY" "$HERE/scenarios.py"
cd "$HERE/../exploits"
for s in race_withdraw idor_orders negative_quantity; do
  echo "=== $s"; "$PY" "$s.py" | tail -n 1
done
# The exploits share one IP and the fixed app allows 5 logins/minute per IP.
echo "... waiting 61s for the login rate-limit window"; sleep 61
echo "=== credential_stuffing"; "$PY" credential_stuffing.py | tail -n 1

sleep 1
mkdir -p "$HERE/samples"
docker compose --project-directory "$COMPOSE_DIR" logs api --no-log-prefix --since "$SINCE" \
  | grep '^{' > "$OUT"
echo
echo "[+] wrote $(wc -l < "$OUT" | tr -d ' ') events to $OUT"
echo
"$PY" "$HERE/detect.py" "$OUT"
