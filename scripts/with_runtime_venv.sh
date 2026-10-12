#!/usr/bin/env bash
# Invoke dns-lab-agent-tools with the deployed runtime interpreter so
# websocket-client is available for Top Reports.
set -euo pipefail
ROOT="${DNS_LAB_RUNTIME:-/home/jackie_tsai/.local/share/dns-lab-agent-tools/current}"
PY="${ROOT}/.venv/bin/python"
if [[ ! -x "$PY" ]]; then
  echo "RUNTIME_VENV_MISSING: expected $PY" >&2
  exit 2
fi
export PYTHONPATH="$ROOT${PYTHONPATH:+:$PYTHONPATH}"
exec "$PY" "$@"
