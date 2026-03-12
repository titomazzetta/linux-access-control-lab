#!/usr/bin/env bash
set -euo pipefail

LOG_FILE="/var/log/globex/security_events.jsonl"

if [[ "${EUID}" -ne 0 ]]; then
  if command -v sudo >/dev/null 2>&1; then
    SUDO="sudo"
  else
    echo "[ERROR] Run as root or install sudo."
    exit 1
  fi
else
  SUDO=""
fi

if ! $SUDO test -f "$LOG_FILE"; then
  echo "[ERROR] $LOG_FILE not found. Run setup first: sudo bash globex_setup.sh task3"
  exit 1
fi

echo "Watching $LOG_FILE (Ctrl+C to stop)"
if command -v jq >/dev/null 2>&1; then
  $SUDO tail -f "$LOG_FILE" | jq -r '[.timestamp, .program, .severity, .message] | @tsv'
else
  echo "jq not found; streaming raw JSON lines"
  $SUDO tail -f "$LOG_FILE"
fi
