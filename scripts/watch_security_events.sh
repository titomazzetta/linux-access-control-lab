#!/usr/bin/env bash
set -euo pipefail

LOG_FILE="/var/log/globex/security_events.jsonl"

usage() {
  cat <<USAGE
Usage: $0 [--raw]
  --raw   Always print raw JSON lines (skip jq formatting)
USAGE
}

RAW_MODE=0
case "${1:-}" in
  --raw) RAW_MODE=1 ;;
  "" ) ;;
  -h|--help) usage; exit 0 ;;
  *) echo "[ERROR] Unknown option: $1"; usage; exit 1 ;;
esac

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
if [[ "$RAW_MODE" -eq 1 ]] || ! command -v jq >/dev/null 2>&1; then
  [[ "$RAW_MODE" -eq 0 ]] && echo "jq not found; streaming raw JSON lines"
  exec $SUDO tail -f "$LOG_FILE"
fi

# Robust formatting: do not terminate if a malformed line appears in the log.
$SUDO tail -f "$LOG_FILE" | while IFS= read -r line; do
  if formatted=$(printf '%s' "$line" | jq -r '[.timestamp, .program, .severity, .message] | @tsv' 2>/dev/null); then
    echo "$formatted"
  else
    echo "$line"
  fi
done
