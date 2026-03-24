#!/usr/bin/env bash
set -euo pipefail

COUNT="${1:-3}"
LOG_FILE="/var/log/globex/security_events.jsonl"

usage() {
  echo "Usage: $0 [count>=1]"
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

if ! [[ "$COUNT" =~ ^[0-9]+$ ]] || [[ "$COUNT" -lt 1 ]]; then
  usage
  exit 1
fi

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

echo "Generating $COUNT authpriv test events via logger..."
for i in $(seq 1 "$COUNT"); do
  $SUDO logger -p authpriv.notice -t globex-test "globex logging test event #$i from $(whoami)"
  sleep 0.2
done

# Do not force rsyslog restart here. In healthy setups, logger events should flow immediately.
# Restarting can fail in container/non-systemd contexts and isn't required for validation.
sleep 0.5

echo "Done. Check with:"
echo "  sudo tail -n $COUNT $LOG_FILE"
