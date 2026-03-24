#!/usr/bin/env bash
set -euo pipefail

LOG_DIR="/var/log/globex"
JSON_LOG="$LOG_DIR/security_events.jsonl"
AUTH_LOG="$LOG_DIR/auth.log"
RSYSLOG_CONF="/etc/rsyslog.d/10-globex-security.conf"
RSYSLOG_CHECK_OUT="/tmp/globex_rsyslog_check.out"

usage() {
  echo "Usage: $0"
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
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

echo "== Globex logging health check =="

echo "[1/6] rsyslog service status"
if command -v systemctl >/dev/null 2>&1 && [[ -d /run/systemd/system ]]; then
  if $SUDO systemctl is-active --quiet rsyslog; then
    echo "  [OK] rsyslog is active"
  else
    echo "  [FAIL] rsyslog is not active"
    exit 1
  fi
else
  echo "  [WARN] systemd is not available in this environment; skipping service check"
fi

echo "[2/6] Globex rsyslog config exists"
if $SUDO test -f "$RSYSLOG_CONF"; then
  echo "  [OK] $RSYSLOG_CONF present"
else
  echo "  [FAIL] Missing $RSYSLOG_CONF"
  exit 1
fi

echo "[3/6] rsyslog config syntax"
if ! command -v rsyslogd >/dev/null 2>&1; then
  echo "  [WARN] rsyslogd binary not found; skipping syntax validation"
else
  if $SUDO rsyslogd -N1 >"$RSYSLOG_CHECK_OUT" 2>&1; then
    echo "  [OK] rsyslog config syntax valid"
  else
    echo "  [FAIL] rsyslog config syntax invalid"
    sed -n '1,120p' "$RSYSLOG_CHECK_OUT"
    exit 1
  fi
fi

echo "[4/6] log files exist"
$SUDO test -f "$JSON_LOG" && echo "  [OK] $JSON_LOG present" || echo "  [WARN] $JSON_LOG missing (no events yet?)"
$SUDO test -f "$AUTH_LOG" && echo "  [OK] $AUTH_LOG present" || echo "  [WARN] $AUTH_LOG missing (no events yet?)"

echo "[5/6] file permissions"
$SUDO ls -ld "$LOG_DIR" 2>/dev/null | sed 's/^/  /' || echo "  [WARN] $LOG_DIR missing"
$SUDO ls -l "$LOG_DIR" 2>/dev/null | sed 's/^/  /' || true

echo "[6/6] recent JSON events (up to 5)"
if $SUDO test -f "$JSON_LOG"; then
  $SUDO tail -n 5 "$JSON_LOG" | sed 's/^/  /'
else
  echo "  [INFO] No JSON log file to display yet"
fi

echo "Health check complete."
