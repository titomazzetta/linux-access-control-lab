#!/bin/bash
# ────────────────────────────────────────────────
#  Globex Financial Dashboard — Quick Start
#  For demo/dev mode (no root required)
# ────────────────────────────────────────────────

CYAN='\033[0;36m'; GREEN='\033[0;32m'; RESET='\033[0m'; BOLD='\033[1m'

echo -e "${CYAN}"
echo "  ╔══════════════════════════════════════════════════════╗"
echo "  ║     GLOBEX FINANCIAL — SECURITY DASHBOARD           ║"
echo "  ║     Quick Start (Demo Mode)                         ║"
echo "  ╚══════════════════════════════════════════════════════╝"
echo -e "${RESET}"

# Check Python
if ! command -v python3 &>/dev/null; then
  echo "ERROR: python3 is required. Install it first."
  exit 1
fi

# Install Flask if needed
python3 -c "import flask" 2>/dev/null || {
  echo "Installing Flask..."
  pip3 install flask --break-system-packages --quiet || pip3 install flask --quiet
}

# Create data dir
mkdir -p data

# Check if already running
if lsof -i:5050 &>/dev/null 2>&1; then
  echo -e "${GREEN}Dashboard already running at http://localhost:5050${RESET}"
  echo "Open your browser to: http://localhost:5050"
  exit 0
fi

echo -e "${GREEN}[✔]${RESET} Starting Globex Security Dashboard..."
echo -e "${GREEN}[✔]${RESET} Open: ${BOLD}http://localhost:5050${RESET}"
echo ""
echo "  Press Ctrl+C to stop"
echo ""

python3 app.py
