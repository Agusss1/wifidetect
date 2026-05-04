#!/usr/bin/env bash
set -euo pipefail

INSTALL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV="$INSTALL_DIR/venv"
PIDFILE="$INSTALL_DIR/data/wifidetect.pid"
LOG="$INSTALL_DIR/data/wifidetect.log"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'

if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}[✗]${NC} Ejecuta con sudo: sudo bash start.sh"
  exit 1
fi

if [ ! -d "$VENV" ]; then
  echo -e "${YELLOW}[!]${NC} Entorno virtual no encontrado. Ejecuta primero: sudo bash install.sh"
  exit 1
fi

# Check if already running
if [ -f "$PIDFILE" ]; then
  OLD_PID=$(cat "$PIDFILE")
  if kill -0 "$OLD_PID" 2>/dev/null; then
    echo -e "${YELLOW}[!]${NC} WiFiDetect ya está corriendo (PID $OLD_PID)"
    echo "    Para detenerlo: sudo kill $OLD_PID"
    exit 0
  else
    rm -f "$PIDFILE"
  fi
fi

# Optional: set interface via env
# export NETWORK_INTERFACE=wlan0

echo ""
echo "============================================"
echo "  WiFiDetect iniciando..."
echo "  Logs: $LOG"
echo "  Para detener: sudo kill \$(cat $PIDFILE)"
echo "============================================"
echo ""

mkdir -p "$INSTALL_DIR/data"

# Run with virtual env python
cd "$INSTALL_DIR"
"$VENV/bin/python" main.py &
BGPID=$!
echo $BGPID > "$PIDFILE"
echo -e "${GREEN}[✓]${NC} WiFiDetect corriendo en http://localhost:5000 (PID $BGPID)"
echo ""

# Optionally open browser
if command -v xdg-open &>/dev/null; then
  sleep 2
  xdg-open "http://localhost:5000" &>/dev/null &
fi

wait $BGPID
