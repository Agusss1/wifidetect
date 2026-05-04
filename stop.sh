#!/usr/bin/env bash
INSTALL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PIDFILE="$INSTALL_DIR/data/wifidetect.pid"

if [ -f "$PIDFILE" ]; then
  PID=$(cat "$PIDFILE")
  if kill -0 "$PID" 2>/dev/null; then
    kill "$PID"
    rm -f "$PIDFILE"
    echo "WiFiDetect detenido (PID $PID)."
  else
    echo "El proceso ya no existe."
    rm -f "$PIDFILE"
  fi
else
  echo "No se encontró PID file. WiFiDetect no está corriendo."
fi
