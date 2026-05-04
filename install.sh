#!/usr/bin/env bash
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()    { echo -e "${GREEN}[✓]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
error()   { echo -e "${RED}[✗]${NC} $*"; exit 1; }

echo ""
echo "============================================"
echo "  WiFiDetect - Instalación"
echo "============================================"
echo ""

# --- Root check ---
if [ "$EUID" -ne 0 ]; then
  error "Ejecuta este script con sudo: sudo bash install.sh"
fi

INSTALL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
info "Directorio de instalación: $INSTALL_DIR"

# --- System packages ---
info "Actualizando repositorios..."
apt-get update -qq

PACKAGES=(
  python3 python3-pip python3-venv python3-dev
  nmap arp-scan avahi-utils avahi-daemon
  iptables iproute2 net-tools
  libffi-dev libssl-dev
)

info "Instalando paquetes del sistema..."
for pkg in "${PACKAGES[@]}"; do
  if dpkg -l "$pkg" &>/dev/null; then
    echo "  [ya instalado] $pkg"
  else
    apt-get install -y -qq "$pkg" && echo "  [instalado] $pkg"
  fi
done

# --- Python virtual environment ---
VENV="$INSTALL_DIR/venv"
if [ ! -d "$VENV" ]; then
  info "Creando entorno virtual Python..."
  python3 -m venv "$VENV"
fi

info "Instalando dependencias Python..."
"$VENV/bin/pip" install --upgrade pip -q
"$VENV/bin/pip" install -r "$INSTALL_DIR/requirements.txt" -q
info "Dependencias Python instaladas."

# --- Data directory ---
mkdir -p "$INSTALL_DIR/data"
info "Directorio de datos creado."

# --- Avahi daemon ---
if ! systemctl is-active --quiet avahi-daemon 2>/dev/null; then
  systemctl enable avahi-daemon --quiet 2>/dev/null || true
  systemctl start avahi-daemon 2>/dev/null || true
  info "avahi-daemon iniciado."
else
  info "avahi-daemon ya está corriendo."
fi

# --- Make scripts executable ---
chmod +x "$INSTALL_DIR/start.sh"
chmod +x "$INSTALL_DIR/main.py"

info ""
info "============================================"
info "  Instalación completada."
info "  Ejecuta: sudo bash start.sh"
info "============================================"
echo ""
