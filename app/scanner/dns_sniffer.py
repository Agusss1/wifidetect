"""
DNS sniffer pasivo: captura consultas DNS en la LAN y las asocia
al dispositivo que las originó.

Funciona mejor cuando el kill switch está activo (somos MITM).
En modo normal solo captura lo que es visible en modo promiscuo
(varía según el router/AP).
"""

import logging
import threading
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

# Dominios de infraestructura que no tienen valor para el historial
_NOISE_SUFFIXES = (
    '.in-addr.arpa', '.ip6.arpa', '.local',
    'wpad', 'isatap', 'teredo',
)

_DEDUP_MINUTES = 5   # No volver a guardar el mismo dominio en X minutos


class DNSSniffer:
    def __init__(self, app, iface: str):
        self.app = app
        self.iface = iface
        self._running = False
        self._thread: threading.Thread | None = None

    def start(self):
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._loop, daemon=True,
                                        name='dns-sniffer')
        self._thread.start()
        logger.info('DNS sniffer iniciado')

    def stop(self):
        self._running = False

    # ------------------------------------------------------------------

    def _loop(self):
        try:
            from scapy.all import sniff, DNS, IP
        except ImportError:
            logger.warning('scapy no disponible — DNS sniffer inactivo')
            return

        def handle(pkt):
            if not self._running:
                return
            try:
                if not (IP in pkt and DNS in pkt):
                    return
                # Solo queries (qr=0), no respuestas
                if pkt[DNS].qr != 0:
                    return
                src_ip = pkt[IP].src
                for _ in range(pkt[DNS].qdcount):
                    raw = pkt[DNS].qd.qname
                    domain = (raw.decode('utf-8', errors='replace')
                               if isinstance(raw, bytes) else str(raw))
                    domain = domain.rstrip('.').lower()
                    if domain and not any(domain.endswith(s) for s in _NOISE_SUFFIXES):
                        self._record(src_ip, domain)
            except Exception as e:
                logger.debug(f'DNS parse error: {e}')

        try:
            sniff(
                iface=self.iface,
                filter='udp port 53',
                prn=handle,
                store=False,
                stop_filter=lambda _: not self._running,
            )
        except Exception as e:
            logger.warning(f'DNS sniffer se detuvo: {e}')

    def _record(self, src_ip: str, domain: str):
        with self.app.app_context():
            from app.models import DomainVisit, Device, ExcludedMAC
            from app import db

            excluded = {e.mac.lower() for e in ExcludedMAC.query.all()}
            device = Device.query.filter_by(ip=src_ip).first()
            if device is None or device.mac.lower() in excluded:
                return

            cutoff = datetime.utcnow() - timedelta(minutes=_DEDUP_MINUTES)
            already = DomainVisit.query.filter_by(
                device_id=device.id,
                domain=domain,
            ).filter(DomainVisit.visited_at >= cutoff).first()

            if not already:
                db.session.add(DomainVisit(
                    device_id=device.id,
                    domain=domain,
                ))
                db.session.commit()
                logger.debug(f'DNS: {device.display_name} -> {domain}')
