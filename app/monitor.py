import logging
import threading
from datetime import datetime
from collections import defaultdict

logger = logging.getLogger(__name__)


class DeviceMonitor:
    """
    Orchestrates periodic scanning, history tracking, alerts,
    and port-scan detection.
    """

    def __init__(self, app, socketio, scanner, firewall):
        self.app = app
        self.socketio = socketio
        self.scanner = scanner
        self.firewall = firewall
        self._scan_count = 0
        # port_scan detection: {ip: [timestamps]}
        self._connection_log: dict[str, list[float]] = defaultdict(list)
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Main scan cycle
    # ------------------------------------------------------------------

    def run_scan(self, deep: bool = False):
        """Execute a full scan and update the database."""
        logger.info("Starting scan cycle...")
        self._scan_count += 1
        # Every 5th scan do OS detection
        do_deep = deep or (self._scan_count % 5 == 0)

        try:
            found_devices = self.scanner.scan(deep=do_deep)
        except Exception as e:
            logger.error(f"Scan failed: {e}")
            return

        with self.app.app_context():
            self._process_scan_results(found_devices)

    def _process_scan_results(self, found_devices: list[dict]):
        from app.models import Device, DeviceSession, Alert
        from app import db

        now = datetime.utcnow()
        found_macs = {d['mac'] for d in found_devices}

        # Mark offline devices whose sessions need closing
        online_devices = Device.query.filter_by(is_online=True).all()
        for device in online_devices:
            if device.mac not in found_macs:
                device.is_online = False
                # Close open session
                open_session = DeviceSession.query.filter_by(
                    device_id=device.id, disconnected_at=None
                ).first()
                if open_session:
                    open_session.disconnected_at = now
                db.session.commit()
                self.socketio.emit('device_offline', device.to_dict())

        # Process found devices
        for info in found_devices:
            mac = info['mac']
            ip = info['ip']

            device = Device.query.filter_by(mac=mac).first()
            is_new = device is None

            if is_new:
                device = Device(
                    mac=mac,
                    ip=ip,
                    vendor=info.get('vendor', ''),
                    hostname=info.get('hostname', ''),
                    mdns_name=info.get('mdns_name', ''),
                    os_detected=info.get('os_detected', ''),
                    os_confidence=info.get('os_confidence', 0),
                    is_random_mac=info.get('is_random_mac', False),
                    first_seen=now,
                )
                db.session.add(device)
                db.session.flush()

                # Create alert
                alert = Alert(
                    type='new_device',
                    message=f"Nuevo dispositivo detectado: {mac} ({ip}) - {device.vendor}",
                    device_mac=mac,
                )
                db.session.add(alert)
                logger.info(f"New device: {mac} @ {ip}")
            else:
                # Update existing
                device.ip = ip
                if info.get('vendor') and info['vendor'] != 'Unknown':
                    device.vendor = info['vendor']
                if info.get('hostname'):
                    device.hostname = info['hostname']
                if info.get('mdns_name'):
                    device.mdns_name = info['mdns_name']
                if info.get('os_detected'):
                    device.os_detected = info['os_detected']
                    device.os_confidence = info.get('os_confidence', 0)
                device.is_random_mac = info.get('is_random_mac', False)

            device.is_online = True
            device.last_seen = now

            # Open session if just came online or is new
            if is_new or not DeviceSession.query.filter_by(
                device_id=device.id, disconnected_at=None
            ).first():
                session = DeviceSession(device_id=device.id, ip=ip, connected_at=now)
                db.session.add(session)

            # Re-apply firewall block if device is flagged
            if device.is_blocked and ip:
                self.firewall.block_ip(ip)

            db.session.commit()

            event = 'new_device' if is_new else 'device_update'
            self.socketio.emit(event, device.to_dict())

            if is_new:
                self.socketio.emit('alert', {
                    'type': 'new_device',
                    'message': f"Nuevo dispositivo: {device.display_name} ({ip})",
                    'mac': mac,
                })

        # Emit full device list refresh
        all_devices = [d.to_dict() for d in Device.query.all()]
        self.socketio.emit('devices_list', all_devices)
        logger.info(f"Scan complete. {len(found_devices)} devices online.")

    # ------------------------------------------------------------------
    # Port scan detection via scapy (passive)
    # ------------------------------------------------------------------

    def start_port_scan_detection(self):
        """Start a background thread sniffing for port scan patterns."""
        import threading
        t = threading.Thread(target=self._sniff_loop, daemon=True)
        t.start()
        logger.info("Port scan detection started")

    def _sniff_loop(self):
        try:
            from scapy.all import sniff, TCP
            sniff(
                filter="tcp[tcpflags] & (tcp-syn) != 0",
                prn=self._check_packet,
                store=False,
            )
        except Exception as e:
            logger.warning(f"Port scan detection unavailable: {e}")

    def _check_packet(self, pkt):
        import time
        from config import Config
        src = pkt['IP'].src if 'IP' in pkt else None
        if not src:
            return

        now = time.time()
        with self._lock:
            self._connection_log[src].append(now)
            # Keep only last 60 seconds
            self._connection_log[src] = [
                t for t in self._connection_log[src] if now - t < 60
            ]
            count = len(self._connection_log[src])

        if count >= Config.PORT_SCAN_THRESHOLD:
            with self._lock:
                self._connection_log[src] = []  # Reset after alert
            self._handle_port_scan(src, count)

    def _handle_port_scan(self, ip: str, count: int):
        logger.warning(f"Possible port scan from {ip}: {count} SYN packets/min")
        with self.app.app_context():
            from app.models import Alert, Device
            from app import db
            device = Device.query.filter_by(ip=ip).first()
            name = device.display_name if device else ip
            alert = Alert(
                type='port_scan',
                message=f"Posible port scan desde {name} ({ip}): {count} SYN/min",
                device_mac=device.mac if device else ip,
            )
            db.session.add(alert)
            db.session.commit()
            self.socketio.emit('alert', {
                'type': 'port_scan',
                'message': alert.message,
                'mac': device.mac if device else '',
            })
