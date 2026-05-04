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
        self._connection_log: dict[str, list[float]] = defaultdict(list)
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Main scan cycle
    # ------------------------------------------------------------------

    def run_scan(self, deep: bool = False):
        logger.info("Starting scan cycle...")
        self._scan_count += 1
        do_deep = deep or (self._scan_count % 5 == 0)

        try:
            found_devices = self.scanner.scan(deep=do_deep)
        except Exception as e:
            logger.error(f"Scan failed: {e}")
            return

        with self.app.app_context():
            self._process_scan_results(found_devices)

    def _get_excluded_macs(self) -> set:
        from app.models import ExcludedMAC
        return {e.mac.lower() for e in ExcludedMAC.query.all()}

    def _process_scan_results(self, found_devices: list[dict]):
        from app.models import Device, DeviceSession, Alert
        from app import db
        import app.services.discord as discord

        excluded = self._get_excluded_macs()

        # Filter excluded MACs completely from found list
        found_devices = [d for d in found_devices if d['mac'].lower() not in excluded]

        now = datetime.utcnow()
        found_macs = {d['mac'] for d in found_devices}

        # Mark offline devices whose sessions need closing
        online_devices = Device.query.filter_by(is_online=True).all()
        for device in online_devices:
            if device.mac.lower() in excluded:
                continue
            if device.mac not in found_macs:
                device.is_online = False
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
            was_random = device.is_random_mac if device else False

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

                alert = Alert(
                    type='new_device',
                    message=f"Nuevo dispositivo: {mac} ({ip}) - {device.vendor}",
                    device_mac=mac,
                )
                db.session.add(alert)
                logger.info(f"New device: {mac} @ {ip}")

                # Discord: new device
                threading.Thread(
                    target=discord.send_new_device, args=(device,), daemon=True
                ).start()

                # Discord: suspicious if random MAC
                if device.is_random_mac:
                    threading.Thread(
                        target=discord.send_suspicious, args=(device,), daemon=True
                    ).start()

            else:
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

                newly_random = info.get('is_random_mac', False)
                device.is_random_mac = newly_random

                # Newly discovered random MAC on an existing device
                if newly_random and not was_random and not device.is_known:
                    threading.Thread(
                        target=discord.send_suspicious, args=(device,), daemon=True
                    ).start()

            device.is_online = True
            device.last_seen = now

            if is_new or not DeviceSession.query.filter_by(
                device_id=device.id, disconnected_at=None
            ).first():
                db.session.add(DeviceSession(device_id=device.id, ip=ip, connected_at=now))

            if device.is_blocked and ip:
                self.firewall.block_ip(ip)

            db.session.commit()

            self.socketio.emit('new_device' if is_new else 'device_update', device.to_dict())

            if is_new:
                self.socketio.emit('alert', {
                    'type': 'new_device',
                    'message': f"Nuevo dispositivo: {device.display_name} ({ip})",
                    'mac': mac,
                })

        all_devices = [d.to_dict() for d in Device.query.filter(
            ~Device.mac.in_(excluded)
        ).all()]
        self.socketio.emit('devices_list', all_devices)
        logger.info(f"Scan complete. {len(found_devices)} devices online.")

    # ------------------------------------------------------------------
    # Port scan detection via scapy (passive)
    # ------------------------------------------------------------------

    def start_port_scan_detection(self):
        t = threading.Thread(target=self._sniff_loop, daemon=True)
        t.start()
        logger.info("Port scan detection started")

    def _sniff_loop(self):
        try:
            from scapy.all import sniff
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
            self._connection_log[src] = [
                t for t in self._connection_log[src] if now - t < 60
            ]
            count = len(self._connection_log[src])

        if count >= Config.PORT_SCAN_THRESHOLD:
            with self._lock:
                self._connection_log[src] = []
            self._handle_port_scan(src, count)

    def _handle_port_scan(self, ip: str, count: int):
        logger.warning(f"Possible port scan from {ip}: {count} SYN packets/min")
        with self.app.app_context():
            from app.models import Alert, Device, ExcludedMAC
            from app import db
            import app.services.discord as discord

            # Don't alert on excluded MACs
            excluded = {e.mac.lower() for e in ExcludedMAC.query.all()}
            device = Device.query.filter_by(ip=ip).first()
            if device and device.mac.lower() in excluded:
                return

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

            threading.Thread(
                target=discord.send_port_scan,
                args=(ip, name, count),
                daemon=True,
            ).start()
