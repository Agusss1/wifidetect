#!/usr/bin/env python3
"""
WiFiDetect - Home Network Security Monitor
Run with: sudo python3 main.py
"""

import os
import sys
import threading
import logging

if os.geteuid() != 0:
    print("ERROR: Este programa requiere privilegios de root.")
    print("Ejecuta con: sudo python3 main.py")
    sys.exit(1)

from app import create_app, db, socketio
from app.scanner.network import NetworkScanner, get_default_interface
from app.scanner.oui import load_oui_database
from app.security.firewall import FirewallManager
from app.security.bandwidth import BandwidthManager
from app.security.scheduler import BlockScheduler
from app.monitor import DeviceMonitor

logger = logging.getLogger(__name__)


def main():
    app = create_app()

    # Determine interface
    from config import Config
    iface = Config.NETWORK_INTERFACE or get_default_interface()
    logger.info(f"Using interface: {iface}")

    # Pre-load OUI database in background
    oui_thread = threading.Thread(target=load_oui_database, daemon=True)
    oui_thread.start()

    # Initialize security modules
    try:
        firewall = FirewallManager()
    except Exception as e:
        logger.warning(f"Firewall init failed (iptables unavailable?): {e}")
        firewall = _DummyFirewall()

    try:
        bandwidth = BandwidthManager(iface)
    except Exception as e:
        logger.warning(f"Bandwidth manager init failed (tc unavailable?): {e}")
        bandwidth = _DummyBandwidth()

    # Register extensions for routes
    app.extensions['firewall'] = firewall
    app.extensions['bandwidth'] = bandwidth

    # Scanner & monitor
    scanner = NetworkScanner(iface)
    monitor = DeviceMonitor(app, socketio, scanner, firewall)
    app.extensions['monitor'] = monitor

    # Block scheduler
    block_scheduler = BlockScheduler(firewall, app)

    # APScheduler for periodic scanning
    from apscheduler.schedulers.background import BackgroundScheduler
    from app.models import AppConfig

    def scheduled_scan():
        monitor.run_scan()
        block_scheduler.tick()

    scheduler = BackgroundScheduler()

    with app.app_context():
        interval = int(AppConfig.get('scan_interval', Config.SCAN_INTERVAL))

    scheduler.add_job(scheduled_scan, 'interval', minutes=interval, id='main_scan')
    scheduler.start()

    # Initial scan after 3 seconds
    def initial_scan():
        import time
        time.sleep(3)
        monitor.run_scan()

    t = threading.Thread(target=initial_scan, daemon=True)
    t.start()

    # Port scan detection
    monitor.start_port_scan_detection()

    logger.info("Starting WiFiDetect on http://localhost:5000")
    print("\n" + "="*50)
    print("  WiFiDetect arriba en http://localhost:5000")
    print("="*50 + "\n")

    socketio.run(app, host='0.0.0.0', port=5000, debug=False, use_reloader=False)


class _DummyFirewall:
    def block_ip(self, ip): logger.warning(f"Firewall N/A: would block {ip}")
    def unblock_ip(self, ip): logger.warning(f"Firewall N/A: would unblock {ip}")
    def is_blocked(self, ip): return False
    def flush_chain(self): pass
    def get_blocked_ips(self): return []


class _DummyBandwidth:
    def set_limit(self, ip, kbps): logger.warning(f"BW N/A: would limit {ip} to {kbps}kbps")
    def remove_limit(self, ip): pass
    def get_stats(self, ip): return {}


if __name__ == '__main__':
    main()
