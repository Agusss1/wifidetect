import subprocess
import re
import socket
import logging
import netifaces
from typing import Optional

logger = logging.getLogger(__name__)


def get_default_interface() -> str:
    """Return the default network interface (the one with the default route)."""
    try:
        gateways = netifaces.gateways()
        iface = gateways['default'][netifaces.AF_INET][1]
        return iface
    except Exception:
        pass
    # Fallback: find first non-loopback interface
    for iface in netifaces.interfaces():
        if iface == 'lo':
            continue
        addrs = netifaces.ifaddresses(iface)
        if netifaces.AF_INET in addrs:
            return iface
    return 'eth0'


def get_network_cidr(iface: str) -> Optional[str]:
    """Return the network CIDR for the given interface, e.g. 192.168.1.0/24"""
    try:
        addrs = netifaces.ifaddresses(iface)
        inet = addrs.get(netifaces.AF_INET, [{}])[0]
        ip = inet.get('addr')
        netmask = inet.get('netmask')
        if not ip or not netmask:
            return None
        # Convert netmask to CIDR prefix length
        prefix = sum(bin(int(x)).count('1') for x in netmask.split('.'))
        # Compute network address
        ip_parts = [int(x) for x in ip.split('.')]
        mask_parts = [int(x) for x in netmask.split('.')]
        net_parts = [str(ip_parts[i] & mask_parts[i]) for i in range(4)]
        return f"{'.'.join(net_parts)}/{prefix}"
    except Exception as e:
        logger.error(f"Could not determine network CIDR: {e}")
        return None


def arp_scan(network: str, iface: str) -> list[dict]:
    """Run arp-scan and return list of {ip, mac} dicts."""
    devices = []
    try:
        out = subprocess.check_output(
            ['arp-scan', '--interface', iface, network, '--retry=2'],
            stderr=subprocess.DEVNULL,
            timeout=30,
            text=True
        )
        for line in out.splitlines():
            m = re.match(r'(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F:]{17})', line)
            if m:
                devices.append({'ip': m.group(1), 'mac': m.group(2).lower()})
    except FileNotFoundError:
        logger.warning("arp-scan not found, falling back to arp table")
        devices = _arp_table_fallback()
    except subprocess.TimeoutExpired:
        logger.warning("arp-scan timed out")
    except Exception as e:
        logger.error(f"arp-scan error: {e}")
    return devices


def _arp_table_fallback() -> list[dict]:
    """Read from /proc/net/arp as fallback."""
    devices = []
    try:
        with open('/proc/net/arp', 'r') as f:
            for line in f.readlines()[1:]:
                parts = line.split()
                if len(parts) >= 4 and parts[2] != '0x0':
                    ip = parts[0]
                    mac = parts[3]
                    if mac != '00:00:00:00:00:00':
                        devices.append({'ip': ip, 'mac': mac.lower()})
    except Exception as e:
        logger.error(f"ARP table fallback error: {e}")
    return devices


def nmap_scan(network: str, fast: bool = False) -> dict[str, dict]:
    """
    Run nmap on the network. Returns dict keyed by IP with scan results.
    fast=True skips OS detection for quick scans.
    """
    results: dict[str, dict] = {}
    try:
        import nmap
        nm = nmap.PortScanner()
        args = '-sn -PR'
        if not fast:
            args = '-O --osscan-guess -sV --version-intensity 3 -T4'
        nm.scan(hosts=network, arguments=args, timeout=60)
        for host in nm.all_hosts():
            info: dict = {'hostname': '', 'os': '', 'os_confidence': 0}
            # Hostname
            try:
                hostnames = nm[host].get('hostnames', [])
                if hostnames:
                    info['hostname'] = hostnames[0].get('name', '')
            except Exception:
                pass
            # OS detection
            if not fast:
                try:
                    os_matches = nm[host].get('osmatch', [])
                    if os_matches:
                        best = os_matches[0]
                        info['os'] = best.get('name', '')
                        info['os_confidence'] = int(best.get('accuracy', 0))
                except Exception:
                    pass
            results[host] = info
    except ImportError:
        logger.warning("python-nmap not available")
    except Exception as e:
        logger.error(f"nmap scan error: {e}")
    return results


def resolve_hostname(ip: str) -> str:
    """Try reverse DNS lookup."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ''


class NetworkScanner:
    def __init__(self, interface: str = ''):
        from config import Config
        self.interface = interface or Config.NETWORK_INTERFACE or get_default_interface()
        self.network = get_network_cidr(self.interface)
        logger.info(f"NetworkScanner ready: iface={self.interface}, network={self.network}")

    def scan(self, deep: bool = False) -> list[dict]:
        """
        Perform a full scan. Returns list of device dicts.
        deep=True runs OS detection (slow).
        """
        if not self.network:
            logger.error("Cannot determine network CIDR, skipping scan")
            return []

        from app.scanner.avahi import get_mdns_names
        from app.scanner.oui import lookup_vendor, is_random_mac

        logger.info(f"Scanning {self.network} on {self.interface} (deep={deep})")

        # Step 1: ARP scan for fast device discovery
        arp_devices = arp_scan(self.network, self.interface)
        logger.info(f"ARP scan found {len(arp_devices)} devices")

        # Step 2: mDNS names via avahi
        mdns_map = get_mdns_names()

        # Step 3: nmap for hostnames and OS (optional deep)
        nmap_results = nmap_scan(self.network, fast=not deep)

        devices = []
        for entry in arp_devices:
            ip = entry['ip']
            mac = entry['mac']

            vendor = lookup_vendor(mac)
            random_mac = is_random_mac(mac)

            hostname = ''
            os_name = ''
            os_conf = 0

            if ip in nmap_results:
                nmap_info = nmap_results[ip]
                hostname = nmap_info.get('hostname', '')
                os_name = nmap_info.get('os', '')
                os_conf = nmap_info.get('os_confidence', 0)

            if not hostname:
                hostname = resolve_hostname(ip)

            mdns_name = mdns_map.get(ip, '')

            devices.append({
                'ip': ip,
                'mac': mac,
                'vendor': vendor,
                'hostname': hostname,
                'mdns_name': mdns_name,
                'os_detected': os_name,
                'os_confidence': os_conf,
                'is_random_mac': random_mac,
            })

        return devices
