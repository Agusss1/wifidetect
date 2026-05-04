import subprocess
import logging

logger = logging.getLogger(__name__)


def _run(cmd: list[str]) -> tuple[bool, str]:
    try:
        r = subprocess.run(cmd, check=True, capture_output=True, text=True)
        return True, r.stdout
    except subprocess.CalledProcessError as e:
        return False, e.stderr


class BandwidthManager:
    def __init__(self, interface: str):
        self.iface = interface
        self._setup_root_qdisc()

    def _setup_root_qdisc(self):
        """Set up HTB root qdisc on the interface."""
        # Delete existing and recreate
        subprocess.run(['tc', 'qdisc', 'del', 'dev', self.iface, 'root'],
                       capture_output=True)
        ok, err = _run(['tc', 'qdisc', 'add', 'dev', self.iface,
                        'root', 'handle', '1:', 'htb', 'default', '999'])
        if ok:
            # Default class: unlimited
            _run(['tc', 'class', 'add', 'dev', self.iface,
                  'parent', '1:', 'classid', '1:999',
                  'htb', 'rate', '1000mbit'])
            logger.info(f"TC root qdisc ready on {self.iface}")
        else:
            logger.warning(f"Could not setup TC qdisc: {err}")

    def _ip_to_classid(self, ip: str) -> str:
        """Convert last two octets of IP to a classid like 1:XXYY"""
        parts = ip.split('.')
        return f"1:{int(parts[2]):02x}{int(parts[3]):02x}"

    def set_limit(self, ip: str, kbps: int) -> bool:
        """Apply a download+upload bandwidth limit in kbps to an IP."""
        classid = self._ip_to_classid(ip)
        rate = f"{kbps}kbit"

        # Remove existing class if any
        self.remove_limit(ip)

        # Add class
        ok, err = _run(['tc', 'class', 'add', 'dev', self.iface,
                        'parent', '1:', 'classid', classid,
                        'htb', 'rate', rate, 'ceil', rate])
        if not ok:
            logger.error(f"TC class add failed for {ip}: {err}")
            return False

        # Add filter to match IP
        ok, err = _run(['tc', 'filter', 'add', 'dev', self.iface,
                        'protocol', 'ip', 'parent', '1:',
                        'prio', '1', 'u32',
                        'match', 'ip', 'src', ip,
                        'flowid', classid])
        if not ok:
            logger.error(f"TC filter add failed for {ip}: {err}")
            return False

        logger.info(f"Bandwidth limit {kbps}kbps applied to {ip}")
        return True

    def remove_limit(self, ip: str) -> bool:
        classid = self._ip_to_classid(ip)
        subprocess.run(['tc', 'class', 'del', 'dev', self.iface,
                        'classid', classid], capture_output=True)
        return True

    def get_stats(self, ip: str) -> dict:
        classid = self._ip_to_classid(ip)
        ok, out = _run(['tc', 'class', 'show', 'dev', self.iface,
                        'classid', classid])
        return {'raw': out if ok else ''}
