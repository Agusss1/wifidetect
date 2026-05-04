import subprocess
import logging

logger = logging.getLogger(__name__)

CHAIN = 'WIFIDETECT'


def _run(cmd: list[str]) -> bool:
    try:
        subprocess.run(cmd, check=True, capture_output=True)
        return True
    except subprocess.CalledProcessError as e:
        logger.error(f"iptables error: {e.stderr.decode().strip()}")
        return False


class FirewallManager:
    def __init__(self):
        self._ensure_chain()

    def _ensure_chain(self):
        # Create custom chain if it doesn't exist
        r = subprocess.run(['iptables', '-L', CHAIN], capture_output=True)
        if r.returncode != 0:
            _run(['iptables', '-N', CHAIN])
            # Jump to our chain from FORWARD
            _run(['iptables', '-I', 'FORWARD', '-j', CHAIN])
            # Also from INPUT for local traffic
            _run(['iptables', '-I', 'INPUT', '-j', CHAIN])
        logger.info(f"iptables chain '{CHAIN}' ready")

    def block_ip(self, ip: str) -> bool:
        """Block all traffic from IP."""
        logger.info(f"Blocking {ip}")
        # Remove any existing rule first to avoid duplicates
        self.unblock_ip(ip)
        ok1 = _run(['iptables', '-A', CHAIN, '-s', ip, '-j', 'DROP'])
        ok2 = _run(['iptables', '-A', CHAIN, '-d', ip, '-j', 'DROP'])
        return ok1 and ok2

    def unblock_ip(self, ip: str) -> bool:
        """Remove block rules for IP."""
        logger.info(f"Unblocking {ip}")
        # Run multiple times to clear duplicates, ignore errors
        for _ in range(3):
            subprocess.run(['iptables', '-D', CHAIN, '-s', ip, '-j', 'DROP'], capture_output=True)
            subprocess.run(['iptables', '-D', CHAIN, '-d', ip, '-j', 'DROP'], capture_output=True)
        return True

    def is_blocked(self, ip: str) -> bool:
        try:
            r = subprocess.run(
                ['iptables', '-L', CHAIN, '-n'],
                capture_output=True, text=True
            )
            return ip in r.stdout
        except Exception:
            return False

    def flush_chain(self):
        """Remove all rules from our chain."""
        _run(['iptables', '-F', CHAIN])

    def get_blocked_ips(self) -> list[str]:
        """Return list of currently blocked IPs."""
        blocked = []
        try:
            r = subprocess.run(
                ['iptables', '-L', CHAIN, '-n'],
                capture_output=True, text=True
            )
            import re
            for line in r.stdout.splitlines():
                if 'DROP' in line:
                    m = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                    if m:
                        ip = m.group(1)
                        if ip not in blocked:
                            blocked.append(ip)
        except Exception as e:
            logger.error(f"Error getting blocked IPs: {e}")
        return blocked
