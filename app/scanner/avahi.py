import subprocess
import re
import logging

logger = logging.getLogger(__name__)


def get_mdns_names() -> dict[str, str]:
    """
    Returns a dict mapping IP -> mDNS name using avahi-browse.
    Falls back to an empty dict if avahi is not available.
    """
    result: dict[str, str] = {}
    try:
        out = subprocess.check_output(
            ['avahi-browse', '-a', '-t', '-r', '-p'],
            stderr=subprocess.DEVNULL,
            timeout=10,
            text=True
        )
        # Format: =;iface;proto;name;type;domain;hostname;address;port;txt
        for line in out.splitlines():
            if not line.startswith('='):
                continue
            parts = line.split(';')
            if len(parts) < 9:
                continue
            friendly_name = parts[3].strip()
            ip = parts[7].strip()
            # Skip IPv6 addresses
            if ':' in ip:
                continue
            if ip and friendly_name:
                result[ip] = friendly_name
    except FileNotFoundError:
        logger.debug("avahi-browse not found, skipping mDNS discovery")
    except subprocess.TimeoutExpired:
        logger.debug("avahi-browse timed out")
    except Exception as e:
        logger.debug(f"avahi-browse error: {e}")
    return result
