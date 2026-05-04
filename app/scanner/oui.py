import os
import re
import logging
import urllib.request

logger = logging.getLogger(__name__)

_oui_db: dict[str, str] = {}


def _oui_file_path() -> str:
    from config import Config
    return Config.OUI_FILE


def load_oui_database() -> None:
    path = _oui_file_path()
    if not os.path.exists(path):
        _download_oui(path)
    _parse_oui(path)
    logger.info(f"OUI database loaded: {len(_oui_db)} entries")


def _download_oui(path: str) -> None:
    url = "https://standards-oui.ieee.org/oui/oui.txt"
    logger.info("Downloading OUI database...")
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        urllib.request.urlretrieve(url, path)
        logger.info("OUI database downloaded.")
    except Exception as e:
        logger.warning(f"Could not download OUI database: {e}")
        # Create empty file so we don't retry on every scan
        open(path, 'w').close()


def _parse_oui(path: str) -> None:
    try:
        with open(path, 'r', errors='replace') as f:
            for line in f:
                m = re.match(r'^([0-9A-Fa-f]{2}-[0-9A-Fa-f]{2}-[0-9A-Fa-f]{2})\s+\(hex\)\s+(.+)', line)
                if m:
                    prefix = m.group(1).replace('-', ':').upper()
                    vendor = m.group(2).strip()
                    _oui_db[prefix] = vendor
    except Exception as e:
        logger.error(f"Error parsing OUI file: {e}")


def lookup_vendor(mac: str) -> str:
    if not _oui_db:
        load_oui_database()
    prefix = mac.upper()[:8]
    return _oui_db.get(prefix, 'Unknown')


def is_random_mac(mac: str) -> bool:
    """
    Detect locally administered (randomized) MAC addresses.
    The second-least-significant bit of the first octet being set = locally administered.
    """
    try:
        first_byte = int(mac.split(':')[0], 16)
        return bool(first_byte & 0x02)
    except Exception:
        return False
