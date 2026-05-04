import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'wifidetect-secret-2024')
    SQLALCHEMY_DATABASE_URI = f"sqlite:///{os.path.join(BASE_DIR, 'data', 'wifidetect.db')}"
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Scan interval in minutes
    SCAN_INTERVAL = int(os.environ.get('SCAN_INTERVAL', 3))

    # Network interface (auto-detect if empty)
    NETWORK_INTERFACE = os.environ.get('NETWORK_INTERFACE', '')

    # Alert on new device
    ALERT_NEW_DEVICES = True

    # Port scan detection threshold (connections per minute)
    PORT_SCAN_THRESHOLD = 20

    DATA_DIR = os.path.join(BASE_DIR, 'data')
    OUI_FILE = os.path.join(DATA_DIR, 'oui.txt')
    LOG_FILE = os.path.join(DATA_DIR, 'wifidetect.log')
