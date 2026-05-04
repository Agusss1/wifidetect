from flask import Blueprint, render_template
from app.models import Device, Alert, DeviceSession
from app import db
from datetime import datetime, timedelta

dashboard_bp = Blueprint('dashboard', __name__)


@dashboard_bp.route('/')
def index():
    devices = Device.query.all()
    total = len(devices)
    online = sum(1 for d in devices if d.is_online)
    known = sum(1 for d in devices if d.is_known)
    blocked = sum(1 for d in devices if d.is_blocked)
    unknown = sum(1 for d in devices if not d.is_known and not d.is_blocked)
    suspicious = sum(1 for d in devices if d.is_random_mac and not d.is_known)

    unread_alerts = Alert.query.filter_by(is_read=False).count()

    return render_template('dashboard.html',
                           total=total,
                           online=online,
                           known=known,
                           blocked=blocked,
                           unknown=unknown,
                           suspicious=suspicious,
                           unread_alerts=unread_alerts)
