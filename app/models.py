from datetime import datetime
from app import db


class Device(db.Model):
    __tablename__ = 'devices'

    id = db.Column(db.Integer, primary_key=True)
    mac = db.Column(db.String(17), unique=True, nullable=False, index=True)
    ip = db.Column(db.String(15))
    custom_name = db.Column(db.String(100))
    hostname = db.Column(db.String(200))
    mdns_name = db.Column(db.String(200))
    vendor = db.Column(db.String(200))
    os_detected = db.Column(db.String(200))
    os_confidence = db.Column(db.Integer, default=0)

    is_known = db.Column(db.Boolean, default=False)
    is_blocked = db.Column(db.Boolean, default=False)
    is_random_mac = db.Column(db.Boolean, default=False)

    # Bandwidth limit in kbps (0 = no limit)
    bandwidth_limit = db.Column(db.Integer, default=0)

    first_seen = db.Column(db.DateTime, default=datetime.utcnow)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    is_online = db.Column(db.Boolean, default=True)

    scheduled_blocks = db.relationship('ScheduledBlock', back_populates='device', cascade='all, delete-orphan')
    sessions = db.relationship('DeviceSession', back_populates='device', cascade='all, delete-orphan')

    @property
    def display_name(self):
        return self.custom_name or self.mdns_name or self.hostname or self.mac

    @property
    def status(self):
        if self.is_blocked:
            return 'blocked'
        if self.is_random_mac and not self.is_known:
            return 'suspicious'
        if not self.is_known:
            return 'unknown'
        return 'known'

    def to_dict(self):
        return {
            'id': self.id,
            'mac': self.mac,
            'ip': self.ip,
            'display_name': self.display_name,
            'custom_name': self.custom_name,
            'hostname': self.hostname,
            'mdns_name': self.mdns_name,
            'vendor': self.vendor,
            'os_detected': self.os_detected,
            'os_confidence': self.os_confidence,
            'is_known': self.is_known,
            'is_blocked': self.is_blocked,
            'is_random_mac': self.is_random_mac,
            'is_online': self.is_online,
            'bandwidth_limit': self.bandwidth_limit,
            'status': self.status,
            'first_seen': self.first_seen.isoformat() if self.first_seen else None,
            'last_seen': self.last_seen.isoformat() if self.last_seen else None,
        }


class DeviceSession(db.Model):
    __tablename__ = 'device_sessions'

    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.Integer, db.ForeignKey('devices.id'), nullable=False)
    ip = db.Column(db.String(15))
    connected_at = db.Column(db.DateTime, default=datetime.utcnow)
    disconnected_at = db.Column(db.DateTime)

    device = db.relationship('Device', back_populates='sessions')

    @property
    def duration_seconds(self):
        end = self.disconnected_at or datetime.utcnow()
        return int((end - self.connected_at).total_seconds())

    def to_dict(self):
        return {
            'id': self.id,
            'device_id': self.device_id,
            'device_name': self.device.display_name if self.device else 'Unknown',
            'mac': self.device.mac if self.device else '',
            'ip': self.ip,
            'connected_at': self.connected_at.isoformat() if self.connected_at else None,
            'disconnected_at': self.disconnected_at.isoformat() if self.disconnected_at else None,
            'duration_seconds': self.duration_seconds,
        }


class ScheduledBlock(db.Model):
    __tablename__ = 'scheduled_blocks'

    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.Integer, db.ForeignKey('devices.id'), nullable=False)
    start_hour = db.Column(db.Integer, nullable=False)   # 0-23
    start_minute = db.Column(db.Integer, default=0)
    end_hour = db.Column(db.Integer, nullable=False)
    end_minute = db.Column(db.Integer, default=0)
    days = db.Column(db.String(20), default='0,1,2,3,4,5,6')  # weekdays (0=Mon)
    is_active = db.Column(db.Boolean, default=True)

    device = db.relationship('Device', back_populates='scheduled_blocks')

    def to_dict(self):
        return {
            'id': self.id,
            'device_id': self.device_id,
            'start_hour': self.start_hour,
            'start_minute': self.start_minute,
            'end_hour': self.end_hour,
            'end_minute': self.end_minute,
            'days': self.days,
            'is_active': self.is_active,
        }


class Alert(db.Model):
    __tablename__ = 'alerts'

    id = db.Column(db.Integer, primary_key=True)
    type = db.Column(db.String(50))   # new_device, port_scan, blocked_attempt
    message = db.Column(db.String(500))
    device_mac = db.Column(db.String(17))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_read = db.Column(db.Boolean, default=False)

    def to_dict(self):
        return {
            'id': self.id,
            'type': self.type,
            'message': self.message,
            'device_mac': self.device_mac,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'is_read': self.is_read,
        }


class AppConfig(db.Model):
    __tablename__ = 'app_config'

    key = db.Column(db.String(100), primary_key=True)
    value = db.Column(db.String(500))

    @classmethod
    def get(cls, key, default=None):
        row = cls.query.get(key)
        return row.value if row else default

    @classmethod
    def set(cls, key, value):
        row = cls.query.get(key)
        if row:
            row.value = str(value)
        else:
            db.session.add(cls(key=key, value=str(value)))
        db.session.commit()
