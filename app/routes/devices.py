from flask import Blueprint, render_template, redirect, url_for, request, flash
from app.models import Device, ScheduledBlock
from app import db

devices_bp = Blueprint('devices', __name__)


@devices_bp.route('/')
def list_devices():
    devices = Device.query.order_by(Device.is_online.desc(), Device.last_seen.desc()).all()
    return render_template('devices.html', devices=devices)


@devices_bp.route('/<int:device_id>')
def device_detail(device_id):
    device = Device.query.get_or_404(device_id)
    return render_template('device_detail.html', device=device)
