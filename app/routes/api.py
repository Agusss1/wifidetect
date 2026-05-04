import csv
import io
from datetime import datetime, timedelta
from flask import Blueprint, jsonify, request, Response, current_app

from app import db
from app.models import Device, DeviceSession, Alert, ScheduledBlock, AppConfig, ExcludedMAC

api_bp = Blueprint('api', __name__)


# ---------- Devices ----------

@api_bp.route('/devices')
def get_devices():
    excluded = {e.mac.lower() for e in ExcludedMAC.query.all()}
    devices = Device.query.order_by(Device.is_online.desc(), Device.last_seen.desc()).all()
    return jsonify([d.to_dict() for d in devices if d.mac.lower() not in excluded])


@api_bp.route('/devices/<int:device_id>', methods=['GET'])
def get_device(device_id):
    device = Device.query.get_or_404(device_id)
    return jsonify(device.to_dict())


@api_bp.route('/devices/<int:device_id>', methods=['PATCH'])
def update_device(device_id):
    device = Device.query.get_or_404(device_id)
    data = request.get_json()

    if 'custom_name' in data:
        device.custom_name = data['custom_name']
    if 'is_known' in data:
        device.is_known = bool(data['is_known'])
    if 'bandwidth_limit' in data:
        device.bandwidth_limit = int(data['bandwidth_limit'])
        _apply_bandwidth(device)

    db.session.commit()
    return jsonify(device.to_dict())


@api_bp.route('/devices/<int:device_id>/block', methods=['POST'])
def block_device(device_id):
    import threading
    import app.services.discord as discord
    device = Device.query.get_or_404(device_id)
    fw = _get_firewall()
    if device.ip:
        fw.block_ip(device.ip)
    device.is_blocked = True
    db.session.commit()
    threading.Thread(target=discord.send_blocked, args=(device,), daemon=True).start()
    return jsonify({'status': 'blocked', 'device': device.to_dict()})


@api_bp.route('/devices/<int:device_id>/unblock', methods=['POST'])
def unblock_device(device_id):
    import threading
    import app.services.discord as discord
    device = Device.query.get_or_404(device_id)
    fw = _get_firewall()
    if device.ip:
        fw.unblock_ip(device.ip)
    device.is_blocked = False
    db.session.commit()
    threading.Thread(target=discord.send_unblocked, args=(device,), daemon=True).start()
    return jsonify({'status': 'unblocked', 'device': device.to_dict()})


@api_bp.route('/devices/<int:device_id>/bandwidth', methods=['POST'])
def set_bandwidth(device_id):
    device = Device.query.get_or_404(device_id)
    data = request.get_json()
    kbps = int(data.get('kbps', 0))
    device.bandwidth_limit = kbps
    db.session.commit()
    _apply_bandwidth(device)
    return jsonify({'status': 'ok', 'kbps': kbps})


# ---------- Scheduled blocks ----------

@api_bp.route('/devices/<int:device_id>/schedules', methods=['GET'])
def get_schedules(device_id):
    device = Device.query.get_or_404(device_id)
    return jsonify([s.to_dict() for s in device.scheduled_blocks])


@api_bp.route('/devices/<int:device_id>/schedules', methods=['POST'])
def add_schedule(device_id):
    Device.query.get_or_404(device_id)
    data = request.get_json()
    block = ScheduledBlock(
        device_id=device_id,
        start_hour=int(data['start_hour']),
        start_minute=int(data.get('start_minute', 0)),
        end_hour=int(data['end_hour']),
        end_minute=int(data.get('end_minute', 0)),
        days=data.get('days', '0,1,2,3,4,5,6'),
    )
    db.session.add(block)
    db.session.commit()
    return jsonify(block.to_dict()), 201


@api_bp.route('/schedules/<int:schedule_id>', methods=['DELETE'])
def delete_schedule(schedule_id):
    block = ScheduledBlock.query.get_or_404(schedule_id)
    db.session.delete(block)
    db.session.commit()
    return jsonify({'status': 'deleted'})


# ---------- History ----------

@api_bp.route('/history')
def get_history():
    days = int(request.args.get('days', 7))
    since = datetime.utcnow() - timedelta(days=days)
    sessions = DeviceSession.query.filter(
        DeviceSession.connected_at >= since
    ).order_by(DeviceSession.connected_at.desc()).limit(500).all()
    return jsonify([s.to_dict() for s in sessions])


@api_bp.route('/history/device/<int:device_id>')
def device_history(device_id):
    sessions = DeviceSession.query.filter_by(device_id=device_id)\
        .order_by(DeviceSession.connected_at.desc()).limit(100).all()
    return jsonify([s.to_dict() for s in sessions])


# ---------- Alerts ----------

@api_bp.route('/alerts')
def get_alerts():
    limit = int(request.args.get('limit', 50))
    alerts = Alert.query.order_by(Alert.created_at.desc()).limit(limit).all()
    return jsonify([a.to_dict() for a in alerts])


@api_bp.route('/alerts/read', methods=['POST'])
def mark_alerts_read():
    Alert.query.filter_by(is_read=False).update({'is_read': True})
    db.session.commit()
    return jsonify({'status': 'ok'})


@api_bp.route('/alerts/unread_count')
def unread_alerts_count():
    count = Alert.query.filter_by(is_read=False).count()
    return jsonify({'count': count})


# ---------- Stats for charts ----------

@api_bp.route('/stats/hourly')
def hourly_stats():
    """Return device count by hour for the last 24h."""
    from sqlalchemy import func
    now = datetime.utcnow()
    since = now - timedelta(hours=24)
    rows = db.session.query(
        func.strftime('%H', DeviceSession.connected_at).label('hour'),
        func.count(DeviceSession.id).label('count')
    ).filter(DeviceSession.connected_at >= since)\
     .group_by('hour').all()
    return jsonify([{'hour': r.hour, 'count': r.count} for r in rows])


@api_bp.route('/stats/devices')
def device_stats():
    excluded = {e.mac.lower() for e in ExcludedMAC.query.all()}
    devices = [d for d in Device.query.all() if d.mac.lower() not in excluded]
    return jsonify({
        'total': len(devices),
        'online': sum(1 for d in devices if d.is_online),
        'known': sum(1 for d in devices if d.is_known),
        'blocked': sum(1 for d in devices if d.is_blocked),
        'unknown': sum(1 for d in devices if not d.is_known and not d.is_blocked and d.is_online),
        'suspicious': sum(1 for d in devices if d.is_random_mac and not d.is_known),
    })


# ---------- Export ----------

@api_bp.route('/export/csv')
def export_csv():
    days = int(request.args.get('days', 30))
    since = datetime.utcnow() - timedelta(days=days)
    sessions = DeviceSession.query.filter(
        DeviceSession.connected_at >= since
    ).order_by(DeviceSession.connected_at.desc()).all()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Device', 'MAC', 'IP', 'Connected At', 'Disconnected At', 'Duration (min)'])
    for s in sessions:
        writer.writerow([
            s.device.display_name if s.device else 'Unknown',
            s.device.mac if s.device else '',
            s.ip,
            s.connected_at.strftime('%Y-%m-%d %H:%M:%S') if s.connected_at else '',
            s.disconnected_at.strftime('%Y-%m-%d %H:%M:%S') if s.disconnected_at else 'Online',
            round(s.duration_seconds / 60, 1),
        ])

    output.seek(0)
    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': f'attachment; filename=wifidetect_{datetime.now().strftime("%Y%m%d")}.csv'}
    )


@api_bp.route('/export/pdf')
def export_pdf():
    from reportlab.lib.pagesizes import A4, landscape
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib import colors
    import io as bio

    days = int(request.args.get('days', 30))
    since = datetime.utcnow() - timedelta(days=days)
    sessions = DeviceSession.query.filter(
        DeviceSession.connected_at >= since
    ).order_by(DeviceSession.connected_at.desc()).limit(200).all()

    buf = bio.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=landscape(A4))
    styles = getSampleStyleSheet()
    elements = []

    elements.append(Paragraph('WiFiDetect - Reporte de conexiones', styles['Title']))
    elements.append(Paragraph(f'Período: últimos {days} días', styles['Normal']))
    elements.append(Spacer(1, 12))

    data = [['Dispositivo', 'MAC', 'IP', 'Conectado', 'Desconectado', 'Duración (min)']]
    for s in sessions:
        data.append([
            s.device.display_name if s.device else 'Unknown',
            s.device.mac if s.device else '',
            s.ip or '',
            s.connected_at.strftime('%d/%m/%Y %H:%M') if s.connected_at else '',
            s.disconnected_at.strftime('%d/%m/%Y %H:%M') if s.disconnected_at else 'Online',
            str(round(s.duration_seconds / 60, 1)),
        ])

    table = Table(data, repeatRows=1)
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1a73e8')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 8),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8f9fa')]),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('PADDING', (0, 0), (-1, -1), 4),
    ]))
    elements.append(table)
    doc.build(elements)

    buf.seek(0)
    return Response(
        buf.getvalue(),
        mimetype='application/pdf',
        headers={'Content-Disposition': f'attachment; filename=wifidetect_{datetime.now().strftime("%Y%m%d")}.pdf'}
    )


# ---------- Config ----------

@api_bp.route('/config', methods=['GET'])
def get_config():
    from config import Config
    return jsonify({
        'scan_interval': int(AppConfig.get('scan_interval', Config.SCAN_INTERVAL)),
        'alert_new_devices': AppConfig.get('alert_new_devices', 'true') == 'true',
    })


@api_bp.route('/config', methods=['POST'])
def set_config():
    data = request.get_json()
    if 'scan_interval' in data:
        AppConfig.set('scan_interval', int(data['scan_interval']))
    if 'alert_new_devices' in data:
        AppConfig.set('alert_new_devices', str(data['alert_new_devices']).lower())
    return jsonify({'status': 'ok'})


@api_bp.route('/scan/trigger', methods=['POST'])
def trigger_scan():
    """Manually trigger a scan."""
    from app.monitor import DeviceMonitor
    monitor = current_app.extensions.get('monitor')
    if monitor:
        import threading
        deep = request.get_json(silent=True, force=True) or {}
        t = threading.Thread(target=monitor.run_scan, kwargs={'deep': deep.get('deep', False)})
        t.daemon = True
        t.start()
        return jsonify({'status': 'scan started'})
    return jsonify({'status': 'monitor not ready'}), 503


# ---------- Discord ----------

@api_bp.route('/discord/config', methods=['GET'])
def get_discord_config():
    return jsonify({
        'webhook_url': AppConfig.get('discord_webhook_url', ''),
        'enabled': AppConfig.get('discord_enabled', 'false') == 'true',
    })


@api_bp.route('/discord/config', methods=['POST'])
def set_discord_config():
    data = request.get_json()
    if 'webhook_url' in data:
        AppConfig.set('discord_webhook_url', data['webhook_url'].strip())
    if 'enabled' in data:
        AppConfig.set('discord_enabled', 'true' if data['enabled'] else 'false')
    return jsonify({'status': 'ok'})


@api_bp.route('/discord/test', methods=['POST'])
def test_discord():
    from app.services.discord import test_webhook
    data = request.get_json() or {}
    url = data.get('url') or AppConfig.get('discord_webhook_url', '')
    if not url:
        return jsonify({'ok': False, 'error': 'No hay URL configurada'}), 400
    ok = test_webhook(url)
    return jsonify({'ok': ok})


# ---------- Excluded MACs (modo invisible) ----------

@api_bp.route('/excluded-macs', methods=['GET'])
def get_excluded_macs():
    rows = ExcludedMAC.query.order_by(ExcludedMAC.added_at.desc()).all()
    return jsonify([r.to_dict() for r in rows])


@api_bp.route('/excluded-macs', methods=['POST'])
def add_excluded_mac():
    data = request.get_json()
    mac = data.get('mac', '').strip().lower()
    label = data.get('label', '').strip()
    if not mac:
        return jsonify({'error': 'MAC requerida'}), 400
    existing = ExcludedMAC.query.get(mac)
    if existing:
        existing.label = label
    else:
        db.session.add(ExcludedMAC(mac=mac, label=label))
    db.session.commit()
    return jsonify({'status': 'ok', 'mac': mac}), 201


@api_bp.route('/excluded-macs/<path:mac>', methods=['DELETE'])
def delete_excluded_mac(mac):
    row = ExcludedMAC.query.get(mac.lower())
    if row:
        db.session.delete(row)
        db.session.commit()
    return jsonify({'status': 'deleted'})


# ---------- Helpers ----------

def _get_firewall():
    from flask import current_app
    return current_app.extensions['firewall']


def _apply_bandwidth(device: Device):
    from flask import current_app
    bw = current_app.extensions.get('bandwidth')
    if bw and device.ip:
        if device.bandwidth_limit > 0:
            bw.set_limit(device.ip, device.bandwidth_limit)
        else:
            bw.remove_limit(device.ip)
