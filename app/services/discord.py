"""
Discord webhook integration for WiFiDetect.
All public functions are fire-and-forget: they return True on success,
False on failure, and never raise.
"""

import logging
from datetime import datetime, timezone

import requests

logger = logging.getLogger(__name__)

_TIMEOUT = 6

# Embed colours (decimal)
_COL_NEW        = 0x3B82F6   # blue
_COL_SUSPICIOUS = 0xF59E0B   # amber
_COL_BLOCKED    = 0xEF4444   # red
_COL_UNBLOCKED  = 0x22C55E   # green
_COL_PORT_SCAN  = 0xDC2626   # dark red
_COL_SUMMARY    = 0x6366F1   # indigo


# ---------- internal helpers ----------

def _cfg():
    from app.models import AppConfig
    return (
        AppConfig.get('discord_webhook_url', ''),
        AppConfig.get('discord_enabled', 'false') == 'true',
    )


def _post(payload: dict) -> bool:
    url, enabled = _cfg()
    if not enabled or not url:
        return False
    try:
        r = requests.post(url, json=payload, timeout=_TIMEOUT)
        if r.status_code == 204:
            return True
        r.raise_for_status()
        return True
    except requests.exceptions.RequestException as e:
        logger.error(f"Discord webhook failed: {e}")
        return False


def _ts() -> str:
    return datetime.now(timezone.utc).isoformat()


def _embed(title: str, colour: int, fields: list[dict], description: str = '') -> dict:
    e: dict = {
        'title': title,
        'color': colour,
        'fields': fields,
        'footer': {'text': 'WiFiDetect'},
        'timestamp': _ts(),
    }
    if description:
        e['description'] = description
    return {'embeds': [e]}


def _device_fields(device) -> list[dict]:
    fields = [
        {'name': 'IP',         'value': device.ip or '—',               'inline': True},
        {'name': 'MAC',        'value': f'`{device.mac}`',               'inline': True},
        {'name': 'Fabricante', 'value': device.vendor or 'Desconocido', 'inline': True},
    ]
    if device.os_detected:
        fields.append({'name': 'Sistema operativo',
                       'value': f'{device.os_detected} ({device.os_confidence}%)',
                       'inline': True})
    if device.hostname or device.mdns_name:
        fields.append({'name': 'Nombre de host',
                       'value': device.mdns_name or device.hostname,
                       'inline': True})
    return fields


# ---------- public API ----------

def send_new_device(device) -> bool:
    name = device.display_name
    payload = _embed(
        title=f'🔌 Nuevo dispositivo: {name}',
        colour=_COL_NEW,
        fields=_device_fields(device),
    )
    return _post(payload)


def send_suspicious(device) -> bool:
    name = device.display_name
    payload = _embed(
        title=f'⚠️ Dispositivo sospechoso: {name}',
        colour=_COL_SUSPICIOUS,
        description='MAC address aleatoria/randomizada detectada.',
        fields=_device_fields(device),
    )
    return _post(payload)


def send_blocked(device) -> bool:
    payload = _embed(
        title=f'🔒 Dispositivo bloqueado: {device.display_name}',
        colour=_COL_BLOCKED,
        fields=_device_fields(device),
    )
    return _post(payload)


def send_unblocked(device) -> bool:
    payload = _embed(
        title=f'🔓 Dispositivo desbloqueado: {device.display_name}',
        colour=_COL_UNBLOCKED,
        fields=_device_fields(device),
    )
    return _post(payload)


def send_port_scan(ip: str, name: str, count: int) -> bool:
    payload = _embed(
        title='🚨 Posible port scan detectado',
        colour=_COL_PORT_SCAN,
        description=f'Se detectaron **{count}** paquetes SYN/min desde este dispositivo.',
        fields=[
            {'name': 'Dispositivo', 'value': name,  'inline': True},
            {'name': 'IP',          'value': ip,    'inline': True},
        ],
    )
    return _post(payload)


def send_daily_summary(app) -> bool:
    with app.app_context():
        from app.models import Device
        from app.services.discord import _cfg, _post, _embed, _COL_SUMMARY

        url, enabled = _cfg()
        if not enabled or not url:
            return False

        devices = Device.query.all()
        online   = [d for d in devices if d.is_online]
        blocked  = [d for d in devices if d.is_blocked]
        unknown  = [d for d in devices if not d.is_known and not d.is_blocked and d.is_online]
        suspicious = [d for d in devices if d.is_random_mac and not d.is_known and d.is_online]

        def _list(devs, limit=10):
            lines = [f'• {d.display_name} — `{d.ip}`' for d in devs[:limit]]
            if len(devs) > limit:
                lines.append(f'_...y {len(devs) - limit} más_')
            return '\n'.join(lines) or '_Ninguno_'

        fields = [
            {'name': f'📶 En línea ({len(online)})',      'value': _list(online),     'inline': False},
            {'name': f'❓ Sin clasificar ({len(unknown)})', 'value': _list(unknown),    'inline': False},
        ]
        if blocked:
            fields.append({'name': f'🔒 Bloqueados ({len(blocked)})', 'value': _list(blocked), 'inline': False})
        if suspicious:
            fields.append({'name': f'⚠️ Sospechosos ({len(suspicious)})', 'value': _list(suspicious), 'inline': False})

        payload = _embed(
            title='📊 Resumen diario de red — WiFiDetect',
            colour=_COL_SUMMARY,
            description=f'**{len(online)}** dispositivos activos de {len(devices)} registrados.',
            fields=fields,
        )
        return _post(payload)


def test_webhook(url: str) -> bool:
    """Send a test message to a specific URL without checking DB config."""
    payload = _embed(
        title='✅ Webhook de prueba — WiFiDetect',
        colour=_COL_UNBLOCKED,
        description='La integración con Discord está funcionando correctamente.',
        fields=[{'name': 'Estado', 'value': 'Conexión exitosa', 'inline': True}],
    )
    try:
        r = requests.post(url, json=payload, timeout=_TIMEOUT)
        return r.status_code in (200, 204)
    except Exception as e:
        logger.error(f"Discord test failed: {e}")
        return False
