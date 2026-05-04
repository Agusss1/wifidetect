'use strict';

// ---- Socket.IO ----
const socket = io();
let allDevices = [];

socket.on('connect', () => console.log('Socket connected'));
socket.on('devices_list', (devices) => {
  allDevices = devices;
  renderDeviceTable(devices);
  updateStats(devices);
});
socket.on('new_device', (device) => {
  showToast(`Nuevo dispositivo: ${device.display_name} (${device.ip})`, 'success');
  fetchDevices();
  refreshAlerts();
});
socket.on('device_offline', () => fetchDevices());
socket.on('device_update', () => fetchDevices());
socket.on('alert', (data) => {
  showToast(data.message, data.type === 'port_scan' ? 'error' : 'success');
  refreshAlerts();
});

// ---- Fetch helpers ----
async function apiFetch(url, opts = {}) {
  const res = await fetch(url, { headers: {'Content-Type': 'application/json'}, ...opts });
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}

async function fetchDevices() {
  try {
    allDevices = await apiFetch('/api/devices');
    renderDeviceTable(allDevices);
    updateStats(allDevices);
  } catch(e) { console.error('fetchDevices:', e); }
}

// ---- Device table rendering ----
function statusDot(status) {
  const map = { known: 'dot-known', unknown: 'dot-unknown', blocked: 'dot-blocked', suspicious: 'dot-suspicious' };
  const labels = { known: 'Conocido', unknown: 'Sin clasificar', blocked: 'Bloqueado', suspicious: 'Sospechoso' };
  return `<span class="status-dot ${map[status] || 'dot-offline'}" title="${labels[status] || status}"></span>${labels[status] || status}`;
}

function timeAgo(isoStr) {
  if (!isoStr) return '—';
  const diff = Date.now() - new Date(isoStr + 'Z').getTime();
  const s = Math.floor(diff / 1000);
  if (s < 60) return 'hace ' + s + 's';
  const m = Math.floor(s / 60);
  if (m < 60) return 'hace ' + m + 'm';
  const h = Math.floor(m / 60);
  if (h < 24) return 'hace ' + h + 'h';
  return 'hace ' + Math.floor(h/24) + 'd';
}

function renderDeviceTable(devices) {
  const tbody = document.getElementById('deviceTableBody');
  if (!tbody) return;

  const filter = (document.getElementById('filterInput') || {}).value?.toLowerCase() || '';
  const statusFilter = (document.getElementById('filterStatus') || {}).value || '';

  let filtered = devices.filter(d => {
    const text = [d.display_name, d.ip, d.mac, d.vendor, d.hostname, d.mdns_name].join(' ').toLowerCase();
    const matchText = !filter || text.includes(filter);
    const matchStatus = !statusFilter || d.status === statusFilter;
    return matchText && matchStatus;
  });

  if (!filtered.length) {
    tbody.innerHTML = '<tr><td colspan="8" class="loading">No hay dispositivos</td></tr>';
    return;
  }

  tbody.innerHTML = filtered.map(d => `
    <tr class="row-${d.status}" data-id="${d.id}">
      <td>${statusDot(d.status)} ${d.is_online ? '' : '<small style="color:#555">(offline)</small>'}</td>
      <td>
        <strong>${esc(d.display_name)}</strong>
        ${d.is_random_mac ? '<span class="badge-tag badge-warning" style="margin-left:4px">MAC rand.</span>' : ''}
      </td>
      <td>${esc(d.ip || '—')}</td>
      <td style="font-family:monospace;font-size:0.8rem">${esc(d.mac)}</td>
      <td>${esc(d.vendor || '—')}</td>
      <td>${d.os_detected ? `${esc(d.os_detected)} <small style="color:var(--text-muted)">(${d.os_confidence}%)</small>` : '—'}</td>
      <td style="color:var(--text-muted)">${timeAgo(d.last_seen)}</td>
      <td>
        <div style="display:flex;gap:4px;flex-wrap:wrap">
          <button class="btn btn-sm btn-info" onclick="openDeviceModal(${d.id})">&#x270F;</button>
          ${d.is_blocked
            ? `<button class="btn btn-sm btn-success" onclick="unblockDevice(${d.id})">&#x1F513;</button>`
            : `<button class="btn btn-sm btn-danger" onclick="blockDevice(${d.id})">&#x1F512;</button>`}
          ${d.is_known
            ? `<button class="btn btn-sm btn-secondary" title="Quitar lista blanca" onclick="setKnown(${d.id},false)">&#x274C;</button>`
            : `<button class="btn btn-sm btn-success" title="Marcar como conocido" onclick="setKnown(${d.id},true)">&#x2705;</button>`}
        </div>
      </td>
    </tr>
  `).join('');
}

function filterDevices() {
  renderDeviceTable(allDevices);
}

// ---- Stats ----
function updateStats(devices) {
  const set = (id, val) => { const el = document.getElementById(id); if(el) el.textContent = val; };
  set('statTotal', devices.length);
  set('statOnline', devices.filter(d => d.is_online).length);
  set('statKnown', devices.filter(d => d.is_known).length);
  set('statUnknown', devices.filter(d => !d.is_known && !d.is_blocked && d.is_online).length);
  set('statBlocked', devices.filter(d => d.is_blocked).length);
  set('statSuspicious', devices.filter(d => d.is_random_mac && !d.is_known).length);
}

// ---- Charts ----
let statusChartInst = null;
let activityChartInst = null;

async function initCharts() {
  await renderStatusChart();
  await renderActivityChart();
}

async function renderStatusChart() {
  const el = document.getElementById('statusChart');
  if (!el) return;
  const stats = await apiFetch('/api/stats/devices');
  const data = {
    labels: ['Conocidos', 'Sin clasificar', 'Bloqueados', 'Sospechosos'],
    datasets: [{
      data: [stats.known, stats.unknown, stats.blocked, stats.suspicious],
      backgroundColor: ['#22c55e', '#f59e0b', '#ef4444', '#a855f7'],
      borderWidth: 0,
    }]
  };
  if (statusChartInst) statusChartInst.destroy();
  statusChartInst = new Chart(el, {
    type: 'doughnut',
    data,
    options: {
      plugins: { legend: { labels: { color: '#e2e8f0' } } },
      cutout: '65%',
    }
  });
}

async function renderActivityChart() {
  const el = document.getElementById('activityChart');
  if (!el) return;
  const rows = await apiFetch('/api/stats/hourly');
  const hours = Array.from({length: 24}, (_, i) => String(i).padStart(2,'0') + 'h');
  const counts = hours.map((_, i) => {
    const h = String(i).padStart(2, '0');
    const row = rows.find(r => r.hour === h);
    return row ? row.count : 0;
  });
  if (activityChartInst) activityChartInst.destroy();
  activityChartInst = new Chart(el, {
    type: 'bar',
    data: {
      labels: hours,
      datasets: [{ label: 'Conexiones', data: counts, backgroundColor: '#3b82f6', borderRadius: 4 }]
    },
    options: {
      plugins: { legend: { labels: { color: '#e2e8f0' } } },
      scales: {
        x: { ticks: { color: '#8892a4' }, grid: { color: '#2e3347' } },
        y: { ticks: { color: '#8892a4' }, grid: { color: '#2e3347' }, beginAtZero: true }
      }
    }
  });
}

// ---- Device actions ----
async function blockDevice(id) {
  try {
    await apiFetch(`/api/devices/${id}/block`, { method: 'POST' });
    showToast('Dispositivo bloqueado', 'success');
    fetchDevices();
  } catch(e) { showToast('Error al bloquear: ' + e.message, 'error'); }
}

async function unblockDevice(id) {
  try {
    await apiFetch(`/api/devices/${id}/unblock`, { method: 'POST' });
    showToast('Dispositivo desbloqueado', 'success');
    fetchDevices();
  } catch(e) { showToast('Error al desbloquear: ' + e.message, 'error'); }
}

async function setKnown(id, known) {
  try {
    await apiFetch(`/api/devices/${id}`, { method: 'PATCH', body: JSON.stringify({ is_known: known }) });
    showToast(known ? 'Marcado como conocido' : 'Removido de lista blanca', 'success');
    fetchDevices();
  } catch(e) { showToast('Error: ' + e.message, 'error'); }
}

// ---- Device edit modal ----
async function openDeviceModal(id) {
  const device = allDevices.find(d => d.id === id) || await apiFetch(`/api/devices/${id}`);
  const schedules = await apiFetch(`/api/devices/${id}/schedules`);

  document.getElementById('modalTitle').textContent = `Editar: ${device.display_name}`;
  document.getElementById('modalBody').innerHTML = `
    <div class="form-group">
      <label>Nombre personalizado</label>
      <input type="text" id="editName" value="${esc(device.custom_name || '')}" placeholder="Ej: Celu de Sofi">
    </div>
    <div class="form-group">
      <label>Límite de ancho de banda (kbps, 0 = sin límite)</label>
      <input type="number" id="editBw" value="${device.bandwidth_limit || 0}" min="0">
    </div>
    <div style="font-size:0.82rem;color:var(--text-muted);margin-bottom:12px">
      Ej: 512 = 512 kbps, 2048 = 2 Mbps, 0 = sin límite
    </div>

    <h4 style="margin-bottom:10px;font-size:0.9rem">Bloqueos programados</h4>
    <div class="schedule-list" id="scheduleList">
      ${schedules.map(s => `
        <div class="schedule-item" id="sch-${s.id}">
          <span>${formatSchedule(s)}</span>
          <button class="btn btn-sm btn-danger" onclick="deleteSchedule(${s.id})">✕</button>
        </div>
      `).join('') || '<div style="color:var(--text-muted);font-size:0.82rem">Sin horarios programados</div>'}
    </div>

    <details style="margin-bottom:12px">
      <summary style="cursor:pointer;font-size:0.85rem;color:var(--blue)">+ Agregar horario de bloqueo</summary>
      <div style="margin-top:12px">
        <div class="form-row">
          <div class="form-group">
            <label>Desde (hora)</label>
            <input type="number" id="schStart" min="0" max="23" value="23" placeholder="23">
          </div>
          <div class="form-group">
            <label>Hasta (hora)</label>
            <input type="number" id="schEnd" min="0" max="23" value="8" placeholder="8">
          </div>
        </div>
        <div class="form-group">
          <label>Días (0=Lun ... 6=Dom)</label>
          <input type="text" id="schDays" value="0,1,2,3,4,5,6" placeholder="0,1,2,3,4,5,6">
        </div>
        <button class="btn btn-primary" onclick="addSchedule(${id})">Agregar</button>
      </div>
    </details>

    <div class="form-actions">
      <button class="btn btn-secondary" onclick="closeModal()">Cancelar</button>
      <button class="btn btn-primary" onclick="saveDevice(${id})">Guardar</button>
    </div>
  `;
  openModal();
}

function formatSchedule(s) {
  const pad = n => String(n).padStart(2,'0');
  const days = ['Lun','Mar','Mié','Jue','Vie','Sáb','Dom'];
  const dayNames = s.days.split(',').map(d => days[parseInt(d)] || d).join(', ');
  return `${pad(s.start_hour)}:${pad(s.start_minute)}–${pad(s.end_hour)}:${pad(s.end_minute)} | ${dayNames}`;
}

async function saveDevice(id) {
  const name = document.getElementById('editName').value.trim();
  const bw = parseInt(document.getElementById('editBw').value) || 0;
  try {
    await apiFetch(`/api/devices/${id}`, {
      method: 'PATCH',
      body: JSON.stringify({ custom_name: name, bandwidth_limit: bw })
    });
    showToast('Guardado', 'success');
    closeModal();
    fetchDevices();
  } catch(e) { showToast('Error: ' + e.message, 'error'); }
}

async function addSchedule(deviceId) {
  const start = parseInt(document.getElementById('schStart').value);
  const end = parseInt(document.getElementById('schEnd').value);
  const days = document.getElementById('schDays').value;
  try {
    await apiFetch(`/api/devices/${deviceId}/schedules`, {
      method: 'POST',
      body: JSON.stringify({ start_hour: start, end_hour: end, days })
    });
    showToast('Horario agregado', 'success');
    openDeviceModal(deviceId);
  } catch(e) { showToast('Error: ' + e.message, 'error'); }
}

async function deleteSchedule(scheduleId) {
  try {
    await apiFetch(`/api/schedules/${scheduleId}`, { method: 'DELETE' });
    document.getElementById(`sch-${scheduleId}`)?.remove();
    showToast('Horario eliminado', 'success');
  } catch(e) { showToast('Error: ' + e.message, 'error'); }
}

// ---- Scan ----
async function triggerScan(deep = false) {
  try {
    setScanIndicator(true);
    await apiFetch('/api/scan/trigger', { method: 'POST', body: JSON.stringify({ deep }) });
    showToast(deep ? 'Escaneo profundo iniciado...' : 'Escaneo iniciado...', 'success');
    setTimeout(() => { fetchDevices(); setScanIndicator(false); }, 5000);
  } catch(e) { showToast('Error al escanear: ' + e.message, 'error'); setScanIndicator(false); }
}

function setScanIndicator(scanning) {
  const el = document.getElementById('scanIndicator');
  if (!el) return;
  el.className = scanning ? 'scanning' : '';
  el.innerHTML = scanning ? '<span class="spin">&#x21BB;</span> Escaneando...' : '&#x2714; Listo';
}

// ---- Alerts ----
async function refreshAlerts() {
  const alerts = await apiFetch('/api/alerts?limit=20');
  const unread = alerts.filter(a => !a.is_read).length;
  const badge = document.getElementById('alertCount');
  if (badge) {
    badge.textContent = unread;
    badge.classList.toggle('hidden', unread === 0);
  }
  const list = document.getElementById('alertList');
  if (!list) return;
  list.innerHTML = alerts.map(a => `
    <div class="alert-item ${a.is_read ? '' : 'unread'}">
      <div class="alert-type ${a.type}">${a.type.replace('_',' ')}</div>
      <div class="alert-msg">${esc(a.message)}</div>
      <div class="alert-time">${timeAgo(a.created_at)}</div>
    </div>
  `).join('') || '<div style="padding:16px;color:var(--text-muted);font-size:0.85rem">Sin alertas</div>';
}

function toggleAlerts() {
  const panel = document.getElementById('alertPanel');
  panel.classList.toggle('hidden');
  if (!panel.classList.contains('hidden')) refreshAlerts();
}

async function markAlertsRead() {
  await apiFetch('/api/alerts/read', { method: 'POST' });
  refreshAlerts();
}

// ---- History modal ----
async function openHistory() {
  document.getElementById('modalTitle').textContent = 'Historial de conexiones';
  document.getElementById('modalBody').innerHTML = '<div class="loading">Cargando...</div>';
  openModal();
  const sessions = await apiFetch('/api/history?days=7');
  document.getElementById('modalBody').innerHTML = `
    <table style="width:100%;font-size:0.82rem">
      <thead><tr>
        <th>Dispositivo</th><th>IP</th><th>Conectado</th><th>Duración</th>
      </tr></thead>
      <tbody>
        ${sessions.map(s => `
          <tr>
            <td>${esc(s.device_name)}</td>
            <td>${esc(s.ip || '—')}</td>
            <td>${s.connected_at ? new Date(s.connected_at+'Z').toLocaleString('es-AR') : '—'}</td>
            <td>${s.duration_seconds >= 3600
              ? Math.floor(s.duration_seconds/3600) + 'h ' + Math.floor((s.duration_seconds%3600)/60) + 'm'
              : Math.floor(s.duration_seconds/60) + 'm'
            }</td>
          </tr>
        `).join('')}
      </tbody>
    </table>
    <div style="margin-top:14px;display:flex;gap:8px">
      <a href="/api/export/csv?days=7" class="btn btn-secondary">Exportar CSV</a>
      <a href="/api/export/pdf?days=7" class="btn btn-secondary">Exportar PDF</a>
    </div>
  `;
}

// ---- Settings modal ----
async function openSettings() {
  const cfg = await apiFetch('/api/config');
  document.getElementById('modalTitle').textContent = 'Configuración';
  document.getElementById('modalBody').innerHTML = `
    <div class="form-group">
      <label>Intervalo de escaneo (minutos)</label>
      <input type="number" id="cfgInterval" value="${cfg.scan_interval}" min="1" max="60">
    </div>
    <div class="form-group" style="display:flex;align-items:center;gap:10px">
      <input type="checkbox" id="cfgAlerts" ${cfg.alert_new_devices ? 'checked' : ''} style="width:auto">
      <label style="margin:0">Alertar cuando aparece un dispositivo nuevo</label>
    </div>
    <div class="form-actions">
      <button class="btn btn-secondary" onclick="closeModal()">Cancelar</button>
      <button class="btn btn-primary" onclick="saveSettings()">Guardar</button>
    </div>
  `;
  openModal();
}

async function saveSettings() {
  const interval = parseInt(document.getElementById('cfgInterval').value);
  const alerts = document.getElementById('cfgAlerts').checked;
  await apiFetch('/api/config', {
    method: 'POST',
    body: JSON.stringify({ scan_interval: interval, alert_new_devices: alerts })
  });
  showToast('Configuración guardada. Reinicia para aplicar el intervalo.', 'success');
  closeModal();
}

// ---- Modal helpers ----
function openModal() { document.getElementById('modal').classList.remove('hidden'); }
function closeModal() { document.getElementById('modal').classList.add('hidden'); }
document.addEventListener('keydown', e => { if (e.key === 'Escape') closeModal(); });

// ---- Toast ----
let toastTimer;
function showToast(msg, type = '') {
  const el = document.getElementById('toast');
  el.textContent = msg;
  el.className = `toast ${type}`;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => el.classList.add('hidden'), 4000);
}

// ---- Escape HTML ----
function esc(str) {
  return String(str || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

// ---- Discord config ----
async function loadDiscordConfig() {
  try {
    const cfg = await apiFetch('/api/discord/config');
    const urlEl = document.getElementById('discordWebhookUrl');
    const chk = document.getElementById('discordEnabled');
    const badge = document.getElementById('discordStatus');
    if (urlEl) urlEl.value = cfg.webhook_url || '';
    if (chk) chk.checked = cfg.enabled;
    if (badge) {
      badge.textContent = cfg.enabled && cfg.webhook_url ? 'Activo' : 'Inactivo';
      badge.className = `discord-status-badge ${cfg.enabled && cfg.webhook_url ? 'ok' : 'off'}`;
    }
  } catch(e) { console.error('loadDiscordConfig:', e); }
}

async function saveDiscordConfig() {
  const url = document.getElementById('discordWebhookUrl')?.value.trim() || '';
  const enabled = document.getElementById('discordEnabled')?.checked ?? false;
  try {
    await apiFetch('/api/discord/config', {
      method: 'POST',
      body: JSON.stringify({ webhook_url: url, enabled })
    });
    showToast('Configuración de Discord guardada', 'success');
    loadDiscordConfig();
  } catch(e) { showToast('Error: ' + e.message, 'error'); }
}

async function saveDiscordToggle() {
  const url = document.getElementById('discordWebhookUrl')?.value.trim() || '';
  const enabled = document.getElementById('discordEnabled')?.checked ?? false;
  if (enabled && !url) {
    showToast('Ingresá la URL del webhook primero', 'error');
    document.getElementById('discordEnabled').checked = false;
    return;
  }
  await apiFetch('/api/discord/config', {
    method: 'POST',
    body: JSON.stringify({ webhook_url: url, enabled })
  });
  loadDiscordConfig();
  showToast(enabled ? 'Discord activado' : 'Discord desactivado', 'success');
}

async function testDiscord() {
  const url = document.getElementById('discordWebhookUrl')?.value.trim();
  if (!url) { showToast('Ingresá la URL primero', 'error'); return; }
  try {
    const r = await apiFetch('/api/discord/test', {
      method: 'POST',
      body: JSON.stringify({ url })
    });
    if (r.ok) showToast('✅ Mensaje de prueba enviado a Discord', 'success');
    else showToast('❌ No se pudo conectar: ' + (r.error || 'error'), 'error');
  } catch(e) { showToast('Error: ' + e.message, 'error'); }
}

// ---- Excluded MACs (modo invisible) ----
async function loadExcludedMacs() {
  const container = document.getElementById('excludedMacList');
  if (!container) return;
  try {
    const rows = await apiFetch('/api/excluded-macs');
    if (!rows.length) {
      container.innerHTML = '<div style="color:var(--text-muted);font-size:0.82rem;padding:8px 0">Sin MACs excluidas.</div>';
      return;
    }
    container.innerHTML = rows.map(r => `
      <div class="excluded-mac-item">
        <div>
          <div class="excluded-mac-label">${esc(r.label || 'Sin etiqueta')}</div>
          <div class="excluded-mac-addr">${esc(r.mac)}</div>
        </div>
        <button class="btn btn-sm btn-danger" onclick="removeExcludedMac('${esc(r.mac)}')">✕</button>
      </div>
    `).join('');
  } catch(e) { container.innerHTML = '<div style="color:var(--red)">Error al cargar</div>'; }
}

function openAddExcludedModal() {
  document.getElementById('modalTitle').textContent = '🕶 Agregar MAC al modo invisible';
  document.getElementById('modalBody').innerHTML = `
    <div class="form-group">
      <label>Dirección MAC</label>
      <input type="text" id="excMac" placeholder="aa:bb:cc:dd:ee:ff" style="font-family:monospace">
    </div>
    <div class="form-group">
      <label>Etiqueta (opcional)</label>
      <input type="text" id="excLabel" placeholder="Mi notebook, Mi celular...">
    </div>
    <div style="font-size:0.78rem;color:var(--text-muted);margin-bottom:12px">
      Este dispositivo no aparecerá en el dashboard, historial ni será enviado a Discord.
    </div>
    <div class="form-actions">
      <button class="btn btn-secondary" onclick="closeModal()">Cancelar</button>
      <button class="btn btn-primary" onclick="addExcludedMac()">Agregar</button>
    </div>
    <div style="margin-top:16px;border-top:1px solid var(--border);padding-top:12px">
      <div style="font-size:0.8rem;color:var(--text-muted);margin-bottom:8px">
        O elegí de los dispositivos detectados:
      </div>
      <div id="excPickList">
        ${allDevices.map(d => `
          <div style="display:flex;justify-content:space-between;align-items:center;padding:5px 0;border-bottom:1px solid var(--border);font-size:0.82rem">
            <span>${esc(d.display_name)} <span style="color:var(--text-muted)">${esc(d.mac)}</span></span>
            <button class="btn btn-sm btn-secondary" onclick="quickExclude('${esc(d.mac)}','${esc(d.display_name)}')">Excluir</button>
          </div>
        `).join('')}
      </div>
    </div>
  `;
  openModal();
}

async function addExcludedMac() {
  const mac = document.getElementById('excMac').value.trim().toLowerCase();
  const label = document.getElementById('excLabel').value.trim();
  if (!mac) { showToast('Ingresá una MAC', 'error'); return; }
  try {
    await apiFetch('/api/excluded-macs', { method: 'POST', body: JSON.stringify({ mac, label }) });
    showToast('MAC excluida correctamente', 'success');
    closeModal();
    loadExcludedMacs();
    fetchDevices();
  } catch(e) { showToast('Error: ' + e.message, 'error'); }
}

async function quickExclude(mac, name) {
  try {
    await apiFetch('/api/excluded-macs', { method: 'POST', body: JSON.stringify({ mac, label: name }) });
    showToast(`${name} excluido`, 'success');
    closeModal();
    loadExcludedMacs();
    fetchDevices();
  } catch(e) { showToast('Error: ' + e.message, 'error'); }
}

async function removeExcludedMac(mac) {
  try {
    await apiFetch(`/api/excluded-macs/${encodeURIComponent(mac)}`, { method: 'DELETE' });
    showToast('MAC removida de la lista', 'success');
    loadExcludedMacs();
  } catch(e) { showToast('Error: ' + e.message, 'error'); }
}

// ---- Page initializers ----
function initDashboard() {
  fetchDevices();
  initCharts();
  refreshAlerts();
  loadDiscordConfig();
  loadExcludedMacs();
  // Poll every 30s as fallback
  setInterval(fetchDevices, 30000);
  setInterval(refreshAlerts, 60000);
  setInterval(initCharts, 120000);
}

function initDevicesPage() {
  refreshAlerts();
  setInterval(refreshAlerts, 60000);
}
