'use strict';

// ---- Socket.IO ----
const socket = io();
let allDevices = [];

socket.on('connect', () => console.log('[WiFiDetect] socket connected'));
socket.on('devices_list', devices => { allDevices = devices; renderDeviceTable(devices); updateStats(devices); });
socket.on('new_device',   () => { fetchDevices(); refreshAlerts(); });
socket.on('device_offline', () => fetchDevices());
socket.on('device_update',  () => fetchDevices());
socket.on('alert', data => { showToast(data.message, data.type === 'port_scan' ? 'error' : 'success'); refreshAlerts(); });

// ---- Fetch helpers ----
async function apiFetch(url, opts = {}) {
  const res = await fetch(url, { headers: { 'Content-Type': 'application/json' }, ...opts });
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}

async function fetchDevices() {
  try {
    allDevices = await apiFetch('/api/devices');
    renderDeviceTable(allDevices);
    updateStats(allDevices);
    populateDnsDeviceFilter();
  } catch (e) { console.error('fetchDevices:', e); }
}

// ---- Device table ----
function statusPill(status) {
  const map = {
    known:      ['pill-known',     'Conocido'],
    unknown:    ['pill-unknown',   'Sin clasificar'],
    blocked:    ['pill-blocked',   'Bloqueado'],
    suspicious: ['pill-suspicious','Sospechoso'],
  };
  const [cls, label] = map[status] || ['pill-unknown', status];
  return `<span class="status-pill ${cls}"><span class="status-dot dot-${status}"></span>${label}</span>`;
}

function timeAgo(isoStr) {
  if (!isoStr) return '—';
  const diff = Date.now() - new Date(isoStr + 'Z').getTime();
  const s = Math.floor(diff / 1000);
  if (s < 60)   return `hace ${s}s`;
  const m = Math.floor(s / 60);
  if (m < 60)   return `hace ${m}m`;
  const h = Math.floor(m / 60);
  if (h < 24)   return `hace ${h}h`;
  return `hace ${Math.floor(h / 24)}d`;
}

function renderDeviceTable(devices) {
  const tbody = document.getElementById('deviceTableBody');
  if (!tbody) return;

  const text   = (document.getElementById('filterInput') || {}).value?.toLowerCase() || '';
  const status = (document.getElementById('filterStatus') || {}).value || '';

  const filtered = devices.filter(d => {
    const blob = [d.display_name, d.ip, d.mac, d.vendor, d.hostname, d.mdns_name].join(' ').toLowerCase();
    return (!text || blob.includes(text)) && (!status || d.status === status);
  });

  if (!filtered.length) {
    tbody.innerHTML = '<tr><td colspan="8" class="loading">Sin resultados</td></tr>';
    return;
  }

  tbody.innerHTML = filtered.map(d => `
    <tr class="row-${d.status}" data-id="${d.id}">
      <td>${statusPill(d.status)}</td>
      <td>
        <span class="online-dot ${d.is_online ? 'online' : 'offline'}"></span>
        <strong>${esc(d.display_name)}</strong>
        ${d.is_random_mac ? '<span class="tag tag-warning" style="margin-left:4px">rand</span>' : ''}
      </td>
      <td style="font-family:monospace;font-size:0.8rem">${esc(d.ip || '—')}</td>
      <td style="font-family:monospace;font-size:0.78rem;color:var(--text-muted)">${esc(d.mac)}</td>
      <td>${esc(d.vendor || '—')}</td>
      <td style="font-size:0.78rem">
        ${d.os_detected
          ? `${esc(d.os_detected)} <span style="color:var(--text-muted)">${d.os_confidence}%</span>`
          : '—'}
      </td>
      <td style="color:var(--text-muted);font-size:0.78rem">${timeAgo(d.last_seen)}</td>
      <td>
        <div style="display:flex;gap:4px;flex-wrap:wrap">
          <button class="btn btn-ghost btn-xs" onclick="openDeviceModal(${d.id})">Editar</button>
          ${d.is_blocked
            ? `<button class="btn btn-success btn-xs" onclick="unblockDevice(${d.id})">Desbloquear</button>`
            : `<button class="btn btn-danger  btn-xs" onclick="blockDevice(${d.id})">Bloquear</button>`}
          ${d.is_known
            ? `<button class="btn btn-ghost btn-xs" onclick="setKnown(${d.id},false)">– Lista blanca</button>`
            : `<button class="btn btn-success btn-xs" onclick="setKnown(${d.id},true)">+ Lista blanca</button>`}
        </div>
      </td>
    </tr>
  `).join('');
}

function filterDevices() { renderDeviceTable(allDevices); }

// ---- Stats ----
function updateStats(devices) {
  const s = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = v; };
  s('statTotal',     devices.length);
  s('statOnline',    devices.filter(d => d.is_online).length);
  s('statKnown',     devices.filter(d => d.is_known).length);
  s('statUnknown',   devices.filter(d => !d.is_known && !d.is_blocked && d.is_online).length);
  s('statBlocked',   devices.filter(d => d.is_blocked).length);
  s('statSuspicious',devices.filter(d => d.is_random_mac && !d.is_known).length);
}

// ---- Charts ----
let _statusChart = null, _activityChart = null;

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
      backgroundColor: ['#16c784', '#f0a500', '#e84040', '#9d6ff7'],
      borderWidth: 0,
    }]
  };
  if (_statusChart) _statusChart.destroy();
  _statusChart = new Chart(el, {
    type: 'doughnut', data,
    options: {
      cutout: '68%',
      plugins: { legend: { labels: { color: '#6b7280', font: { size: 11 } } } },
    }
  });
}

async function renderActivityChart() {
  const el = document.getElementById('activityChart');
  if (!el) return;
  const rows = await apiFetch('/api/stats/hourly');
  const hours = Array.from({ length: 24 }, (_, i) => String(i).padStart(2, '0') + 'h');
  const counts = hours.map((_, i) => {
    const h = String(i).padStart(2, '0');
    return (rows.find(r => r.hour === h) || {}).count || 0;
  });
  if (_activityChart) _activityChart.destroy();
  _activityChart = new Chart(el, {
    type: 'bar',
    data: { labels: hours, datasets: [{ label: 'Conexiones', data: counts, backgroundColor: '#4f8ef7', borderRadius: 3 }] },
    options: {
      plugins: { legend: { display: false } },
      scales: {
        x: { ticks: { color: '#6b7280', font: { size: 10 } }, grid: { color: '#1e2029' } },
        y: { ticks: { color: '#6b7280', font: { size: 10 } }, grid: { color: '#1e2029' }, beginAtZero: true },
      },
    }
  });
}

// ---- Device actions ----
async function blockDevice(id) {
  try {
    await apiFetch(`/api/devices/${id}/block`, { method: 'POST' });
    showToast('Dispositivo bloqueado', 'success');
    fetchDevices();
  } catch (e) { showToast('Error: ' + e.message, 'error'); }
}

async function unblockDevice(id) {
  try {
    await apiFetch(`/api/devices/${id}/unblock`, { method: 'POST' });
    showToast('Dispositivo desbloqueado', 'success');
    fetchDevices();
  } catch (e) { showToast('Error: ' + e.message, 'error'); }
}

async function setKnown(id, known) {
  try {
    await apiFetch(`/api/devices/${id}`, { method: 'PATCH', body: JSON.stringify({ is_known: known }) });
    showToast(known ? 'Marcado como conocido' : 'Removido de lista blanca', 'success');
    fetchDevices();
  } catch (e) { showToast('Error: ' + e.message, 'error'); }
}

// ---- Device edit modal ----
async function openDeviceModal(id) {
  const device   = allDevices.find(d => d.id === id) || await apiFetch(`/api/devices/${id}`);
  const schedules = await apiFetch(`/api/devices/${id}/schedules`);

  document.getElementById('modalTitle').textContent = device.display_name;
  document.getElementById('modalBody').innerHTML = `
    <div class="form-group">
      <label>Nombre personalizado</label>
      <input type="text" id="editName" value="${esc(device.custom_name || '')}" placeholder="Ej: Celu de Sofi">
    </div>
    <div class="form-group">
      <label>Límite de ancho de banda (kbps — 0 = sin límite)</label>
      <input type="number" id="editBw" value="${device.bandwidth_limit || 0}" min="0">
    </div>
    <div class="section-label" style="margin-top:16px">Bloqueos programados</div>
    <div class="schedule-list" id="scheduleList">
      ${schedules.map(s => `
        <div class="schedule-item" id="sch-${s.id}">
          <span>${formatSchedule(s)}</span>
          <button class="btn btn-danger btn-xs" onclick="deleteSchedule(${s.id})">×</button>
        </div>
      `).join('') || '<div style="color:var(--text-muted);font-size:0.78rem">Sin horarios</div>'}
    </div>
    <details style="margin-bottom:12px">
      <summary style="cursor:pointer;font-size:0.82rem;color:var(--blue);margin-bottom:8px">+ Agregar horario</summary>
      <div class="form-row" style="margin-top:8px">
        <div class="form-group">
          <label>Desde (hora)</label>
          <input type="number" id="schStart" min="0" max="23" value="23">
        </div>
        <div class="form-group">
          <label>Hasta (hora)</label>
          <input type="number" id="schEnd" min="0" max="23" value="8">
        </div>
      </div>
      <div class="form-group">
        <label>Días (0=Lun … 6=Dom)</label>
        <input type="text" id="schDays" value="0,1,2,3,4,5,6">
      </div>
      <button class="btn btn-primary btn-sm" onclick="addSchedule(${id})">Agregar</button>
    </details>
    <div class="form-actions">
      <button class="btn btn-ghost btn-sm" onclick="closeModal()">Cancelar</button>
      <button class="btn btn-primary btn-sm" onclick="saveDevice(${id})">Guardar</button>
    </div>
  `;
  openModal();
}

function formatSchedule(s) {
  const p = n => String(n).padStart(2, '0');
  const days = ['Lun','Mar','Mié','Jue','Vie','Sáb','Dom'];
  const dayStr = s.days.split(',').map(d => days[+d] || d).join(', ');
  return `${p(s.start_hour)}:${p(s.start_minute)} – ${p(s.end_hour)}:${p(s.end_minute)} | ${dayStr}`;
}

async function saveDevice(id) {
  const name = document.getElementById('editName').value.trim();
  const bw   = parseInt(document.getElementById('editBw').value) || 0;
  try {
    await apiFetch(`/api/devices/${id}`, { method: 'PATCH', body: JSON.stringify({ custom_name: name, bandwidth_limit: bw }) });
    showToast('Guardado', 'success');
    closeModal();
    fetchDevices();
  } catch (e) { showToast('Error: ' + e.message, 'error'); }
}

async function addSchedule(deviceId) {
  const start = parseInt(document.getElementById('schStart').value);
  const end   = parseInt(document.getElementById('schEnd').value);
  const days  = document.getElementById('schDays').value;
  try {
    await apiFetch(`/api/devices/${deviceId}/schedules`, { method: 'POST', body: JSON.stringify({ start_hour: start, end_hour: end, days }) });
    showToast('Horario agregado', 'success');
    openDeviceModal(deviceId);
  } catch (e) { showToast('Error: ' + e.message, 'error'); }
}

async function deleteSchedule(scheduleId) {
  try {
    await apiFetch(`/api/schedules/${scheduleId}`, { method: 'DELETE' });
    document.getElementById(`sch-${scheduleId}`)?.remove();
    showToast('Horario eliminado', 'success');
  } catch (e) { showToast('Error: ' + e.message, 'error'); }
}

// ---- Kill switch ----
async function checkKillSwitchStatus() {
  try {
    const s = await apiFetch('/api/killswitch/status');
    setKillSwitchUI(s.active);
  } catch (e) { /* silencioso */ }
}

function setKillSwitchUI(active) {
  const banner    = document.getElementById('lockdownBanner');
  const btnLock   = document.getElementById('btnLockdown');
  const navStatus = document.getElementById('ksNavStatus');

  if (banner) banner.classList.toggle('hidden', !active);
  if (navStatus) navStatus.classList.toggle('hidden', !active);

  if (btnLock) {
    if (active) {
      btnLock.textContent = 'Restaurar red';
      btnLock.className = 'btn btn-restore btn-sm';
      btnLock.onclick = deactivateKillSwitch;
    } else {
      btnLock.textContent = 'Cortar internet';
      btnLock.className = 'btn btn-lockdown btn-sm';
      btnLock.onclick = activateKillSwitch;
    }
  }
}

async function activateKillSwitch() {
  if (!confirm('Vas a cortar el acceso a internet de todos los dispositivos de la red excepto el tuyo.\n¿Confirmar?')) return;
  try {
    const r = await apiFetch('/api/killswitch/activate', { method: 'POST' });
    if (r.ok) {
      showToast(`Red en lockdown — ${r.blocked} dispositivos bloqueados`, 'error');
      setKillSwitchUI(true);
    } else {
      showToast('Error: ' + r.error, 'error');
    }
  } catch (e) { showToast('Error: ' + e.message, 'error'); }
}

async function deactivateKillSwitch() {
  try {
    await apiFetch('/api/killswitch/deactivate', { method: 'POST' });
    showToast('Red restaurada', 'success');
    setKillSwitchUI(false);
  } catch (e) { showToast('Error: ' + e.message, 'error'); }
}

// ---- DNS History ----
async function loadDnsHistory() {
  const tbody = document.getElementById('dnsTableBody');
  if (!tbody) return;

  const deviceId = (document.getElementById('dnsDeviceFilter') || {}).value || '';
  try {
    const url = deviceId
      ? `/api/dns-history/device/${deviceId}?limit=100`
      : `/api/dns-history?hours=24&limit=150`;
    const rows = await apiFetch(url);

    if (!rows.length) {
      tbody.innerHTML = '<tr><td colspan="3" class="loading">Sin datos — el sniffer DNS captura consultas cuando hay tráfico en la red.</td></tr>';
      return;
    }

    tbody.innerHTML = rows.map(r => `
      <tr>
        <td class="dns-domain">${esc(r.domain)}</td>
        <td class="dns-device">${esc(r.device_name)}</td>
        <td style="color:var(--text-muted);font-size:0.75rem">${r.visited_at ? new Date(r.visited_at + 'Z').toLocaleString('es-AR') : '—'}</td>
      </tr>
    `).join('');
  } catch (e) {
    tbody.innerHTML = `<tr><td colspan="3" style="color:var(--red);padding:12px">Error: ${esc(e.message)}</td></tr>`;
  }
}

function populateDnsDeviceFilter() {
  const sel = document.getElementById('dnsDeviceFilter');
  if (!sel) return;
  const current = sel.value;
  sel.innerHTML = '<option value="">Todos los dispositivos</option>' +
    allDevices.map(d => `<option value="${d.id}" ${d.id == current ? 'selected' : ''}>${esc(d.display_name)}</option>`).join('');
}

// ---- Scan ----
async function triggerScan(deep = false) {
  try {
    setScanIndicator(true);
    await apiFetch('/api/scan/trigger', { method: 'POST', body: JSON.stringify({ deep }) });
    showToast(deep ? 'Escaneo profundo iniciado' : 'Escaneando...', 'success');
    setTimeout(() => { fetchDevices(); setScanIndicator(false); }, 5000);
  } catch (e) { showToast('Error: ' + e.message, 'error'); setScanIndicator(false); }
}

function setScanIndicator(scanning) {
  const el = document.getElementById('scanIndicator');
  if (!el) return;
  el.className = scanning ? 'scanning' : '';
  el.innerHTML = scanning ? '<span class="spin">↻</span> Escaneando...' : '';
}

// ---- Alerts ----
async function refreshAlerts() {
  try {
    const alerts = await apiFetch('/api/alerts?limit=20');
    const unread  = alerts.filter(a => !a.is_read).length;
    const badge   = document.getElementById('alertCount');
    const btn     = document.getElementById('alertBell');

    if (badge) { badge.textContent = unread; badge.classList.toggle('hidden', unread === 0); }
    if (btn)   btn.classList.toggle('has-alerts', unread > 0);

    const list = document.getElementById('alertList');
    if (!list) return;
    list.innerHTML = alerts.map(a => `
      <div class="alert-item ${a.is_read ? '' : 'unread'}">
        <div class="alert-type ${a.type}">${a.type.replace('_', ' ')}</div>
        <div class="alert-msg">${esc(a.message)}</div>
        <div class="alert-time">${timeAgo(a.created_at)}</div>
      </div>
    `).join('') || '<div style="padding:16px;color:var(--text-muted);font-size:0.82rem">Sin alertas</div>';
  } catch (e) { /* silencioso */ }
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
    <table style="width:100%;font-size:0.8rem">
      <thead><tr>
        <th>Dispositivo</th><th>IP</th><th>Conectado</th><th>Duración</th>
      </tr></thead>
      <tbody>
        ${sessions.map(s => `
          <tr>
            <td>${esc(s.device_name)}</td>
            <td style="font-family:monospace">${esc(s.ip || '—')}</td>
            <td>${s.connected_at ? new Date(s.connected_at + 'Z').toLocaleString('es-AR') : '—'}</td>
            <td>${s.duration_seconds >= 3600
              ? `${Math.floor(s.duration_seconds / 3600)}h ${Math.floor((s.duration_seconds % 3600) / 60)}m`
              : `${Math.floor(s.duration_seconds / 60)}m`
            }</td>
          </tr>`).join('')}
      </tbody>
    </table>
    <div style="margin-top:12px;display:flex;gap:8px">
      <a href="/api/export/csv?days=7"  class="btn btn-ghost btn-sm">Exportar CSV</a>
      <a href="/api/export/pdf?days=7"  class="btn btn-ghost btn-sm">Exportar PDF</a>
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
      <label class="toggle-switch">
        <input type="checkbox" id="cfgAlerts" ${cfg.alert_new_devices ? 'checked' : ''}>
        <span class="toggle-slider"></span>
      </label>
      <span style="font-size:0.85rem">Alertar cuando aparece un dispositivo nuevo</span>
    </div>
    <div class="form-actions">
      <button class="btn btn-ghost btn-sm" onclick="closeModal()">Cancelar</button>
      <button class="btn btn-primary btn-sm" onclick="saveSettings()">Guardar</button>
    </div>
  `;
  openModal();
}

async function saveSettings() {
  const interval = parseInt(document.getElementById('cfgInterval').value);
  const alerts   = document.getElementById('cfgAlerts').checked;
  await apiFetch('/api/config', { method: 'POST', body: JSON.stringify({ scan_interval: interval, alert_new_devices: alerts }) });
  showToast('Configuración guardada. Reinicia para aplicar el intervalo.', 'success');
  closeModal();
}

// ---- Discord config ----
async function loadDiscordConfig() {
  try {
    const cfg   = await apiFetch('/api/discord/config');
    const urlEl = document.getElementById('discordWebhookUrl');
    const chk   = document.getElementById('discordEnabled');
    const badge = document.getElementById('discordStatus');
    if (urlEl) urlEl.value = cfg.webhook_url || '';
    if (chk)   chk.checked = cfg.enabled;
    if (badge) {
      badge.textContent = cfg.enabled && cfg.webhook_url ? 'Activo' : 'Inactivo';
      badge.className = `discord-status-badge ${cfg.enabled && cfg.webhook_url ? 'ok' : 'off'}`;
    }
  } catch (e) { /* silencioso */ }
}

async function saveDiscordConfig() {
  const url     = document.getElementById('discordWebhookUrl')?.value.trim() || '';
  const enabled = document.getElementById('discordEnabled')?.checked ?? false;
  try {
    await apiFetch('/api/discord/config', { method: 'POST', body: JSON.stringify({ webhook_url: url, enabled }) });
    showToast('Discord guardado', 'success');
    loadDiscordConfig();
  } catch (e) { showToast('Error: ' + e.message, 'error'); }
}

async function saveDiscordToggle() {
  const url     = document.getElementById('discordWebhookUrl')?.value.trim() || '';
  const enabled = document.getElementById('discordEnabled')?.checked ?? false;
  if (enabled && !url) {
    showToast('Ingresá la URL del webhook primero', 'error');
    document.getElementById('discordEnabled').checked = false;
    return;
  }
  await apiFetch('/api/discord/config', { method: 'POST', body: JSON.stringify({ webhook_url: url, enabled }) });
  loadDiscordConfig();
}

async function testDiscord() {
  const url = document.getElementById('discordWebhookUrl')?.value.trim();
  if (!url) { showToast('Ingresá la URL primero', 'error'); return; }
  try {
    const r = await apiFetch('/api/discord/test', { method: 'POST', body: JSON.stringify({ url }) });
    showToast(r.ok ? 'Mensaje de prueba enviado' : 'Error: ' + (r.error || 'falló'), r.ok ? 'success' : 'error');
  } catch (e) { showToast('Error: ' + e.message, 'error'); }
}

// ---- Excluded MACs ----
async function loadExcludedMacs() {
  const container = document.getElementById('excludedMacList');
  if (!container) return;
  try {
    const rows = await apiFetch('/api/excluded-macs');
    if (!rows.length) {
      container.innerHTML = '<div style="color:var(--text-muted);font-size:0.78rem">Sin MACs excluidas.</div>';
      return;
    }
    container.innerHTML = rows.map(r => `
      <div class="excluded-mac-item">
        <div>
          <div style="font-size:0.82rem;font-weight:500">${esc(r.label || 'Sin etiqueta')}</div>
          <div class="excluded-mac-addr">${esc(r.mac)}</div>
        </div>
        <button class="btn btn-danger btn-xs" onclick="removeExcludedMac('${esc(r.mac)}')">×</button>
      </div>
    `).join('');
  } catch (e) { /* silencioso */ }
}

function openAddExcludedModal() {
  document.getElementById('modalTitle').textContent = 'Agregar al modo invisible';
  document.getElementById('modalBody').innerHTML = `
    <div class="form-group">
      <label>Dirección MAC</label>
      <input type="text" id="excMac" placeholder="aa:bb:cc:dd:ee:ff" style="font-family:monospace">
    </div>
    <div class="form-group">
      <label>Etiqueta</label>
      <input type="text" id="excLabel" placeholder="Mi notebook, Mi celular...">
    </div>
    <p style="font-size:0.75rem;color:var(--text-muted);margin-bottom:12px">
      Este dispositivo no aparecerá en el dashboard ni será enviado a Discord.
    </p>
    ${allDevices.length ? `
    <div class="section-label">Elegir de la lista</div>
    <div style="max-height:180px;overflow-y:auto">
      ${allDevices.map(d => `
        <div style="display:flex;justify-content:space-between;align-items:center;padding:6px 0;border-bottom:1px solid var(--border);font-size:0.8rem">
          <span>${esc(d.display_name)} <span style="color:var(--text-muted)">${esc(d.mac)}</span></span>
          <button class="btn btn-ghost btn-xs" onclick="quickExclude('${esc(d.mac)}','${esc(d.display_name)}')">Excluir</button>
        </div>`).join('')}
    </div>` : ''}
    <div class="form-actions" style="margin-top:14px">
      <button class="btn btn-ghost btn-sm" onclick="closeModal()">Cancelar</button>
      <button class="btn btn-primary btn-sm" onclick="addExcludedMac()">Agregar</button>
    </div>
  `;
  openModal();
}

async function addExcludedMac() {
  const mac   = document.getElementById('excMac').value.trim().toLowerCase();
  const label = document.getElementById('excLabel').value.trim();
  if (!mac) { showToast('Ingresá una MAC', 'error'); return; }
  try {
    await apiFetch('/api/excluded-macs', { method: 'POST', body: JSON.stringify({ mac, label }) });
    showToast('MAC excluida', 'success');
    closeModal(); loadExcludedMacs(); fetchDevices();
  } catch (e) { showToast('Error: ' + e.message, 'error'); }
}

async function quickExclude(mac, name) {
  try {
    await apiFetch('/api/excluded-macs', { method: 'POST', body: JSON.stringify({ mac, label: name }) });
    showToast(`${name} excluido`, 'success');
    closeModal(); loadExcludedMacs(); fetchDevices();
  } catch (e) { showToast('Error: ' + e.message, 'error'); }
}

async function removeExcludedMac(mac) {
  try {
    await apiFetch(`/api/excluded-macs/${encodeURIComponent(mac)}`, { method: 'DELETE' });
    showToast('Removido', 'success'); loadExcludedMacs();
  } catch (e) { showToast('Error: ' + e.message, 'error'); }
}

// ---- Modal ----
function openModal()  { document.getElementById('modal').classList.remove('hidden'); }
function closeModal() { document.getElementById('modal').classList.add('hidden'); }
document.addEventListener('keydown', e => { if (e.key === 'Escape') closeModal(); });

// ---- Toast ----
let _toastTimer;
function showToast(msg, type = '') {
  const el = document.getElementById('toast');
  el.textContent = msg;
  el.className = `toast ${type}`;
  clearTimeout(_toastTimer);
  _toastTimer = setTimeout(() => el.classList.add('hidden'), 4000);
}

// ---- Escape HTML ----
function esc(str) {
  return String(str ?? '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

// ---- Page initializers ----
function initDashboard() {
  fetchDevices();
  initCharts();
  refreshAlerts();
  loadDiscordConfig();
  loadExcludedMacs();
  loadDnsHistory();
  checkKillSwitchStatus();

  setInterval(fetchDevices,          30000);
  setInterval(refreshAlerts,         60000);
  setInterval(initCharts,           120000);
  setInterval(loadDnsHistory,        60000);
  setInterval(checkKillSwitchStatus, 15000);
}

function initDevicesPage() {
  refreshAlerts();
  setInterval(refreshAlerts, 60000);
}
