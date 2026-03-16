// ═══════════════════════════════════════════════════════════════════
// QuickFW Dashboard — stat cards, interface health, quick actions,
//                     firewall summary, auto-refresh
// ═══════════════════════════════════════════════════════════════════
(function() {
const { esc, fmtBytes, fmtUptime } = QFW.util;
let cpuChart, memChart;
let refreshTimer = null;

QFW.registerPage('dashboard', {
  init(page) {
    page.innerHTML = `
      <div class="page-header">
        <div><h1>Dashboard</h1><p class="page-sub">Real-time appliance overview</p></div>
        <span class="version-badge" id="version-badge">v\u2014</span>
      </div>

      <!-- Stat cards (5 columns) -->
      <div class="stat-grid">
        <div class="stat-card">
          <div class="stat-icon orange"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z"/></svg></div>
          <div class="stat-body"><div class="stat-label">CPU</div><div class="stat-value" id="dash-cpu">\u2014</div><div class="stat-sub" id="dash-load">\u2014</div></div>
          <canvas class="stat-chart mini-chart" id="cpu-chart"></canvas>
        </div>
        <div class="stat-card">
          <div class="stat-icon purple"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/></svg></div>
          <div class="stat-body"><div class="stat-label">Memory</div><div class="stat-value" id="dash-mem">\u2014</div><div class="stat-sub" id="dash-mem-detail">\u2014</div></div>
          <canvas class="stat-chart mini-chart" id="mem-chart"></canvas>
        </div>
        <div class="stat-card">
          <div class="stat-icon blue"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20z"/><path d="M2 12h20"/></svg></div>
          <div class="stat-body"><div class="stat-label">Active Connections</div><div class="stat-value" id="dash-conns">\u2014</div></div>
        </div>
        <div class="stat-card">
          <div class="stat-icon green"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg></div>
          <div class="stat-body"><div class="stat-label">RX Total</div><div class="stat-value" id="dash-rx">\u2014</div></div>
        </div>
        <div class="stat-card">
          <div class="stat-icon red"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg></div>
          <div class="stat-body"><div class="stat-label">TX Total</div><div class="stat-value" id="dash-tx">\u2014</div></div>
        </div>
      </div>

      <!-- Interface Health -->
      <div class="card">
        <div class="card-header"><h2>Interface Status</h2></div>
        <div class="card-body" style="padding:0;">
          <table class="data-table">
            <thead><tr><th>Interface</th><th>Status</th><th>Role</th><th>IPv4</th><th>RX</th><th>TX</th></tr></thead>
            <tbody id="dash-iface-body"><tr><td colspan="6" class="table-empty">Loading\u2026</td></tr></tbody>
          </table>
        </div>
      </div>

      <div class="cards-row">
        <!-- Quick Actions -->
        <div class="card">
          <div class="card-header"><h2>Quick Actions</h2></div>
          <div class="card-body">
            <div class="quick-actions">
              <div class="quick-action-card" onclick="QFW.showPage('firewall')">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
                <span>Add Firewall Rule</span>
              </div>
              <div class="quick-action-card" onclick="QFW.showPage('nat')">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M7 16V4m0 0L3 8m4-4l4 4M17 8v12m0 0l4-4m-4 4l-4-4"/></svg>
                <span>Add Port Forward</span>
              </div>
              <div class="quick-action-card" onclick="QFW.showPage('interfaces')">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 12h-4l-3 9L9 3l-3 9H2"/></svg>
                <span>Interfaces</span>
              </div>
              <div class="quick-action-card" onclick="QFW.showPage('settings')">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9"/></svg>
                <span>Settings</span>
              </div>
            </div>
          </div>
        </div>

        <!-- Firewall Status Summary -->
        <div class="card">
          <div class="card-header"><h2>Firewall Status</h2></div>
          <div class="card-body">
            <div class="info-table" id="dash-fw-summary">
              <div class="info-row"><span class="info-label">Loading\u2026</span></div>
            </div>
          </div>
        </div>
      </div>
    `;

    // Init sparkline charts
    cpuChart = QFW.components.MiniChart(document.getElementById('cpu-chart'), { color:'#ea580c', fillColor:'rgba(234,88,12,0.1)', width:80, height:32 });
    memChart = QFW.components.MiniChart(document.getElementById('mem-chart'), { color:'#7c3aed', fillColor:'rgba(124,58,237,0.1)', width:80, height:32 });
  },

  load(page) {
    loadDashboard();
    // Auto-refresh every 5 seconds
    if (refreshTimer) clearInterval(refreshTimer);
    refreshTimer = setInterval(loadDashboard, 5000);
  },

  destroy() {
    if (refreshTimer) { clearInterval(refreshTimer); refreshTimer = null; }
  }
});

function loadDashboard() {
  // System info
  QFW.api.get('/api/system/info').then(d => {
    document.getElementById('dash-cpu').textContent = (d.cpu_usage_percent||0).toFixed(1)+'%';
    document.getElementById('dash-load').textContent = 'Load: '+(d.load_avg_1||0).toFixed(2)+' / '+(d.load_avg_5||0).toFixed(2)+' / '+(d.load_avg_15||0).toFixed(2);
    document.getElementById('dash-mem').textContent = (d.memory_percent||0).toFixed(1)+'%';
    document.getElementById('dash-mem-detail').textContent = (d.memory_used_mb||0)+' / '+(d.memory_total_mb||0)+' MB';
    document.getElementById('version-badge').textContent = 'v'+(d.version||'?');
    cpuChart.push(d.cpu_usage_percent||0);
    memChart.push(d.memory_percent||0);
  }).catch(()=>{});

  // Traffic
  QFW.api.get('/api/system/traffic').then(d => {
    document.getElementById('dash-conns').textContent = (d.active_connections||0).toLocaleString();
    document.getElementById('dash-rx').textContent = fmtBytes(d.total_rx_bytes||0);
    document.getElementById('dash-tx').textContent = fmtBytes(d.total_tx_bytes||0);
  }).catch(()=>{});

  // Interface health
  QFW.api.get('/api/interfaces').then(d => {
    QFW.interfaces = d.interfaces||[];
    const tbody = document.getElementById('dash-iface-body');
    if (!QFW.interfaces.length) { tbody.innerHTML = '<tr><td colspan="6" class="table-empty">No interfaces.</td></tr>'; return; }
    tbody.innerHTML = QFW.interfaces.map(i => {
      const r = i.role ? '<span class="role-badge role-'+i.role+'">'+i.role.toUpperCase()+'</span>' : '<span class="role-badge role-none">\u2014</span>';
      return '<tr><td><strong>'+esc(i.name)+'</strong></td>'
        +'<td><span class="'+(i.link_up?'iface-up':'iface-down')+'">\u25CF '+(i.link_up?'UP':'DOWN')+'</span></td>'
        +'<td>'+r+'</td>'
        +'<td class="mono">'+(i.ipv4_addrs.join(', ')||'\u2014')+'</td>'
        +'<td class="mono">'+fmtBytes(i.rx_bytes)+'</td>'
        +'<td class="mono">'+fmtBytes(i.tx_bytes)+'</td></tr>';
    }).join('');
  }).catch(()=>{});

  // Firewall status summary
  QFW.api.get('/api/firewall').then(fw => {
    const el = document.getElementById('dash-fw-summary');
    const ruleCount = fw.rules ? fw.rules.length : 0;
    el.innerHTML =
      '<div class="info-row"><span class="info-label">Forward Policy</span><span class="info-val"><span class="badge '+(fw.forward_policy==='drop'?'badge-red':'badge-green')+'">'+(fw.forward_policy||'accept').toUpperCase()+'</span></span></div>' +
      '<div class="info-row"><span class="info-label">Input Policy</span><span class="info-val"><span class="badge '+(fw.input_policy==='drop'?'badge-red':'badge-green')+'">'+(fw.input_policy||'accept').toUpperCase()+'</span></span></div>' +
      '<div class="info-row"><span class="info-label">Output Policy</span><span class="info-val"><span class="badge badge-green">'+(fw.output_policy||'accept').toUpperCase()+'</span></span></div>' +
      '<div class="info-row"><span class="info-label">Total Rules</span><span class="info-val">'+ruleCount+'</span></div>';
  }).catch(() => {
    const el = document.getElementById('dash-fw-summary');
    if (el) el.innerHTML = '<div class="info-row"><span class="info-label">Unable to load firewall status</span></div>';
  });
}

})();
