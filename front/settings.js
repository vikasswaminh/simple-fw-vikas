// ═══════════════════════════════════════════════════════════════════
// QuickFW Settings — system config, config export/import, appliance
// ═══════════════════════════════════════════════════════════════════
(function() {
const { esc } = QFW.util;
const TABS = ['system','appliance'];

QFW.registerPage('settings', {
  init(page) {
    page.innerHTML = `
      <div class="page-header"><div><h1>Settings</h1><p class="page-sub">Appliance configuration</p></div></div>

      <div class="sub-tabs">
        <div class="sub-tab active" data-stab="system">System</div>
        <div class="sub-tab" data-stab="appliance">Appliance</div>
      </div>

      <!-- System -->
      <div class="sub-content active" id="stab-system">
        <div class="card"><div class="card-header"><h2>System Settings</h2></div><div class="card-body">
          <div class="form-grid">
            <div class="form-group"><label>Hostname</label><input type="text" id="set-hostname"></div>
            <div class="form-group"><label>Timezone</label><input type="text" id="set-timezone" placeholder="e.g. America/New_York"></div>
            <div class="form-group full-width"><label>DNS Servers (comma-separated)</label><input type="text" id="set-dns" placeholder="8.8.8.8, 1.1.1.1"></div>
            <div class="form-group full-width"><label>NTP Servers (comma-separated)</label><input type="text" id="set-ntp" placeholder="0.pool.ntp.org, 1.pool.ntp.org"></div>
          </div>
          <div style="margin-top:14px;"><button class="btn-primary" id="save-system-btn">Save System Settings</button></div>
        </div></div>
      </div>

      <!-- Appliance -->
      <div class="sub-content" id="stab-appliance">
        <div class="card"><div class="card-header"><h2>Configuration Management</h2></div><div class="card-body">
          <div class="btn-group">
            <button class="btn-secondary" id="export-config-btn">Export Config (JSON)</button>
            <label class="btn-secondary" style="cursor:pointer;">Import Config<input type="file" id="import-file" accept=".json" style="display:none;"></label>
          </div>
        </div></div>
        <div class="card" style="margin-top:16px;">
          <div class="card-header"><h2>Appliance Controls</h2></div>
          <div class="card-body">
            <p style="font-size:13px;color:var(--text-light);margin-bottom:12px;">These actions affect the running appliance. Use with caution.</p>
            <div class="btn-group">
              <button class="btn-danger" id="reboot-btn">Reboot Appliance</button>
            </div>
          </div>
        </div>
      </div>
    `;

    // Sub-tab switching
    page.querySelectorAll('.sub-tab').forEach(tab => {
      tab.onclick = () => {
        page.querySelectorAll('.sub-tab').forEach(t => t.classList.remove('active'));
        page.querySelectorAll('.sub-content').forEach(c => c.classList.remove('active'));
        tab.classList.add('active');
        document.getElementById('stab-'+tab.dataset.stab).classList.add('active');
      };
    });

    page.querySelector('#save-system-btn').onclick = saveSystemSettings;
    page.querySelector('#export-config-btn').onclick = exportConfig;
    page.querySelector('#import-file').onchange = function() { importConfig(this); };
    page.querySelector('#reboot-btn').onclick = rebootAppliance;
  },

  load(page) {
    QFW.api.get('/api/settings').then(d => {
      document.getElementById('set-hostname').value = d.hostname||'';
      document.getElementById('set-timezone').value = d.timezone||'';
      document.getElementById('set-dns').value = (d.dns_servers||[]).join(', ');
      document.getElementById('set-ntp').value = (d.ntp_servers||[]).join(', ');
    }).catch(()=>{});
  }
});

function saveSystemSettings() {
  const hostname = document.getElementById('set-hostname').value.trim();
  const timezone = document.getElementById('set-timezone').value.trim();
  const dns_servers = document.getElementById('set-dns').value.split(',').map(s=>s.trim()).filter(Boolean);
  const ntp_servers = document.getElementById('set-ntp').value.split(',').map(s=>s.trim()).filter(Boolean);
  QFW.api.post('/api/settings', {hostname,timezone,dns_servers,ntp_servers})
    .then(() => QFW.toast('System settings saved','success'))
    .catch(e => QFW.toast('Save failed: '+e.message,'error'));
}

function exportConfig() {
  QFW.api.get('/api/config/export').then(d => {
    const blob = new Blob([JSON.stringify(d,null,2)],{type:'application/json'});
    const a = document.createElement('a'); a.href = URL.createObjectURL(blob);
    a.download = 'quickfw-config-'+new Date().toISOString().slice(0,10)+'.json';
    a.click(); URL.revokeObjectURL(a.href);
    QFW.toast('Config exported','success');
  }).catch(e => QFW.toast('Export failed: '+e.message,'error'));
}

function importConfig(input) {
  const file = input.files[0]; if(!file) return;
  const reader = new FileReader();
  reader.onload = function(e) {
    try {
      const cfg = JSON.parse(e.target.result);
      QFW.confirmDialog('Import Config', '<p>Import config from <strong>'+esc(file.name)+'</strong>? This will overwrite current configuration.</p>', 'Import', function() {
        const promises = [];
        if(cfg.firewall) promises.push(QFW.api.post('/api/firewall', cfg.firewall));
        if(cfg.nat) promises.push(QFW.api.post('/api/nat', cfg.nat));
        if(cfg.roles) promises.push(QFW.api.post('/api/interfaces/roles', cfg.roles));
        if(cfg.routes) promises.push(QFW.api.post('/api/routes', cfg.routes));
        if(cfg.settings) promises.push(QFW.api.post('/api/settings', cfg.settings));
        Promise.all(promises).then(() => QFW.toast('Config imported successfully','success')).catch(er => QFW.toast('Import failed: '+er.message,'error'));
      });
    } catch(er) { QFW.toast('Invalid JSON: '+er.message,'error'); }
  };
  reader.readAsText(file);
  input.value = '';
}

function rebootAppliance() {
  QFW.confirmDialog('Reboot Appliance', '<p>This will reboot the entire appliance. All active connections will be dropped.</p><div class="confirm-field"><label>Enter your password to confirm</label><input type="password" id="reboot-confirm-pass"></div>', 'Reboot Now', function() {
    const pass = document.getElementById('reboot-confirm-pass') ? document.getElementById('reboot-confirm-pass').value : '';
    QFW.api.post('/api/system/reboot', {confirm_password:pass})
      .then(() => QFW.toast('Appliance is rebooting...','info'))
      .catch(e => QFW.toast('Reboot failed: '+e.message,'error'));
  });
}

})();
