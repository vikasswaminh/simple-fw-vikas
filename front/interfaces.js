// ═══════════════════════════════════════════════════════════════════
// QuickFW Interfaces Page
// ═══════════════════════════════════════════════════════════════════
(function() {
const { esc, fmtBytes } = QFW.util;

QFW.registerPage('interfaces', {
  init(page) {
    page.innerHTML = `
      <div class="page-header">
        <div><h1>Network Interfaces</h1><p class="page-sub">Configure and monitor all network interfaces</p></div>
        <button class="btn-secondary" id="iface-refresh-btn">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14"><path d="M23 4v6h-6M1 20v-6h6"/><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/></svg>
          Refresh
        </button>
      </div>
      <div class="card">
        <div class="card-body" style="padding:0;">
          <table class="data-table">
            <thead><tr><th>Interface</th><th>MAC</th><th>Status</th><th>IPv4</th><th>MTU</th><th>Speed</th><th>Role</th><th>RX / TX</th><th>Errors</th><th>Actions</th></tr></thead>
            <tbody id="interfaces-body"><tr><td colspan="10" class="table-empty">Loading\u2026</td></tr></tbody>
          </table>
        </div>
      </div>
      <div id="iface-modal-container"></div>
    `;
    page.querySelector('#iface-refresh-btn').onclick = () => this.load(page);
  },

  load(page) {
    Promise.all([
      QFW.api.get('/api/interfaces'),
      QFW.api.get('/api/interfaces/roles')
    ]).then(([iData, rData]) => {
      QFW.interfaces = iData.interfaces||[];
      QFW.roles = {};
      (rData.roles||[]).forEach(r => { QFW.roles[r.interface]={role:r.role,zone:r.zone}; });

      const tbody = document.getElementById('interfaces-body');
      if (!QFW.interfaces.length) { tbody.innerHTML = '<tr><td colspan="10" class="table-empty">No interfaces detected.</td></tr>'; return; }
      tbody.innerHTML = QFW.interfaces.map(i => {
        const role = i.role||'';
        const rb = role ? '<span class="role-badge role-'+role+'">'+role.toUpperCase()+'</span>' : '<span class="role-badge role-none">Unset</span>';
        return '<tr>'
          +'<td><strong>'+esc(i.name)+'</strong>'+(i.description?'<br><span style="color:var(--text-light);font-size:11px;">'+esc(i.description)+'</span>':'')+'</td>'
          +'<td class="iface-mac">'+(i.mac||'\u2014')+'</td>'
          +'<td><span class="'+(i.link_up?'iface-up':'iface-down')+'">'+(i.link_up?'UP':'DOWN')+'</span></td>'
          +'<td class="mono">'+(i.ipv4_addrs.join(', ')||'\u2014')+'</td>'
          +'<td>'+i.mtu+'</td>'
          +'<td>'+(i.speed||'\u2014')+'</td>'
          +'<td>'+rb+'</td>'
          +'<td class="mono">'+fmtBytes(i.rx_bytes)+' / '+fmtBytes(i.tx_bytes)+'</td>'
          +'<td>'+(i.rx_errors+i.tx_errors)+' / '+(i.rx_dropped+i.tx_dropped)+'</td>'
          +'<td><button class="btn-xs iface-edit-btn" data-name="'+esc(i.name)+'">Edit</button></td>'
          +'</tr>';
      }).join('');

      // Attach edit handlers
      tbody.querySelectorAll('.iface-edit-btn').forEach(btn => {
        btn.onclick = () => openIfaceModal(btn.dataset.name);
      });
    }).catch(() => {
      document.getElementById('interfaces-body').innerHTML = '<tr><td colspan="10" class="table-empty">Failed to load.</td></tr>';
    });
  }
});

function openIfaceModal(name) {
  const i = QFW.interfaces.find(x => x.name === name);
  const roleData = QFW.roles[name] || {};

  let body = '<input type="hidden" id="im-name" value="'+esc(name)+'">';
  body += '<div class="form-grid">';
  body += '<div class="form-group"><label>Mode</label><select id="im-mode" class="form-select"><option value="">No change</option><option value="dhcp">DHCP</option><option value="static">Static</option></select></div>';
  body += '<div class="form-group"><label>MTU</label><input type="number" id="im-mtu" placeholder="1500" value="'+(i?i.mtu:'')+'"></div>';
  body += '<div class="form-group" id="im-addr-group"><label>IP Address / CIDR</label><input type="text" id="im-address" placeholder="192.168.1.1/24" value="'+(i?(i.ipv4_addrs[0]||''):'')+'"></div>';
  body += '<div class="form-group" id="im-gw-group"><label>Gateway</label><input type="text" id="im-gateway" placeholder="192.168.1.254"></div>';
  body += '<div class="form-group full-width" id="im-dns-group"><label>DNS Servers (comma-separated)</label><input type="text" id="im-dns" placeholder="8.8.8.8, 1.1.1.1"></div>';
  body += '<div class="form-group full-width"><label>Description</label><input type="text" id="im-description" placeholder="Optional description" value="'+esc(i?i.description||'':'')+'"></div>';
  body += '<div class="form-group"><label>Role</label><select id="im-role" class="form-select"><option value="">Unset</option><option value="wan"'+(roleData.role==='wan'?' selected':'')+'>WAN</option><option value="lan"'+(roleData.role==='lan'?' selected':'')+'>LAN</option><option value="dmz"'+(roleData.role==='dmz'?' selected':'')+'>DMZ</option></select></div>';
  body += '<div class="form-group"><label>Link State</label><select id="im-enabled" class="form-select"><option value="">No change</option><option value="true">Up (enabled)</option><option value="false">Down (disabled)</option></select></div>';
  body += '</div>';

  QFW.openModal({
    title: 'Configure: ' + name,
    width: '520px',
    body: body,
    footer: '<button class="btn-secondary modal-close-btn">Cancel</button><button class="btn-primary modal-save-btn">Apply</button>',
    onOpen(modalEl) {
      // Toggle static fields
      const modeSelect = modalEl.querySelector('#im-mode');
      function toggleStatic() {
        const mode = modeSelect.value;
        ['im-addr-group','im-gw-group','im-dns-group'].forEach(id => {
          const g = modalEl.querySelector('#'+id);
          if (g) g.style.display = (mode==='dhcp') ? 'none' : '';
        });
      }
      modeSelect.onchange = toggleStatic;
      toggleStatic();

      modalEl.querySelector('.modal-save-btn').onclick = function() {
        const body = {
          name: name,
          mode: modeSelect.value || '',
          address: modalEl.querySelector('#im-address').value.trim(),
          gateway: modalEl.querySelector('#im-gateway').value.trim(),
          dns: modalEl.querySelector('#im-dns').value.trim() ? modalEl.querySelector('#im-dns').value.split(',').map(s=>s.trim()).filter(Boolean) : [],
        };
        const mtu = modalEl.querySelector('#im-mtu').value;
        if (mtu) body.mtu = parseInt(mtu);
        const enabledVal = modalEl.querySelector('#im-enabled').value;
        if (enabledVal) body.enabled = enabledVal === 'true';
        const desc = modalEl.querySelector('#im-description').value.trim();
        body.description = desc;

        QFW.api.post('/api/interfaces/config', body).then(() => {
          // Save role
          const role = modalEl.querySelector('#im-role').value;
          QFW.roles[name] = { role, zone: role };
          const roles = Object.entries(QFW.roles).filter(([_,v])=>v.role).map(([k,v])=>({interface:k,role:v.role,zone:v.zone}));
          QFW.api.post('/api/interfaces/roles', {roles}).catch(()=>{});
          modalEl.remove();
          QFW.toast('Interface '+name+' configured', 'success');
          QFW.showPage('interfaces');
        }).catch(e => QFW.toast('Failed: '+e.message, 'error'));
      };
    }
  });
}

})();
