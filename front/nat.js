// ═══════════════════════════════════════════════════════════════════
// QuickFW NAT / Routing — masquerade, port forwarding, static routes
// ═══════════════════════════════════════════════════════════════════
(function() {
const { esc, fmtBytes, ifaceOpts } = QFW.util;
let masqRules = [], pfRules = [], routes = [];

QFW.registerPage('nat', {
  init(page) {
    page.innerHTML = `
      <div class="page-header">
        <div><h1>NAT / Routing</h1><p class="page-sub">Address translation and static routing via nftables</p></div>
        <button class="btn-primary" id="nat-save-all">Apply All Changes</button>
      </div>

      <!-- Masquerade -->
      <div class="card">
        <div class="card-header"><h2>Masquerade (SNAT)</h2><button class="btn-xs" id="nat-add-masq">+ Add</button></div>
        <div class="card-body" style="padding:0;">
          <table class="data-table"><thead><tr><th>WAN Interface</th><th>Source CIDR</th><th style="width:80px;">Actions</th></tr></thead>
          <tbody id="masquerade-body"><tr><td colspan="3" class="table-empty">No masquerade rules.</td></tr></tbody></table>
        </div>
      </div>

      <!-- Port Forward -->
      <div class="card">
        <div class="card-header"><h2>Port Forwarding (DNAT)</h2><button class="btn-xs" id="nat-add-pf">+ Add</button></div>
        <div id="pf-flow-diagrams" class="card-body" style="padding:8px 16px 0;border-bottom:1px solid var(--border);display:none;"></div>
        <div class="card-body" style="padding:0;">
          <table class="data-table"><thead><tr><th>Protocol</th><th>WAN Port</th><th>Forward To (ip:port)</th><th>In Interface</th><th style="width:80px;">Actions</th></tr></thead>
          <tbody id="portforward-body"><tr><td colspan="5" class="table-empty">No port forward rules.</td></tr></tbody></table>
        </div>
      </div>

      <!-- Static Routes -->
      <div class="card">
        <div class="card-header"><h2>Static Routes</h2><button class="btn-xs" id="nat-add-route">+ Add</button></div>
        <div class="card-body" style="padding:0;">
          <table class="data-table"><thead><tr><th>Destination</th><th>Gateway</th><th>Interface</th><th>Metric</th><th style="width:80px;">Actions</th></tr></thead>
          <tbody id="routes-body"><tr><td colspan="5" class="table-empty">No static routes.</td></tr></tbody></table>
        </div>
      </div>
    `;
    page.querySelector('#nat-add-masq').onclick = () => openMasqModal(-1);
    page.querySelector('#nat-add-pf').onclick = () => openPfModal(-1);
    page.querySelector('#nat-add-route').onclick = () => openRouteModal(-1);
    page.querySelector('#nat-save-all').onclick = saveAll;
  },

  load(page) {
    Promise.all([
      QFW.api.get('/api/nat'),
      QFW.api.get('/api/routes'),
      QFW.api.get('/api/interfaces')
    ]).then(([natData, rtData, iData]) => {
      QFW.interfaces = iData.interfaces||[];
      masqRules = natData.masquerade || [];
      pfRules = natData.port_forward || [];
      routes = (rtData.routes || []);
      renderMasq();
      renderPf();
      renderRoutes();
    }).catch(()=>{});
  }
});

function renderMasq() {
  const tb = document.getElementById('masquerade-body');
  if (!masqRules.length) { tb.innerHTML = '<tr><td colspan="3" class="table-empty">No masquerade rules.</td></tr>'; return; }
  tb.innerHTML = masqRules.map((r,i) =>
    '<tr><td>'+esc(r.out_interface||'')+'</td><td class="mono">'+esc(r.source_cidr||'')+'</td><td><button class="btn-xs masq-edit" data-idx="'+i+'">Edit</button> <button class="btn-xs masq-del" data-idx="'+i+'" style="color:var(--danger);">Del</button></td></tr>'
  ).join('');
  tb.querySelectorAll('.masq-edit').forEach(b => { b.onclick = () => openMasqModal(parseInt(b.dataset.idx)); });
  tb.querySelectorAll('.masq-del').forEach(b => { b.onclick = () => { masqRules.splice(parseInt(b.dataset.idx),1); renderMasq(); }; });
}

function renderPf() {
  const tb = document.getElementById('portforward-body');
  const flowEl = document.getElementById('pf-flow-diagrams');
  if (!pfRules.length) { tb.innerHTML = '<tr><td colspan="5" class="table-empty">No port forward rules.</td></tr>'; flowEl.style.display='none'; return; }
  tb.innerHTML = pfRules.map((r,i) =>
    '<tr><td>'+esc(r.protocol||'tcp').toUpperCase()+'</td><td>'+esc(String(r.dest_port||''))+'</td><td class="mono">'+esc(r.forward_to||'')+'</td><td>'+esc(r.in_interface||'')+'</td><td><button class="btn-xs pf-edit" data-idx="'+i+'">Edit</button> <button class="btn-xs pf-del" data-idx="'+i+'" style="color:var(--danger);">Del</button></td></tr>'
  ).join('');
  tb.querySelectorAll('.pf-edit').forEach(b => { b.onclick = () => openPfModal(parseInt(b.dataset.idx)); });
  tb.querySelectorAll('.pf-del').forEach(b => { b.onclick = () => { pfRules.splice(parseInt(b.dataset.idx),1); renderPf(); }; });
  // Flow diagrams
  flowEl.style.display = '';
  flowEl.innerHTML = pfRules.map(r =>
    '<div class="flow-diagram"><span class="flow-box">WAN:'+esc(String(r.dest_port||'?'))+'</span><span class="flow-arrow">\u2500\u2500'+esc((r.protocol||'tcp').toUpperCase())+'\u2500\u2500\u25B6</span><span class="flow-box">'+esc(r.forward_to||'?')+'</span></div>'
  ).join('');
}

function renderRoutes() {
  const tb = document.getElementById('routes-body');
  if (!routes.length) { tb.innerHTML = '<tr><td colspan="5" class="table-empty">No static routes.</td></tr>'; return; }
  tb.innerHTML = routes.map((r,i) =>
    '<tr><td class="mono">'+esc(r.destination||'')+'</td><td class="mono">'+esc(r.gateway||'')+'</td><td>'+esc(r.interface||'')+'</td><td>'+esc(String(r.metric||0))+'</td><td><button class="btn-xs rt-edit" data-idx="'+i+'">Edit</button> <button class="btn-xs rt-del" data-idx="'+i+'" style="color:var(--danger);">Del</button></td></tr>'
  ).join('');
  tb.querySelectorAll('.rt-edit').forEach(b => { b.onclick = () => openRouteModal(parseInt(b.dataset.idx)); });
  tb.querySelectorAll('.rt-del').forEach(b => { b.onclick = () => { routes.splice(parseInt(b.dataset.idx),1); renderRoutes(); }; });
}

function openMasqModal(idx) {
  const isNew = idx === -1;
  const r = isNew ? {out_interface:'',source_cidr:''} : {...masqRules[idx]};
  QFW.openModal({
    title: isNew ? 'Add Masquerade Rule' : 'Edit Masquerade Rule',
    body: '<div class="form-grid"><div class="form-group"><label>WAN Interface</label><select id="masq-iface" class="form-select">'+ifaceOpts(r.out_interface)+'</select></div><div class="form-group"><label>Source CIDR <span class="required">*</span></label><input type="text" id="masq-cidr" value="'+esc(r.source_cidr||'')+'" placeholder="192.168.1.0/24"></div></div>',
    onOpen(m) {
      m.querySelector('.modal-save-btn').onclick = () => {
        const iface = m.querySelector('#masq-iface').value;
        const cidr = m.querySelector('#masq-cidr').value.trim();
        if (!cidr) { QFW.toast('Source CIDR is required','error'); return; }
        if (!cidr.includes('/')) { QFW.toast('CIDR format required (e.g. 192.168.1.0/24)','error'); return; }
        const rule = { out_interface: iface==='any'?'':iface, source_cidr: cidr };
        if (isNew) masqRules.push(rule); else masqRules[idx] = rule;
        m.remove(); renderMasq();
      };
    }
  });
}

function openPfModal(idx) {
  const isNew = idx === -1;
  const r = isNew ? {protocol:'tcp',dest_port:'',forward_to:'',in_interface:''} : {...pfRules[idx]};
  QFW.openModal({
    title: isNew ? 'Add Port Forward' : 'Edit Port Forward',
    body: '<div class="form-grid"><div class="form-group"><label>Protocol</label><select id="pf-proto" class="form-select"><option value="tcp"'+(r.protocol==='tcp'?' selected':'')+'>TCP</option><option value="udp"'+(r.protocol==='udp'?' selected':'')+'>UDP</option></select></div><div class="form-group"><label>WAN Port <span class="required">*</span></label><input type="number" id="pf-port" value="'+(r.dest_port||'')+'" placeholder="8080"></div><div class="form-group"><label>Forward To (ip:port) <span class="required">*</span></label><input type="text" id="pf-fwd" value="'+esc(r.forward_to||'')+'" placeholder="192.168.1.10:80"></div><div class="form-group"><label>In Interface</label><select id="pf-iface" class="form-select">'+ifaceOpts(r.in_interface)+'</select></div></div>',
    onOpen(m) {
      m.querySelector('.modal-save-btn').onclick = () => {
        const port = parseInt(m.querySelector('#pf-port').value);
        const fwd = m.querySelector('#pf-fwd').value.trim();
        if (!port || port < 1 || port > 65535) { QFW.toast('Valid port required (1-65535)','error'); return; }
        if (!fwd || !fwd.includes(':')) { QFW.toast('Forward To must be ip:port format','error'); return; }
        const rule = { protocol: m.querySelector('#pf-proto').value, dest_port: port, forward_to: fwd, in_interface: m.querySelector('#pf-iface').value==='any'?'':m.querySelector('#pf-iface').value };
        if (isNew) pfRules.push(rule); else pfRules[idx] = rule;
        m.remove(); renderPf();
      };
    }
  });
}

function openRouteModal(idx) {
  const isNew = idx === -1;
  const r = isNew ? {destination:'',gateway:'',interface:'',metric:0} : {...routes[idx]};
  QFW.openModal({
    title: isNew ? 'Add Static Route' : 'Edit Static Route',
    body: '<div class="form-grid"><div class="form-group"><label>Destination CIDR <span class="required">*</span></label><input type="text" id="rt-dest" value="'+esc(r.destination||'')+'" placeholder="10.0.0.0/8"></div><div class="form-group"><label>Gateway <span class="required">*</span></label><input type="text" id="rt-gw" value="'+esc(r.gateway||'')+'" placeholder="192.168.1.1"></div><div class="form-group"><label>Interface</label><select id="rt-iface" class="form-select">'+ifaceOpts(r.interface)+'</select></div><div class="form-group"><label>Metric</label><input type="number" id="rt-metric" value="'+(r.metric||0)+'" placeholder="0"></div></div>',
    onOpen(m) {
      m.querySelector('.modal-save-btn').onclick = () => {
        const dest = m.querySelector('#rt-dest').value.trim();
        const gw = m.querySelector('#rt-gw').value.trim();
        if (!dest || !gw) { QFW.toast('Destination and Gateway required','error'); return; }
        const route = { destination: dest, gateway: gw, interface: m.querySelector('#rt-iface').value==='any'?'':m.querySelector('#rt-iface').value, metric: parseInt(m.querySelector('#rt-metric').value)||0 };
        if (isNew) routes.push(route); else routes[idx] = route;
        m.remove(); renderRoutes();
      };
    }
  });
}

function saveAll() {
  Promise.all([
    QFW.api.post('/api/nat', {masquerade:masqRules, port_forward:pfRules}),
    QFW.api.post('/api/routes', {routes})
  ]).then(() => QFW.toast('NAT and routes applied ('+masqRules.length+' masq, '+pfRules.length+' fwd, '+routes.length+' routes)', 'success'))
  .catch(e => QFW.toast('Save failed: '+e.message, 'error'));
}

})();
