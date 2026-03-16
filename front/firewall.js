// ═══════════════════════════════════════════════════════════════════
// QuickFW Firewall Rules — card-row rules, edit modal, search,
//                          reorder, templates, counters, zones,
//                          schedules, dry-run
// ═══════════════════════════════════════════════════════════════════
(function() {
const { esc, fmtBytes, ifaceOpts } = QFW.util;
let rules = [], groups = {}, counters = [], zones = [];
const DAYS = ['mon','tue','wed','thu','fri','sat','sun'];
const TEMPLATES = [
  { name:'Allow LAN \u2192 WAN', rule:{ name:'Allow LAN to WAN', enabled:true, direction:'forward', in_interface:'', out_interface:'', protocol:'any', src_ip:'', src_port:'', dst_ip:'', dst_port:'', action:'accept', log:false }},
  { name:'Block All Incoming', rule:{ name:'Block Incoming', enabled:true, direction:'input', in_interface:'', out_interface:'', protocol:'any', src_ip:'', src_port:'', dst_ip:'', dst_port:'', action:'drop', log:true }},
  { name:'Allow SSH', rule:{ name:'Allow SSH', enabled:true, direction:'input', in_interface:'', out_interface:'', protocol:'tcp', src_ip:'', src_port:'', dst_ip:'', dst_port:'22', action:'accept', log:false }},
  { name:'Allow HTTPS', rule:{ name:'Allow HTTPS', enabled:true, direction:'forward', in_interface:'', out_interface:'', protocol:'tcp', src_ip:'', src_port:'', dst_ip:'', dst_port:'443', action:'accept', log:false }},
  { name:'Allow DNS', rule:{ name:'Allow DNS', enabled:true, direction:'forward', in_interface:'', out_interface:'', protocol:'udp', src_ip:'', src_port:'', dst_ip:'', dst_port:'53', action:'accept', log:false }},
  { name:'Business Hours Only', rule:{ name:'Business Hours Web', enabled:true, direction:'forward', in_interface:'', out_interface:'', protocol:'tcp', src_ip:'', src_port:'', dst_ip:'', dst_port:'80,443', action:'accept', log:false, schedule:{days:['mon','tue','wed','thu','fri'],start:'08:00',end:'18:00'} }},
];

QFW.registerPage('firewall', {
  init(page) {
    page.innerHTML = `
      <div class="page-header">
        <div><h1>Firewall Rules</h1><p class="page-sub">L3/L4 stateful packet filtering \u2014 top-down, first match</p></div>
        <div class="btn-group">
          <div style="position:relative;">
            <button class="btn-secondary" id="fw-add-btn">+ Add Rule</button>
            <div class="rule-templates-menu" id="fw-templates-menu"></div>
          </div>
          <button class="btn-secondary" id="fw-preview-btn" title="Preview generated nftables script">Preview nft</button>
          <button class="btn-primary" id="fw-save-btn">Save &amp; Apply</button>
        </div>
      </div>

      <!-- Search / Filter -->
      <div id="fw-search-bar"></div>

      <!-- Policies -->
      <div class="card">
        <div class="card-header"><h2>Chain Default Policies</h2></div>
        <div class="card-body">
          <div class="policy-grid">
            <div class="policy-item"><label>Input</label><select id="policy-input" class="form-select-sm"><option value="accept">Accept</option><option value="drop">Drop</option></select></div>
            <div class="policy-item"><label>Forward</label><select id="policy-forward" class="form-select-sm"><option value="accept">Accept</option><option value="drop">Drop</option></select></div>
            <div class="policy-item"><label>Output</label><select id="policy-output" class="form-select-sm"><option value="accept">Accept</option><option value="drop">Drop</option></select></div>
          </div>
        </div>
      </div>

      <!-- Groups -->
      <div class="card collapsible">
        <div class="card-header clickable" onclick="this.closest('.card').classList.toggle('collapsed')">
          <h2>Address &amp; Port Groups</h2>
          <span class="collapse-icon">&#9660;</span>
        </div>
        <div class="card-collapse">
          <div class="card-body">
            <div class="groups-split">
              <div>
                <div class="group-header"><strong>Address Groups</strong><button class="btn-xs" id="fw-add-addr-group">+ Add</button></div>
                <div id="addr-groups-container"><div class="table-empty" style="padding:8px;">No address groups.</div></div>
              </div>
              <div>
                <div class="group-header"><strong>Port Groups</strong><button class="btn-xs" id="fw-add-port-group">+ Add</button></div>
                <div id="port-groups-container"><div class="table-empty" style="padding:8px;">No port groups.</div></div>
              </div>
            </div>
            <div style="margin-top:10px;text-align:right;"><button class="btn-secondary" id="fw-save-groups-btn">Save Groups</button></div>
          </div>
        </div>
      </div>

      <!-- Rules list -->
      <div class="card">
        <div class="card-body" id="fw-rules-list">
          <div class="empty-state"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" width="36" height="36"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg><span>No rules. Click "+ Add Rule" to create one.</span></div>
        </div>
      </div>
    `;

    // Templates menu
    const menu = page.querySelector('#fw-templates-menu');
    menu.innerHTML = TEMPLATES.map((t,i) => '<div class="rule-template-item" data-idx="'+i+'">'+esc(t.name)+'</div>').join('') + '<div class="rule-template-item" data-idx="-1" style="border-top:1px solid var(--border);font-weight:600;">Blank Rule</div>';
    const addBtn = page.querySelector('#fw-add-btn');
    addBtn.onclick = () => menu.classList.toggle('show');
    menu.querySelectorAll('.rule-template-item').forEach(item => {
      item.onclick = () => {
        menu.classList.remove('show');
        const idx = parseInt(item.dataset.idx);
        const tmpl = idx >= 0 ? JSON.parse(JSON.stringify(TEMPLATES[idx].rule)) : { name:'', enabled:true, direction:'forward', in_interface:'', out_interface:'', protocol:'any', src_ip:'', src_port:'', dst_ip:'', dst_port:'', action:'accept', log:false, src_zone:'', dst_zone:'', comment:'', schedule:null };
        openRuleModal(-1, tmpl);
      };
    });
    document.addEventListener('click', e => { if (!addBtn.contains(e.target) && !menu.contains(e.target)) menu.classList.remove('show'); });

    page.querySelector('#fw-save-btn').onclick = saveFirewallRules;
    page.querySelector('#fw-preview-btn').onclick = previewDryRun;
    page.querySelector('#fw-save-groups-btn').onclick = saveGroups;
    page.querySelector('#fw-add-addr-group').onclick = addAddrGroup;
    page.querySelector('#fw-add-port-group').onclick = addPortGroup;

    // Search bar
    QFW.components.SearchBar({
      container: page.querySelector('#fw-search-bar'),
      placeholder: 'Search rules by name, IP, port, zone\u2026',
      filters: [
        { key:'direction', label:'Direction', options:['forward','input','output'] },
        { key:'action', label:'Action', options:['accept','drop','reject'] },
        { key:'protocol', label:'Protocol', options:['tcp','udp','icmp','any'] },
      ],
      onFilter(q, filters) { filterRules(q, filters); }
    });
  },

  load(page) {
    Promise.all([
      QFW.api.get('/api/firewall'),
      QFW.api.get('/api/interfaces'),
      QFW.api.get('/api/firewall/groups').catch(()=>({address_groups:[],port_groups:[]})),
      QFW.api.get('/api/firewall/counters').catch(()=>({counters:[]})),
      QFW.api.get('/api/interfaces/roles').catch(()=>({}))
    ]).then(([fw, iData, g, ctr, rolesData]) => {
      QFW.interfaces = iData.interfaces||[];
      rules = fw.rules || [];
      groups = g;
      counters = ctr.counters || [];
      // Build zone list from interface roles and firewall config zones
      zones = [];
      const zoneSet = new Set();
      if (fw.zones) fw.zones.forEach(z => { if (z.zone && !zoneSet.has(z.zone)) { zoneSet.add(z.zone); zones.push(z.zone); } });
      if (rolesData && typeof rolesData === 'object') {
        Object.values(rolesData).forEach(v => { if (v && v.zone && !zoneSet.has(v.zone)) { zoneSet.add(v.zone); zones.push(v.zone); } });
      }
      if (fw.input_policy) document.getElementById('policy-input').value = fw.input_policy;
      if (fw.forward_policy) document.getElementById('policy-forward').value = fw.forward_policy;
      if (fw.output_policy) document.getElementById('policy-output').value = fw.output_policy;
      renderRules();
      renderGroups(g);
    }).catch(()=>{});
  }
});

// ─── Rule rendering ───

function renderRules() {
  const container = document.getElementById('fw-rules-list');
  if (!rules.length) {
    container.innerHTML = '<div class="empty-state"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" width="36" height="36"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg><span>No rules. Click "+ Add Rule".</span></div>';
    return;
  }
  container.innerHTML = '<div class="rule-list">' + rules.map((r, idx) => renderRuleCard(r, idx)).join('') + '</div>';
  attachRuleEvents(container);
}

function findCounter(r) {
  if (!counters.length || !r.name) return null;
  return counters.find(c => c.comment === r.name) || null;
}

function formatCount(n) {
  if (n >= 1000000) return (n/1000000).toFixed(1)+'M';
  if (n >= 1000) return (n/1000).toFixed(1)+'K';
  return String(n);
}

function renderRuleCard(r, idx) {
  const dirCls = {forward:'fwd',input:'in',output:'out'}[r.direction]||'fwd';
  const actCls = r.action || 'accept';
  const proto = (r.protocol||'any').toUpperCase();
  const srcIp = r.src_ip || '*';
  const srcPort = r.src_port || '*';
  const dstIp = r.dst_ip || '*';
  const dstPort = r.dst_port || '*';
  const inIf = r.in_interface || (r.src_zone ? '@'+r.src_zone : '*');
  const outIf = r.out_interface || (r.dst_zone ? '@'+r.dst_zone : '*');
  const summary = proto + ' ' + srcIp + ':' + srcPort + ' \u2192 ' + dstIp + ':' + dstPort;
  const ctr = findCounter(r);

  // Build meta line
  const meta = [];
  if (r.comment) meta.push(esc(r.comment));
  if (r.src_zone) meta.push('src-zone: '+esc(r.src_zone));
  if (r.dst_zone) meta.push('dst-zone: '+esc(r.dst_zone));
  if (r.schedule && r.schedule.days && r.schedule.days.length) {
    const s = r.schedule;
    let sched = '';
    if (s.days.length < 7) sched += s.days.map(d => d.substring(0,3)).join(',');
    else sched += 'daily';
    if (s.start || s.end) sched += ' ' + (s.start||'00:00') + '\u2013' + (s.end||'23:59');
    meta.push('\u23F0 ' + sched.trim());
  }

  return '<div class="rule-card'+(r.enabled===false?' disabled':'')+'" data-idx="'+idx+'">'
    +'<span class="rule-num">'+(idx+1)+'</span>'
    +'<div class="rule-toggle-wrap"><label class="toggle" style="width:34px;height:18px;"><input type="checkbox" class="rule-enabled-chk" data-idx="'+idx+'"'+(r.enabled!==false?' checked':'')+'><span class="toggle-slider" style="border-radius:18px;"><span style="position:absolute;width:12px;height:12px;left:3px;top:3px;background:white;border-radius:50%;transition:transform 0.2s;"></span></span></label></div>'
    +'<div class="rule-summary">'
    +'<div class="rule-summary-line"><span class="rule-badge '+dirCls+'">'+(r.direction||'FWD').substring(0,3).toUpperCase()+'</span> '
    +(inIf!=='*'?esc(inIf):'*')+'\u2192'+(outIf!=='*'?esc(outIf):'*')+' | '+esc(summary)+' | <span class="rule-badge '+actCls+'">'+(r.action||'accept').toUpperCase()+'</span>'+(r.log?' <span style="font-size:10px;color:var(--text-muted);">LOG</span>':'')+'</div>'
    +'<div class="rule-summary-name">'+(r.name?esc(r.name):'<em>unnamed</em>')
    +(meta.length?' <span class="rule-meta">\u2014 '+meta.join(' \u00B7 ')+'</span>':'')
    +'</div>'
    +'</div>'
    +(ctr ? '<div class="rule-counter" title="'+ctr.packets+' packets / '+fmtBytes(ctr.bytes)+'"><span class="counter-pkts">'+formatCount(ctr.packets)+' pkts</span><span class="counter-bytes">'+fmtBytes(ctr.bytes)+'</span></div>' : '')
    +'<div class="rule-actions">'
    +'<button class="el-btn rule-move-up" data-idx="'+idx+'" title="Move up"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14"><polyline points="18 15 12 9 6 15"/></svg></button>'
    +'<button class="el-btn rule-move-down" data-idx="'+idx+'" title="Move down"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14"><polyline points="6 9 12 15 18 9"/></svg></button>'
    +'<button class="el-btn rule-edit" data-idx="'+idx+'" title="Edit"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg></button>'
    +'<button class="el-btn el-del rule-delete" data-idx="'+idx+'" title="Delete"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg></button>'
    +'</div>'
    +'</div>';
}

function attachRuleEvents(container) {
  container.querySelectorAll('.rule-enabled-chk').forEach(chk => {
    chk.onchange = () => { rules[parseInt(chk.dataset.idx)].enabled = chk.checked; renderRules(); };
  });
  container.querySelectorAll('.rule-edit').forEach(btn => {
    btn.onclick = () => openRuleModal(parseInt(btn.dataset.idx));
  });
  container.querySelectorAll('.rule-delete').forEach(btn => {
    btn.onclick = () => { rules.splice(parseInt(btn.dataset.idx), 1); renderRules(); };
  });
  container.querySelectorAll('.rule-move-up').forEach(btn => {
    btn.onclick = () => { const i=parseInt(btn.dataset.idx); if(i>0){const t=rules[i];rules[i]=rules[i-1];rules[i-1]=t;renderRules();} };
  });
  container.querySelectorAll('.rule-move-down').forEach(btn => {
    btn.onclick = () => { const i=parseInt(btn.dataset.idx); if(i<rules.length-1){const t=rules[i];rules[i]=rules[i+1];rules[i+1]=t;renderRules();} };
  });
}

// ─── Rule modal (with zones + schedule) ───

function zoneOpts(sel) {
  let h = '<option value="">None</option>';
  zones.forEach(z => { h += '<option value="'+esc(z)+'"'+(z===sel?' selected':'')+'>'+esc(z)+'</option>'; });
  return h;
}

function openRuleModal(idx, preset) {
  const isNew = idx === -1;
  const r = isNew ? (preset||{name:'',enabled:true,direction:'forward',in_interface:'',out_interface:'',protocol:'any',src_ip:'',src_port:'',dst_ip:'',dst_port:'',action:'accept',log:false,src_zone:'',dst_zone:'',comment:'',schedule:null}) : JSON.parse(JSON.stringify(rules[idx]));
  const sched = r.schedule || {days:[],start:'',end:''};
  const hasSched = !!(sched.days && sched.days.length);

  let body = '<div class="form-grid">';
  body += '<div class="form-group full-width"><label>Rule Name</label><input type="text" id="rule-name" value="'+esc(r.name||'')+'" placeholder="e.g. Allow Web Traffic"></div>';
  body += '<div class="form-group"><label>Direction</label><select id="rule-dir" class="form-select"><option value="forward"'+(r.direction==='forward'?' selected':'')+'>Forward</option><option value="input"'+(r.direction==='input'?' selected':'')+'>Input</option><option value="output"'+(r.direction==='output'?' selected':'')+'>Output</option></select></div>';
  body += '<div class="form-group"><label>Enabled</label><label class="toggle"><input type="checkbox" id="rule-enabled"'+(r.enabled!==false?' checked':'')+'><span class="toggle-slider"></span></label></div>';
  body += '</div>';

  // Match criteria
  body += '<h3 class="modal-section-hdr">Match Criteria</h3>';
  body += '<div class="form-grid">';
  body += '<div class="form-group"><label>Protocol</label><select id="rule-proto" class="form-select"><option value="any"'+(r.protocol==='any'?' selected':'')+'>Any</option><option value="tcp"'+(r.protocol==='tcp'?' selected':'')+'>TCP</option><option value="udp"'+(r.protocol==='udp'?' selected':'')+'>UDP</option><option value="tcp+udp"'+(r.protocol==='tcp+udp'?' selected':'')+'>TCP+UDP</option><option value="icmp"'+(r.protocol==='icmp'?' selected':'')+'>ICMP</option></select></div>';
  body += '<div class="form-group"><label>In Interface</label><select id="rule-in" class="form-select">'+ifaceOpts(r.in_interface||'any')+'</select></div>';
  body += '<div class="form-group"><label>Source IP</label><input type="text" id="rule-sip" value="'+esc(r.src_ip||'')+'" placeholder="any or CIDR"></div>';
  body += '<div class="form-group"><label>Source Port</label><input type="text" id="rule-sport" value="'+esc(r.src_port||'')+'" placeholder="any or port"></div>';
  body += '<div class="form-group"><label>Out Interface</label><select id="rule-out" class="form-select">'+ifaceOpts(r.out_interface||'any')+'</select></div>';
  body += '<div class="form-group"><label>Destination IP</label><input type="text" id="rule-dip" value="'+esc(r.dst_ip||'')+'" placeholder="any or CIDR"></div>';
  body += '<div class="form-group"><label>Destination Port</label><input type="text" id="rule-dport" value="'+esc(r.dst_port||'')+'" placeholder="any or port"></div>';
  body += '</div>';

  // Zones
  if (zones.length) {
    body += '<h3 class="modal-section-hdr">Zone Matching</h3>';
    body += '<div class="form-grid">';
    body += '<div class="form-group"><label>Source Zone</label><select id="rule-src-zone" class="form-select">'+zoneOpts(r.src_zone||'')+'</select><span class="form-hint">Overrides In Interface if set</span></div>';
    body += '<div class="form-group"><label>Destination Zone</label><select id="rule-dst-zone" class="form-select">'+zoneOpts(r.dst_zone||'')+'</select><span class="form-hint">Overrides Out Interface if set</span></div>';
    body += '</div>';
  }

  // Action
  body += '<h3 class="modal-section-hdr">Action</h3>';
  body += '<div class="form-grid">';
  body += '<div class="form-group"><label>Action</label><select id="rule-action" class="form-select"><option value="accept"'+(r.action==='accept'?' selected':'')+'>Accept</option><option value="drop"'+(r.action==='drop'?' selected':'')+'>Drop</option><option value="reject"'+(r.action==='reject'?' selected':'')+'>Reject</option></select></div>';
  body += '<div class="form-group"><label>Log</label><label class="toggle"><input type="checkbox" id="rule-log"'+(r.log?' checked':'')+'><span class="toggle-slider"></span></label></div>';
  body += '<div class="form-group full-width"><label>Comment</label><input type="text" id="rule-comment" value="'+esc(r.comment||'')+'" placeholder="Optional note"></div>';
  body += '</div>';

  // Schedule
  body += '<h3 class="modal-section-hdr">Schedule <span style="font-weight:400;font-size:11px;color:var(--text-muted);">(optional \u2014 restrict when rule is active)</span></h3>';
  body += '<div class="schedule-toggle"><label class="toggle"><input type="checkbox" id="rule-sched-enable"'+(hasSched?' checked':'')+'><span class="toggle-slider"></span></label><span style="margin-left:8px;font-size:13px;">Enable time-based schedule</span></div>';
  body += '<div class="schedule-fields" id="rule-sched-fields" style="'+(hasSched?'':'display:none;')+'">';
  body += '<div class="sched-days">';
  DAYS.forEach(d => {
    const checked = sched.days && sched.days.includes(d);
    body += '<label class="sched-day-label"><input type="checkbox" class="sched-day-chk" value="'+d+'"'+(checked?' checked':'')+'><span>'+d.charAt(0).toUpperCase()+d.slice(1)+'</span></label>';
  });
  body += '<button class="btn-xs" id="sched-weekdays" style="margin-left:8px;">Weekdays</button>';
  body += '<button class="btn-xs" id="sched-all" style="margin-left:4px;">All</button>';
  body += '</div>';
  body += '<div class="form-grid" style="margin-top:8px;">';
  body += '<div class="form-group"><label>Start Time</label><input type="time" id="rule-sched-start" value="'+esc(sched.start||'')+'" placeholder="08:00"></div>';
  body += '<div class="form-group"><label>End Time</label><input type="time" id="rule-sched-end" value="'+esc(sched.end||'')+'" placeholder="18:00"></div>';
  body += '</div></div>';

  QFW.openModal({
    title: isNew ? 'Add Firewall Rule' : 'Edit Rule #'+(idx+1),
    width: '640px',
    body: body,
    onOpen(modalEl) {
      // Schedule toggle
      const schedEn = modalEl.querySelector('#rule-sched-enable');
      const schedFields = modalEl.querySelector('#rule-sched-fields');
      schedEn.onchange = () => { schedFields.style.display = schedEn.checked ? '' : 'none'; };
      // Weekdays/All shortcuts
      const dayChks = modalEl.querySelectorAll('.sched-day-chk');
      modalEl.querySelector('#sched-weekdays').onclick = (e) => { e.preventDefault(); dayChks.forEach(c => { c.checked = ['mon','tue','wed','thu','fri'].includes(c.value); }); };
      modalEl.querySelector('#sched-all').onclick = (e) => { e.preventDefault(); dayChks.forEach(c => { c.checked = true; }); };

      // Save
      modalEl.querySelector('.modal-save-btn').onclick = function() {
        const newRule = {
          name: modalEl.querySelector('#rule-name').value.trim(),
          enabled: modalEl.querySelector('#rule-enabled').checked,
          direction: modalEl.querySelector('#rule-dir').value,
          protocol: modalEl.querySelector('#rule-proto').value,
          in_interface: modalEl.querySelector('#rule-in').value==='any'?'':modalEl.querySelector('#rule-in').value,
          out_interface: modalEl.querySelector('#rule-out').value==='any'?'':modalEl.querySelector('#rule-out').value,
          src_ip: modalEl.querySelector('#rule-sip').value.trim(),
          src_port: modalEl.querySelector('#rule-sport').value.trim(),
          dst_ip: modalEl.querySelector('#rule-dip').value.trim(),
          dst_port: modalEl.querySelector('#rule-dport').value.trim(),
          action: modalEl.querySelector('#rule-action').value,
          log: modalEl.querySelector('#rule-log').checked,
          comment: modalEl.querySelector('#rule-comment').value.trim(),
          src_zone: (modalEl.querySelector('#rule-src-zone')||{}).value || '',
          dst_zone: (modalEl.querySelector('#rule-dst-zone')||{}).value || '',
        };

        // Schedule
        if (schedEn.checked) {
          const days = [];
          dayChks.forEach(c => { if (c.checked) days.push(c.value); });
          const start = modalEl.querySelector('#rule-sched-start').value;
          const end = modalEl.querySelector('#rule-sched-end').value;
          if (days.length === 0) { QFW.toast('Select at least one day for schedule', 'error'); return; }
          if (!start || !end) { QFW.toast('Start and end time required for schedule', 'error'); return; }
          newRule.schedule = { days, start, end };
        } else {
          newRule.schedule = null;
        }

        if (isNew) rules.push(newRule); else rules[idx] = newRule;
        modalEl.remove();
        renderRules();
      };
    }
  });
}

// ─── Filter ───

function filterRules(q, filters) {
  document.querySelectorAll('.rule-card').forEach(card => {
    const idx = parseInt(card.dataset.idx);
    const r = rules[idx];
    if (!r) return;
    let show = true;
    if (q) {
      const text = [r.name, r.src_ip, r.dst_ip, r.src_port, r.dst_port, r.protocol, r.action, r.direction, r.src_zone, r.dst_zone, r.comment].join(' ').toLowerCase();
      if (!text.includes(q)) show = false;
    }
    if (filters.direction && r.direction !== filters.direction) show = false;
    if (filters.action && r.action !== filters.action) show = false;
    if (filters.protocol && r.protocol !== filters.protocol) show = false;
    card.style.display = show ? '' : 'none';
  });
}

// ─── Save & Dry-Run ───

function buildConfig() {
  return {
    rules,
    input_policy: document.getElementById('policy-input').value,
    forward_policy: document.getElementById('policy-forward').value,
    output_policy: document.getElementById('policy-output').value,
    zones: Object.entries(QFW.roles||{}).filter(([_,v])=>v&&v.role).map(([k,v])=>({interface:k,zone:v.zone||'',role:v.role})),
  };
}

function saveFirewallRules() {
  QFW.api.post('/api/firewall', buildConfig())
    .then(() => {
      QFW.toast('Firewall: '+rules.length+' rules applied to nftables', 'success');
      QFW.api.get('/api/firewall/counters').then(ctr => { counters = ctr.counters || []; renderRules(); }).catch(()=>{});
    })
    .catch(e => QFW.toast('Apply failed: '+e.message, 'error'));
}

function previewDryRun() {
  QFW.api.post('/api/firewall?dry_run=true', buildConfig())
    .then(result => {
      QFW.openModal({
        title: 'nftables Preview (' + (result.rule_count||0) + ' rules)',
        width: '720px',
        body: '<pre class="nft-preview">' + esc(result.nft_script || '(empty)') + '</pre>',
        onOpen() {}
      });
    })
    .catch(e => QFW.toast('Preview failed: '+e.message, 'error'));
}

// ─── Groups ───

function renderGroups(g) {
  const ac = document.getElementById('addr-groups-container');
  const pc = document.getElementById('port-groups-container');
  ac.innerHTML = ''; pc.innerHTML = '';
  if (!g.address_groups || !g.address_groups.length) ac.innerHTML = '<div class="table-empty" style="padding:8px;">No address groups.</div>';
  else (g.address_groups||[]).forEach((gr,i) => {
    ac.innerHTML += '<div class="group-item"><input placeholder="Group name" value="'+esc(gr.name)+'"><input placeholder="IPs (comma-sep)" value="'+esc((gr.addresses||[]).join(', '))+'"><button class="nat-del" onclick="this.parentElement.remove()">&times;</button></div>';
  });
  if (!g.port_groups || !g.port_groups.length) pc.innerHTML = '<div class="table-empty" style="padding:8px;">No port groups.</div>';
  else (g.port_groups||[]).forEach((gr,i) => {
    pc.innerHTML += '<div class="group-item"><input placeholder="Group name" value="'+esc(gr.name)+'"><input placeholder="Ports (comma-sep)" value="'+esc((gr.ports||[]).join(', '))+'"><button class="nat-del" onclick="this.parentElement.remove()">&times;</button></div>';
  });
}
function addAddrGroup() {
  const c = document.getElementById('addr-groups-container');
  const em = c.querySelector('.table-empty'); if(em) em.remove();
  c.innerHTML += '<div class="group-item"><input placeholder="Group name"><input placeholder="IPs (comma-sep)"><button class="nat-del" onclick="this.parentElement.remove()">&times;</button></div>';
}
function addPortGroup() {
  const c = document.getElementById('port-groups-container');
  const em = c.querySelector('.table-empty'); if(em) em.remove();
  c.innerHTML += '<div class="group-item"><input placeholder="Group name"><input placeholder="Ports (comma-sep)"><button class="nat-del" onclick="this.parentElement.remove()">&times;</button></div>';
}
function saveGroups() {
  const address_groups=[], port_groups=[];
  document.querySelectorAll('#addr-groups-container .group-item').forEach(el => {
    const inps=el.querySelectorAll('input');
    if(inps[0].value.trim()) address_groups.push({name:inps[0].value.trim(),addresses:inps[1].value.split(',').map(s=>s.trim()).filter(Boolean)});
  });
  document.querySelectorAll('#port-groups-container .group-item').forEach(el => {
    const inps=el.querySelectorAll('input');
    if(inps[0].value.trim()) port_groups.push({name:inps[0].value.trim(),ports:inps[1].value.split(',').map(s=>s.trim()).filter(Boolean)});
  });
  QFW.api.post('/api/firewall/groups', {address_groups,port_groups})
    .then(() => QFW.toast('Groups saved', 'success'))
    .catch(e => QFW.toast('Save failed: '+e.message, 'error'));
}

})();
