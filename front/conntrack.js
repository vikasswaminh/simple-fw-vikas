// ═══════════════════════════════════════════════════════════════════
// QuickFW Connection Tracking Page — live conntrack table
// ═══════════════════════════════════════════════════════════════════
(function() {
const { esc, fmtBytes } = QFW.util;
let allConns = [], refreshTimer = null;

QFW.registerPage('conntrack', {
  init(page) {
    page.innerHTML = `
      <div class="page-header"><div><h1>Connection Table</h1><p class="page-sub">Active network connections tracked by conntrack</p></div><button class="btn-secondary" id="ct-refresh">Refresh</button></div>
      <div class="card"><div class="card-body">
        <div id="ct-summary" class="conntrack-summary"></div>
        <div class="search-bar" style="margin-bottom:14px;">
          <input class="search-input" id="ct-search" placeholder="Search IP, port\u2026">
          <select class="search-filter" id="ct-proto-filter"><option value="">All Protocols</option><option>TCP</option><option>UDP</option><option>ICMP</option></select>
          <select class="search-filter" id="ct-state-filter"><option value="">All States</option><option>ESTABLISHED</option><option>SYN_SENT</option><option>SYN_RECV</option><option>FIN_WAIT</option><option>TIME_WAIT</option><option>CLOSE</option><option>CLOSE_WAIT</option><option>LAST_ACK</option><option>NEW</option></select>
        </div>
        <div style="overflow-x:auto;">
          <table class="data-table">
            <thead><tr><th>Protocol</th><th>Source</th><th>Destination</th><th>State</th><th>Bytes</th><th>Packets</th><th>TTL</th></tr></thead>
            <tbody id="ct-tbody"><tr><td colspan="7" class="table-empty">Loading\u2026</td></tr></tbody>
          </table>
        </div>
        <div id="ct-pagination" style="text-align:center;padding:12px 0;"></div>
      </div></div>
    `;
    page.querySelector('#ct-refresh').onclick = () => loadConntrack();
    page.querySelector('#ct-search').oninput = QFW.util.debounce(renderFiltered, 250);
    page.querySelector('#ct-proto-filter').onchange = renderFiltered;
    page.querySelector('#ct-state-filter').onchange = renderFiltered;
  },
  load() {
    loadConntrack();
    refreshTimer = setInterval(loadConntrack, 10000);
  },
  destroy() {
    if (refreshTimer) { clearInterval(refreshTimer); refreshTimer = null; }
  }
});

let currentPage = 0;
const PAGE_SIZE = 100;

function loadConntrack() {
  QFW.api.get('/api/conntrack').then(d => {
    allConns = Array.isArray(d) ? d : (d.connections || d.entries || []);
    renderFiltered();
  }).catch(() => {});
}

function renderFiltered() {
  const search = (document.getElementById('ct-search').value || '').toLowerCase();
  const protoF = document.getElementById('ct-proto-filter').value.toLowerCase();
  const stateF = document.getElementById('ct-state-filter').value;

  let filtered = allConns.filter(c => {
    if (protoF && (c.protocol||c.proto||'').toLowerCase() !== protoF) return false;
    if (stateF && (c.state||'') !== stateF) return false;
    if (search) {
      const hay = ((c.src_ip||c.source||'')+(c.dst_ip||c.destination||'')+(c.src_port||'')+(c.dst_port||'')).toLowerCase();
      if (!hay.includes(search)) return false;
    }
    return true;
  });

  // Summary
  const summary = document.getElementById('ct-summary');
  const protos = {};
  filtered.forEach(c => { const p = (c.protocol||c.proto||'other').toUpperCase(); protos[p] = (protos[p]||0)+1; });
  summary.innerHTML = '<span class="conntrack-stat"><strong>Total:</strong> '+filtered.length+'</span>' +
    Object.entries(protos).map(([p,c]) => '<span class="conntrack-stat"><strong>'+esc(p)+':</strong> '+c+'</span>').join('');

  // Pagination
  const totalPages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  if (currentPage >= totalPages) currentPage = totalPages - 1;
  const start = currentPage * PAGE_SIZE;
  const pageItems = filtered.slice(start, start + PAGE_SIZE);

  const tbody = document.getElementById('ct-tbody');
  if (!pageItems.length) {
    tbody.innerHTML = '<tr><td colspan="7" class="table-empty">No connections found.</td></tr>';
  } else {
    tbody.innerHTML = pageItems.map(c => {
      const proto = (c.protocol||c.proto||'?').toUpperCase();
      const state = c.state||'\u2014';
      const stateColor = state === 'ESTABLISHED' ? 'var(--success)' : state === 'TIME_WAIT' ? 'var(--text-muted)' : state.includes('SYN') ? 'var(--warning)' : '';
      const srcIp = c.src_ip||c.source||'?';
      const srcPort = c.src_port||c.sport||'';
      const dstIp = c.dst_ip||c.destination||'?';
      const dstPort = c.dst_port||c.dport||'';
      const bytes = c.bytes||c.total_bytes||0;
      const packets = c.packets||c.total_packets||0;
      const ttl = c.ttl||c.timeout||'\u2014';
      return '<tr><td><span class="badge">'+proto+'</span></td>'
        +'<td class="mono">'+esc(srcIp)+(srcPort?':'+srcPort:'')+'</td>'
        +'<td class="mono">'+esc(dstIp)+(dstPort?':'+dstPort:'')+'</td>'
        +'<td style="color:'+stateColor+';">'+esc(state)+'</td>'
        +'<td class="mono">'+fmtBytes(bytes)+'</td>'
        +'<td>'+packets.toLocaleString()+'</td>'
        +'<td>'+ttl+'</td></tr>';
    }).join('');
  }

  // Pagination controls
  const pagDiv = document.getElementById('ct-pagination');
  if (totalPages <= 1) { pagDiv.innerHTML = ''; return; }
  let phtml = '';
  if (currentPage > 0) phtml += '<button class="btn-xs ct-pg" data-pg="'+(currentPage-1)+'">Prev</button> ';
  phtml += '<span style="font-size:12px;color:var(--text-muted);margin:0 8px;">Page '+(currentPage+1)+' of '+totalPages+' ('+filtered.length+' connections)</span>';
  if (currentPage < totalPages - 1) phtml += ' <button class="btn-xs ct-pg" data-pg="'+(currentPage+1)+'">Next</button>';
  pagDiv.innerHTML = phtml;
  pagDiv.querySelectorAll('.ct-pg').forEach(b => {
    b.onclick = () => { currentPage = parseInt(b.dataset.pg); renderFiltered(); };
  });
}

})();
