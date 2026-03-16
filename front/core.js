// ═══════════════════════════════════════════════════════════════════
// QuickFW Core — Router, API, Components, Utilities
// ═══════════════════════════════════════════════════════════════════

window.QFW = (function() {

// ───── State ─────
const pages = {};
let currentPage = null;
let cachedInterfaces = [];
let cachedRoles = {};

// ───── Utilities ─────
function esc(s) { return s ? String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;') : ''; }
function fmtBytes(b) {
  if (b == null) return '0 B';
  if (b >= 1e12) return (b/1e12).toFixed(2)+' TB';
  if (b >= 1e9) return (b/1e9).toFixed(2)+' GB';
  if (b >= 1e6) return (b/1e6).toFixed(1)+' MB';
  if (b >= 1e3) return (b/1e3).toFixed(0)+' KB';
  return b+' B';
}
function fmtUptime(s) {
  if (!s) return '\u2014';
  const d=Math.floor(s/86400), h=Math.floor((s%86400)/3600), m=Math.floor((s%3600)/60);
  return (d>0?d+'d ':'')+(h>0?h+'h ':'')+m+'m';
}
function fmtTime(ts) {
  if (!ts) return '\u2014';
  const d = new Date(ts);
  if (isNaN(d)) return String(ts);
  return d.toLocaleString();
}
function fmtTimeAgo(ts) {
  if (!ts) return '\u2014';
  const now = Date.now(), then = new Date(ts).getTime();
  if (isNaN(then)) return String(ts);
  const diff = Math.floor((now - then) / 1000);
  if (diff < 60) return diff + 's ago';
  if (diff < 3600) return Math.floor(diff/60) + 'm ago';
  if (diff < 86400) return Math.floor(diff/3600) + 'h ago';
  return Math.floor(diff/86400) + 'd ago';
}
function debounce(fn, ms) {
  let t; return function() { clearTimeout(t); const a=arguments,c=this; t=setTimeout(()=>fn.apply(c,a), ms); };
}
function ifaceOpts(sel) {
  let h = '<option value="any">Any</option>';
  cachedInterfaces.forEach(i => { h += '<option value="'+esc(i.name)+'"'+(i.name===sel?' selected':'')+'>'+esc(i.name)+'</option>'; });
  return h;
}
function el(tag, cls, html) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (html !== undefined) e.innerHTML = html;
  return e;
}

// ───── Toast Notifications ─────
const toastIcons = {
  success:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>',
  error:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>',
  info:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>',
  warn:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>',
};
function toast(msg, type) {
  type = type || 'info';
  const e = document.createElement('div');
  e.className = 'toast ' + type;
  e.innerHTML = (toastIcons[type]||'') + '<span>' + esc(msg) + '</span>';
  document.getElementById('toast-container').appendChild(e);
  setTimeout(() => { e.style.animation='fade-out 0.3s ease forwards'; setTimeout(()=>e.remove(),300); }, 3500);
}

// ───── API Wrapper ─────
const api = {
  async get(url) {
    const r = await fetch(url);
    if (r.status === 401) { showLogin(); throw new Error('Unauthorized'); }
    if (!r.ok) { const t = await r.text(); throw new Error(t || 'HTTP ' + r.status); }
    const ct = r.headers.get('content-type') || '';
    if (ct.includes('json')) return r.json();
    return r.text();
  },
  async post(url, data) {
    const r = await fetch(url, { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(data) });
    if (r.status === 401) { showLogin(); throw new Error('Unauthorized'); }
    if (!r.ok) { const t = await r.text(); throw new Error(t || 'HTTP ' + r.status); }
    const ct = r.headers.get('content-type') || '';
    if (ct.includes('json')) return r.json();
    return r.text();
  }
};

// ───── Login ─────
function showLogin() {
  const lp = document.getElementById('login-page');
  if (lp) lp.style.display = 'flex';
}
function hideLogin() {
  const lp = document.getElementById('login-page');
  if (lp) lp.style.display = 'none';
}
function setupLogin() {
  const form = document.getElementById('login-form');
  if (!form) return;
  form.onsubmit = function(e) {
    e.preventDefault();
    const user = document.getElementById('login-user').value.trim();
    const pass = document.getElementById('login-pass').value;
    const errEl = document.getElementById('login-error');
    if (!user || !pass) { errEl.textContent = 'Username and password required'; return; }
    fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: user, password: pass })
    }).then(r => {
      if (!r.ok) throw new Error('Invalid credentials');
      return r.json().catch(() => ({}));
    }).then(() => {
      errEl.textContent = '';
      hideLogin();
      showPage('dashboard');
    }).catch(err => {
      errEl.textContent = err.message || 'Login failed';
    });
  };
}

// ───── Page Router ─────
function registerPage(id, handler) {
  pages[id] = { handler, initialized: false };
}

function showPage(id) {
  // Destroy current page
  if (currentPage && pages[currentPage] && pages[currentPage].handler.destroy) {
    pages[currentPage].handler.destroy();
  }
  // Hide all pages
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  // Update nav
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
  const nav = document.querySelector('.nav-item[data-page="'+id+'"]');
  if (nav) nav.classList.add('active');
  // Get or create page div
  let pageEl = document.getElementById('page-' + id);
  if (!pageEl) {
    pageEl = document.createElement('div');
    pageEl.id = 'page-' + id;
    pageEl.className = 'page';
    document.querySelector('.main').appendChild(pageEl);
  }
  pageEl.classList.add('active');
  // Initialize if first visit
  if (pages[id] && !pages[id].initialized) {
    pages[id].handler.init(pageEl);
    pages[id].initialized = true;
  }
  // Load data
  if (pages[id] && pages[id].handler.load) {
    pages[id].handler.load(pageEl);
  }
  currentPage = id;
  closeSidebar();
}

// ───── Sidebar ─────
function toggleSidebar() {
  const sb = document.querySelector('.sidebar');
  const bd = document.querySelector('.sidebar-backdrop');
  if (sb) sb.classList.toggle('open');
  if (bd) bd.classList.toggle('show');
}
function closeSidebar() {
  const sb = document.querySelector('.sidebar');
  const bd = document.querySelector('.sidebar-backdrop');
  if (sb) sb.classList.remove('open');
  if (bd) bd.classList.remove('show');
}

// ───── Confirm Dialog ─────
function confirmDialog(title, message, btnLabelOrCallback, callback) {
  let btnLabel;
  if (typeof btnLabelOrCallback === 'function') { callback = btnLabelOrCallback; btnLabel = 'Confirm'; }
  else { btnLabel = btnLabelOrCallback || 'Confirm'; }
  const overlay = el('div', 'modal-overlay');
  overlay.innerHTML =
    '<div class="modal" style="width:420px;">' +
    '<div class="modal-header"><h2>'+esc(title)+'</h2><button class="modal-close" onclick="this.closest(\'.modal-overlay\').remove()">&times;</button></div>' +
    '<div class="modal-body"><div class="confirm-body">'+message+'</div></div>' +
    '<div class="modal-footer">' +
    '<button class="btn-secondary" onclick="this.closest(\'.modal-overlay\').remove()">Cancel</button>' +
    '<button class="btn-danger confirm-action-btn">'+esc(btnLabel)+'</button>' +
    '</div></div>';
  document.body.appendChild(overlay);
  overlay.querySelector('.confirm-action-btn').onclick = function() { overlay.remove(); callback(); };
}

// ═══════════════════════════════════════════════════════════════════
// Component: Modal
// ═══════════════════════════════════════════════════════════════════
function openModal(opts) {
  const overlay = el('div', 'modal-overlay');
  const w = opts.width || '560px';
  overlay.innerHTML =
    '<div class="modal" style="width:'+w+';">' +
    '<div class="modal-header"><h2>'+esc(opts.title||'')+'</h2><button class="modal-close modal-close-btn">&times;</button></div>' +
    '<div class="modal-body">'+(opts.body||'')+'</div>' +
    (opts.footer !== false ? '<div class="modal-footer">'+(opts.footer||'<button class="btn-secondary modal-close-btn">Cancel</button><button class="btn-primary modal-save-btn">Save</button>')+'</div>' : '') +
    '</div>';
  document.body.appendChild(overlay);
  overlay.querySelectorAll('.modal-close-btn').forEach(b => {
    b.onclick = () => { overlay.remove(); if(opts.onClose) opts.onClose(); };
  });
  if (opts.onOpen) opts.onOpen(overlay);
  return overlay;
}

function closeModal() {
  const overlay = document.querySelector('.modal-overlay');
  if (overlay) overlay.remove();
}

// ═══════════════════════════════════════════════════════════════════
// Component: EditableList
// ═══════════════════════════════════════════════════════════════════
function EditableList(opts) {
  const state = { data: JSON.parse(JSON.stringify(opts.data || [])) };
  const container = opts.container;
  const cols = opts.columns || [];
  const readOnly = opts.readOnly || false;

  function render() {
    let html = '<div class="el-toolbar">';
    if (!readOnly) {
      html += '<button class="btn-secondary btn-sm el-add-btn"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg> '+(opts.addLabel||'Add')+'</button>';
    }
    html += '<span class="el-count">'+state.data.length+' item'+(state.data.length!==1?'s':'')+'</span>';
    html += '</div>';

    html += '<div class="el-table-wrap"><table class="el-table"><thead><tr>';
    cols.forEach(c => { html += '<th>'+esc(c.label)+'</th>'; });
    if (!readOnly) html += '<th class="el-actions-col">Actions</th>';
    html += '</tr></thead><tbody>';

    if (!state.data.length) {
      html += '<tr><td colspan="'+(cols.length+(readOnly?0:1))+'" class="el-empty">'+(opts.emptyText||'No items.')+'</td></tr>';
    } else {
      state.data.forEach((row, idx) => {
        html += '<tr data-idx="'+idx+'">';
        cols.forEach(c => {
          const v = row[c.key];
          html += '<td>' + renderCellValue(c, v) + '</td>';
        });
        if (!readOnly) {
          html += '<td class="el-actions">';
          if (state.data.length > 1) {
            html += '<button class="el-btn el-move-up" data-idx="'+idx+'" title="Move up"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14"><polyline points="18 15 12 9 6 15"/></svg></button>';
            html += '<button class="el-btn el-move-down" data-idx="'+idx+'" title="Move down"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14"><polyline points="6 9 12 15 18 9"/></svg></button>';
          }
          html += '<button class="el-btn el-edit" data-idx="'+idx+'" title="Edit"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg></button>';
          html += '<button class="el-btn el-del" data-idx="'+idx+'" title="Delete"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg></button>';
          html += '</td>';
        }
        html += '</tr>';
      });
    }
    html += '</tbody></table></div>';
    container.innerHTML = html;
    attachEvents();
  }

  function renderCellValue(col, val) {
    if (val === undefined || val === null) return '<span class="el-null">\u2014</span>';
    if (col.type === 'toggle') return val ? '<span class="badge badge-green">Yes</span>' : '<span class="badge">No</span>';
    if (col.type === 'select') return '<span class="badge badge-blue">'+esc(String(val))+'</span>';
    if (col.type === 'tags') {
      if (typeof val === 'string') val = val.split(',').map(s=>s.trim()).filter(Boolean);
      if (!Array.isArray(val) || !val.length) return '<span class="el-null">\u2014</span>';
      return val.map(t => '<span class="el-tag">'+esc(t)+'</span>').join(' ');
    }
    if (col.type === 'password') return val ? '<span class="el-masked">\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022</span>' : '<span class="el-null">\u2014</span>';
    return esc(String(val));
  }

  function openEditModal(idx) {
    const isNew = idx === -1;
    const row = isNew ? {} : JSON.parse(JSON.stringify(state.data[idx]));
    let body = '<div class="form-grid">';
    cols.forEach(c => {
      const v = row[c.key];
      const fw = (c.type === 'textarea' || c.type === 'tags') ? ' full-width' : '';
      body += '<div class="form-group'+fw+'">';
      body += '<label>'+esc(c.label)+(c.required?' <span class="required">*</span>':'')+'</label>';
      if (c.hint) body += '<span class="form-hint">'+esc(c.hint)+'</span>';
      body += renderFormInput(c, v);
      body += '</div>';
    });
    body += '</div>';

    openModal({
      title: isNew ? (opts.addLabel || 'Add Item') : 'Edit Item',
      width: '560px',
      body: body,
      onOpen: function(modalEl) {
        modalEl.querySelector('.modal-save-btn').onclick = function() {
          const result = collectModalData(modalEl);
          if (!validateRow(result)) return;
          if (isNew) {
            state.data.push(result);
          } else {
            state.data[idx] = result;
          }
          modalEl.remove();
          render();
          if (opts.onSave) opts.onSave(state.data);
        };
      }
    });
  }

  function renderFormInput(col, val) {
    const key = col.key;
    if (col.type === 'toggle') {
      return '<label class="toggle"><input type="checkbox" data-key="'+key+'"'+(val?' checked':'')+'><span class="toggle-slider"></span></label>';
    }
    if (col.type === 'select') {
      let h = '<select class="form-select" data-key="'+key+'">';
      (col.options||col.opts||[]).forEach(o => { h += '<option value="'+esc(o)+'"'+(val===o?' selected':'')+'>'+esc(o)+'</option>'; });
      h += '</select>';
      return h;
    }
    if (col.type === 'textarea') {
      return '<textarea class="form-textarea" data-key="'+key+'" rows="3">'+esc(val||'')+'</textarea>';
    }
    if (col.type === 'tags') {
      const tags = Array.isArray(val) ? val : (val ? String(val).split(',').map(s=>s.trim()).filter(Boolean) : []);
      return '<div class="tag-editor" data-key="'+key+'">'+
        '<div class="tag-list">'+tags.map(t=>'<span class="tag-chip">'+esc(t)+'<button class="tag-remove" onclick="this.parentElement.remove()">&times;</button></span>').join('')+'</div>'+
        '<input type="text" class="tag-input" placeholder="'+(col.placeholder||'Type and press Enter')+'" onkeydown="if(event.key===\'Enter\'){event.preventDefault();var v=this.value.trim();if(v){var c=document.createElement(\'span\');c.className=\'tag-chip\';c.innerHTML=QFW.esc(v)+\'<button class=tag-remove onclick=this.parentElement.remove()>&times;</button>\';this.previousElementSibling.appendChild(c);this.value=\'\';}}">' +
        '</div>';
    }
    if (col.type === 'password') {
      return '<input type="password" data-key="'+key+'" value="'+esc(val||'')+'" placeholder="'+(col.placeholder||'')+'" class="form-input">';
    }
    if (col.type === 'number') {
      return '<input type="number" data-key="'+key+'" value="'+(val!==undefined&&val!==null?val:'')+'" placeholder="'+(col.placeholder||'')+'" class="form-input">';
    }
    return '<input type="text" data-key="'+key+'" value="'+esc(val||'')+'" placeholder="'+(col.placeholder||'')+'" class="form-input">';
  }

  function collectModalData(modalEl) {
    const result = {};
    cols.forEach(c => {
      const input = modalEl.querySelector('[data-key="'+c.key+'"]');
      if (!input) return;
      if (c.type === 'toggle') {
        result[c.key] = input.querySelector('input[type="checkbox"]') ? input.querySelector('input[type="checkbox"]').checked : input.checked;
      } else if (c.type === 'number') {
        result[c.key] = input.value !== '' ? Number(input.value) : 0;
      } else if (c.type === 'tags') {
        const chips = input.querySelectorAll('.tag-chip');
        result[c.key] = Array.from(chips).map(ch => ch.textContent.replace(/\u00d7$/, '').trim());
      } else {
        result[c.key] = input.value;
      }
    });
    return result;
  }

  function validateRow(row) {
    for (const c of cols) {
      if (c.required && (row[c.key] === '' || row[c.key] === undefined || row[c.key] === null)) {
        toast(c.label + ' is required', 'error');
        return false;
      }
    }
    return true;
  }

  function attachEvents() {
    if (!readOnly) {
      const addBtn = container.querySelector('.el-add-btn');
      if (addBtn) addBtn.onclick = () => openEditModal(-1);
    }
    container.querySelectorAll('.el-edit').forEach(b => {
      b.onclick = () => openEditModal(parseInt(b.dataset.idx));
    });
    container.querySelectorAll('.el-del').forEach(b => {
      b.onclick = () => {
        const idx = parseInt(b.dataset.idx);
        state.data.splice(idx, 1);
        render();
        if (opts.onSave) opts.onSave(state.data);
      };
    });
    container.querySelectorAll('.el-move-up').forEach(b => {
      b.onclick = () => {
        const idx = parseInt(b.dataset.idx);
        if (idx > 0) { const tmp = state.data[idx]; state.data[idx] = state.data[idx-1]; state.data[idx-1] = tmp; render(); if(opts.onSave) opts.onSave(state.data); }
      };
    });
    container.querySelectorAll('.el-move-down').forEach(b => {
      b.onclick = () => {
        const idx = parseInt(b.dataset.idx);
        if (idx < state.data.length-1) { const tmp = state.data[idx]; state.data[idx] = state.data[idx+1]; state.data[idx+1] = tmp; render(); if(opts.onSave) opts.onSave(state.data); }
      };
    });
  }

  const inst = {
    render,
    getData() { return state.data; },
    setData(d) { state.data = JSON.parse(JSON.stringify(d||[])); render(); }
  };
  render();
  return inst;
}

// ═══════════════════════════════════════════════════════════════════
// Component: MiniChart (sparkline on canvas)
// ═══════════════════════════════════════════════════════════════════
function MiniChart(canvas, opts) {
  const ctx = canvas.getContext('2d');
  const color = opts.color || '#2563eb';
  const fill = opts.fillColor || 'rgba(37,99,235,0.1)';
  const maxPts = opts.maxPoints || 30;
  const data = [];

  canvas.width = opts.width || 200;
  canvas.height = opts.height || 50;

  function push(val) {
    data.push(val);
    if (data.length > maxPts) data.shift();
    draw();
  }

  function draw() {
    const w = canvas.width, h = canvas.height;
    ctx.clearRect(0, 0, w, h);
    if (data.length < 2) return;
    const max = Math.max(...data) || 1;
    const step = w / (maxPts - 1);

    ctx.beginPath();
    ctx.moveTo(0, h - (data[0]/max)*h*0.85);
    for (let i = 1; i < data.length; i++) {
      ctx.lineTo(i * step, h - (data[i]/max)*h*0.85);
    }
    ctx.strokeStyle = color;
    ctx.lineWidth = 1.5;
    ctx.stroke();

    ctx.lineTo((data.length-1)*step, h);
    ctx.lineTo(0, h);
    ctx.closePath();
    ctx.fillStyle = fill;
    ctx.fill();
  }

  return { push, draw, getData: () => data };
}

// ═══════════════════════════════════════════════════════════════════
// Component: SearchBar
// ═══════════════════════════════════════════════════════════════════
function SearchBar(opts) {
  const wrap = opts.container;
  let html = '<div class="search-bar">';
  html += '<input type="text" class="search-input" placeholder="'+(opts.placeholder||'Search\u2026')+'">';
  (opts.filters||[]).forEach(f => {
    html += '<select class="search-filter" data-key="'+f.key+'">';
    html += '<option value="">'+esc(f.label)+'</option>';
    (f.options||[]).forEach(o => {
      const val = typeof o === 'string' ? o : o.value;
      const lab = typeof o === 'string' ? o : o.label;
      html += '<option value="'+esc(val)+'">'+esc(lab)+'</option>';
    });
    html += '</select>';
  });
  html += '</div>';
  wrap.innerHTML = html;

  const input = wrap.querySelector('.search-input');
  const selects = wrap.querySelectorAll('.search-filter');
  function trigger() {
    const q = input.value.toLowerCase();
    const fv = {};
    selects.forEach(s => { fv[s.dataset.key] = s.value; });
    if (opts.onFilter) opts.onFilter(q, fv);
  }
  input.oninput = debounce(trigger, 200);
  selects.forEach(s => { s.onchange = trigger; });
  return { trigger, getQuery: () => input.value };
}

// ───── Init ─────
function init() {
  // Setup login form
  setupLogin();
  // Pre-fetch interfaces for dropdowns
  api.get('/api/interfaces').then(d => { cachedInterfaces = d.interfaces||[]; }).catch(()=>{});
  api.get('/api/interfaces/roles').then(d => { (d.roles||[]).forEach(r => { cachedRoles[r.interface]={role:r.role,zone:r.zone}; }); }).catch(()=>{});
  // Show default page
  showPage('dashboard');
}

window.addEventListener('DOMContentLoaded', init);

// ───── Public API ─────
return {
  registerPage,
  showPage,
  api,
  toast,
  esc,
  fmtBytes,
  fmtUptime,
  confirmDialog,
  openModal,
  closeModal,
  components: { EditableList, MiniChart, SearchBar },
  util: { esc, fmtBytes, fmtUptime, fmtTime, fmtTimeAgo, debounce, ifaceOpts, el },
  get interfaces() { return cachedInterfaces; },
  set interfaces(v) { cachedInterfaces = v; },
  get roles() { return cachedRoles; },
  set roles(v) { cachedRoles = v; },
  toggleSidebar,
  closeSidebar,
};

})();
