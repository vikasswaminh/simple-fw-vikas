import { Component } from '@components/component';
import { auditApi } from '@api/endpoints';
import type { AuditEntry } from '@schemas';
import { formatTime, escapeHtml } from '@utils';

export class AuditPage extends Component<{
  entries: AuditEntry[];
  filtered: AuditEntry[];
  loading: boolean;
  error: string | null;
  filterMethod: string;
  filterUser: string;
  filterStatus: string;
  page: number;
  perPage: number;
}> {
  constructor(element: HTMLElement | string) {
    super(element);
    this.state = {
      entries: [], filtered: [], loading: true, error: null,
      filterMethod: '', filterUser: '', filterStatus: '',
      page: 1, perPage: 20,
    };
  }

  async init(): Promise<void> {
    await this.loadData();
  }

  private async loadData(): Promise<void> {
    try {
      const entries = await auditApi.getLog();
      this.setState({ entries, filtered: entries, loading: false });
      this.applyFilters();
    } catch (error) {
      this.setState({ error: error instanceof Error ? error.message : 'Failed to load', loading: false });
    }
  }

  private applyFilters(): void {
    let filtered = [...this.state.entries];
    const { filterMethod, filterUser, filterStatus } = this.state;
    if (filterMethod) filtered = filtered.filter((e: AuditEntry) => e.method === filterMethod);
    if (filterUser) filtered = filtered.filter((e: AuditEntry) => e.user === filterUser);
    if (filterStatus === '2xx') filtered = filtered.filter((e: AuditEntry) => e.status >= 200 && e.status < 300);
    else if (filterStatus === '4xx') filtered = filtered.filter((e: AuditEntry) => e.status >= 400 && e.status < 500);
    else if (filterStatus === '5xx') filtered = filtered.filter((e: AuditEntry) => e.status >= 500);
    this.setState({ filtered, page: 1 });
  }

  private exportData(format: 'csv' | 'json'): void {
    const data = this.state.filtered;
    let content: string;
    let mime: string;
    let ext: string;

    if (format === 'json') {
      content = JSON.stringify(data, null, 2);
      mime = 'application/json';
      ext = 'json';
    } else {
      // Quote + escape every field per RFC 4180. Prefix ' on cells that start
      // with =, +, -, @, \t, \r so Excel/LibreOffice won't execute them as
      // formulas when an admin opens the export.
      const csvEscape = (v: string | number): string => {
        const s = String(v);
        const safeStart = /^[=+\-@\t\r]/.test(s) ? "'" + s : s;
        const needsQuote = /[",\n\r]/.test(safeStart);
        return needsQuote ? '"' + safeStart.replace(/"/g, '""') + '"' : safeStart;
      };
      const headers = 'timestamp,method,endpoint,user,source_ip,status\n';
      content = headers + data.map((e: AuditEntry) =>
        [e.timestamp, e.method, e.endpoint, e.user, e.source_ip, e.status]
          .map(csvEscape).join(',')
      ).join('\n');
      mime = 'text/csv';
      ext = 'csv';
    }

    const blob = new Blob([content], { type: mime });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = `audit-log.${ext}`; a.click();
    URL.revokeObjectURL(url);
  }

  render(): void {
    const { filtered, loading, error, page, perPage, filterMethod, filterStatus } = this.state;

    if (loading) {
      this.element.innerHTML = `<div class="loading"><div class="spinner"></div> Loading...</div>`;
      return;
    }

    const totalPages = Math.ceil(filtered.length / perPage);
    const pageData = filtered.slice((page - 1) * perPage, page * perPage);
    const users = [...new Set(this.state.entries.map((e: AuditEntry) => e.user))];

    this.element.innerHTML = `
      <div class="page-header">
        <h1 class="page-title">Audit Log</h1>
        <div class="page-actions">
          <span class="badge badge-outline">${filtered.length} entries</span>
          <button id="csv-btn" class="btn btn-secondary btn-sm">CSV</button>
          <button id="json-btn" class="btn btn-secondary btn-sm">JSON</button>
          <button id="refresh-btn" class="btn btn-secondary">↻ Refresh</button>
        </div>
      </div>

      <div class="card">
        <!-- Filters -->
        <div style="display: flex; gap: var(--spacing-sm); margin-bottom: var(--spacing-md); flex-wrap: wrap;">
          <select class="form-select" id="filter-method" style="width: 120px;">
            <option value="" ${!filterMethod ? 'selected' : ''}>All Methods</option>
            <option value="GET" ${filterMethod === 'GET' ? 'selected' : ''}>GET</option>
            <option value="POST" ${filterMethod === 'POST' ? 'selected' : ''}>POST</option>
            <option value="PUT" ${filterMethod === 'PUT' ? 'selected' : ''}>PUT</option>
            <option value="DELETE" ${filterMethod === 'DELETE' ? 'selected' : ''}>DELETE</option>
          </select>
          <select class="form-select" id="filter-user" style="width: 140px;">
            <option value="">All Users</option>
            ${users.map(u => `<option value="${escapeHtml(u)}">${escapeHtml(u)}</option>`).join('')}
          </select>
          <select class="form-select" id="filter-status" style="width: 130px;">
            <option value="" ${!filterStatus ? 'selected' : ''}>All Status</option>
            <option value="2xx" ${filterStatus === '2xx' ? 'selected' : ''}>2xx Success</option>
            <option value="4xx" ${filterStatus === '4xx' ? 'selected' : ''}>4xx Error</option>
            <option value="5xx" ${filterStatus === '5xx' ? 'selected' : ''}>5xx Error</option>
          </select>
        </div>

        ${error ? `<p style="color: var(--color-danger); margin-bottom: var(--spacing-md);">${error}</p>` : ''}

        <div class="table-container">
          <table class="table">
            <thead>
              <tr><th>Timestamp</th><th>Method</th><th>Endpoint</th><th>User</th><th>Source IP</th><th>Status</th></tr>
            </thead>
            <tbody>
              ${pageData.map((e: AuditEntry) => `
                <tr>
                  <td style="white-space: nowrap;">${formatTime(e.timestamp)}</td>
                  <td><span class="badge ${this.methodBadge(e.method)} badge-sm">${escapeHtml(e.method)}</span></td>
                  <td class="mono">${escapeHtml(e.endpoint)}</td>
                  <td>${escapeHtml(e.user)}</td>
                  <td class="mono">${escapeHtml(e.source_ip)}</td>
                  <td><span class="badge ${e.status < 300 ? 'badge-success' : e.status < 500 ? 'badge-warning' : 'badge-danger'} badge-sm">${escapeHtml(String(e.status))}</span></td>
                </tr>
              `).join('') || '<tr><td colspan="6" style="color: var(--color-text-muted);">No entries</td></tr>'}
            </tbody>
          </table>
        </div>

        <!-- Pagination -->
        ${totalPages > 1 ? `
          <div style="display: flex; justify-content: space-between; align-items: center; margin-top: var(--spacing-md);">
            <span style="font-size: var(--font-size-xs); color: var(--color-text-muted);">Per page: ${perPage}</span>
            <div style="display: flex; gap: var(--spacing-xs);">
              <button class="btn btn-secondary btn-sm" ${page <= 1 ? 'disabled' : ''} data-page="${page - 1}">← Prev</button>
              <span style="padding: 4px 8px; font-size: var(--font-size-sm);">Page ${page} of ${totalPages}</span>
              <button class="btn btn-secondary btn-sm" ${page >= totalPages ? 'disabled' : ''} data-page="${page + 1}">Next →</button>
            </div>
          </div>
        ` : ''}
      </div>
    `;

    // Events
    this.$<HTMLButtonElement>('#refresh-btn')?.addEventListener('click', () => this.loadData());
    this.$<HTMLButtonElement>('#csv-btn')?.addEventListener('click', () => this.exportData('csv'));
    this.$<HTMLButtonElement>('#json-btn')?.addEventListener('click', () => this.exportData('json'));

    ['filter-method', 'filter-user', 'filter-status'].forEach(id => {
      this.$<HTMLSelectElement>(`#${id}`)?.addEventListener('change', (e) => {
        const key = id.replace('filter-', 'filter') as string;
        const map: Record<string, string> = { 'filtermethod': 'filterMethod', 'filteruser': 'filterUser', 'filterstatus': 'filterStatus' };
        this.setState({ [map[key] || key]: (e.target as HTMLSelectElement).value } as Partial<typeof this.state>);
        this.applyFilters();
      });
    });

    this.$$<HTMLButtonElement>('[data-page]').forEach(btn => {
      btn.addEventListener('click', () => this.setState({ page: parseInt(btn.dataset.page!) }));
    });
  }

  private methodBadge(method: string): string {
    switch (method) {
      case 'GET': return 'badge-info';
      case 'POST': return 'badge-success';
      case 'PUT': case 'PATCH': return 'badge-warning';
      case 'DELETE': return 'badge-danger';
      default: return 'badge-outline';
    }
  }
}
