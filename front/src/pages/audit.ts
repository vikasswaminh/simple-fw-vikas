import { Component } from '@components/component';
import { auditApi } from '@api/endpoints';
import type { AuditEntry } from '@schemas';
import { formatTime } from '@utils';

/**
 * Audit Log Page Component
 */
export class AuditPage extends Component<{
  entries: AuditEntry[];
  loading: boolean;
  error: string | null;
}> {
  constructor(element: HTMLElement | string) {
    super(element);
    this.state = {
      entries: [],
      loading: true,
      error: null,
    };
  }

  async init(): Promise<void> {
    await this.loadData();
  }

  private async loadData(): Promise<void> {
    try {
      const entries = await auditApi.getLog();
      this.setState({ entries, loading: false });
    } catch (error) {
      console.error('Failed to load audit log:', error);
      this.setState({
        error: error instanceof Error ? error.message : 'Failed to load audit log',
        loading: false,
      });
    }
  }

  render(): void {
    const { entries, loading, error } = this.state;

    if (loading) {
      this.element.innerHTML = `
        <div class="loading">
          <div class="spinner"></div>
          <span>Loading audit log...</span>
        </div>
      `;
      return;
    }

    this.element.innerHTML = `
      <div class="card">
        <div class="card-header">
          <h3 class="card-title">Audit Log</h3>
          <button id="refresh-btn" class="btn btn-secondary">Refresh</button>
        </div>

        ${error ? `<p style="color: var(--color-danger)">${error}</p>` : ''}

        <div class="table-container">
          <table class="table">
            <thead>
              <tr>
                <th>Timestamp</th>
                <th>Method</th>
                <th>Endpoint</th>
                <th>User</th>
                <th>Source IP</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              ${entries.map(entry => `
                <tr>
                  <td>${formatTime(entry.timestamp)}</td>
                  <td>
                    <span class="badge ${this.getMethodBadgeClass(entry.method)}">${entry.method}</span>
                  </td>
                  <td>${entry.endpoint}</td>
                  <td>${entry.user}</td>
                  <td>${entry.source_ip}</td>
                  <td>
                    <span class="badge ${entry.status >= 200 && entry.status < 300 ? 'badge-success' : entry.status >= 400 ? 'badge-danger' : 'badge-warning'}">
                      ${entry.status}
                    </span>
                  </td>
                </tr>
              `).join('') || '<tr><td colspan="6">No audit entries found</td></tr>'}
            </tbody>
          </table>
        </div>
      </div>
    `;

    const refreshBtn = this.$<HTMLButtonElement>('#refresh-btn');
    refreshBtn?.addEventListener('click', () => this.loadData());
  }

  private getMethodBadgeClass(method: string): string {
    switch (method) {
      case 'GET':
        return 'badge-info';
      case 'POST':
        return 'badge-success';
      case 'PUT':
      case 'PATCH':
        return 'badge-warning';
      case 'DELETE':
        return 'badge-danger';
      default:
        return 'badge-info';
    }
  }
}
