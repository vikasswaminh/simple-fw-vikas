import { Component } from '@components/component';
import { toolsApi, conntrackApi } from '@api/endpoints';
import type { PingRequest, TracerouteRequest, WolRequest, ConntrackEntry } from '@schemas';

/**
 * Tools Page Component
 */
export class ToolsPage extends Component<{
  pingResult: string | null;
  tracerouteResult: string | null;
  conntrack: ConntrackEntry[];
  wolStatus: string | null;
  loading: boolean;
  activeTab: 'ping' | 'traceroute' | 'wol' | 'conntrack';
}> {
  constructor(element: HTMLElement | string) {
    super(element);
    this.state = {
      pingResult: null,
      tracerouteResult: null,
      conntrack: [],
      wolStatus: null,
      loading: false,
      activeTab: 'ping',
    };
  }

  async init(): Promise<void> {
    if (this.state.activeTab === 'conntrack') {
      await this.loadConntrack();
    }
  }

  private async loadConntrack(): Promise<void> {
    try {
      const entries = await conntrackApi.getConnections();
      this.setState({ conntrack: entries });
    } catch (error) {
      console.error('Failed to load conntrack:', error);
    }
  }

  render(): void {
    const { activeTab, pingResult, tracerouteResult, conntrack, wolStatus, loading } = this.state;

    this.element.innerHTML = `
      <div class="card">
        <div class="card-header">
          <h3 class="card-title">Network Tools</h3>
        </div>

        <!-- Tabs -->
        <div style="display: flex; gap: var(--spacing-sm); margin-bottom: var(--spacing-md); border-bottom: 1px solid var(--color-border);">
          <button class="tab-btn ${activeTab === 'ping' ? 'active' : ''}" data-tab="ping">Ping</button>
          <button class="tab-btn ${activeTab === 'traceroute' ? 'active' : ''}" data-tab="traceroute">Traceroute</button>
          <button class="tab-btn ${activeTab === 'wol' ? 'active' : ''}" data-tab="wol">Wake-on-LAN</button>
          <button class="tab-btn ${activeTab === 'conntrack' ? 'active' : ''}" data-tab="conntrack">Connections</button>
        </div>

        ${activeTab === 'ping' ? this.renderPing(pingResult, loading) : ''}
        ${activeTab === 'traceroute' ? this.renderTraceroute(tracerouteResult, loading) : ''}
        ${activeTab === 'wol' ? this.renderWol(wolStatus, loading) : ''}
        ${activeTab === 'conntrack' ? this.renderConntrack(conntrack) : ''}
      </div>
    `;

    // Bind tab events
    this.$$<HTMLButtonElement>('.tab-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        const tab = btn.dataset.tab as typeof activeTab;
        this.setState({ activeTab: tab });
        if (tab === 'conntrack') {
          this.loadConntrack();
        }
      });
    });

    // Bind tool-specific events
    this.bindToolEvents();
  }

  private bindToolEvents(): void {
    // Ping form
    const pingForm = this.$<HTMLFormElement>('#ping-form');
    pingForm?.addEventListener('submit', async (e) => {
      e.preventDefault();
      const formData = new FormData(pingForm);
      const request: PingRequest = {
        host: formData.get('host') as string,
        count: parseInt(formData.get('count') as string) || 4,
      };

      this.setState({ loading: true, pingResult: null });
      try {
        const result = await toolsApi.ping(request);
        this.setState({ pingResult: result.success ? result.stdout : result.stderr, loading: false });
      } catch (error) {
        this.setState({ pingResult: 'Error: ' + (error instanceof Error ? error.message : 'Unknown error'), loading: false });
      }
    });

    // Traceroute form
    const tracerouteForm = this.$<HTMLFormElement>('#traceroute-form');
    tracerouteForm?.addEventListener('submit', async (e) => {
      e.preventDefault();
      const formData = new FormData(tracerouteForm);
      const request: TracerouteRequest = {
        host: formData.get('host') as string,
      };

      this.setState({ loading: true, tracerouteResult: null });
      try {
        const result = await toolsApi.traceroute(request);
        this.setState({ tracerouteResult: result.success ? result.stdout : result.stderr, loading: false });
      } catch (error) {
        this.setState({ tracerouteResult: 'Error: ' + (error instanceof Error ? error.message : 'Unknown error'), loading: false });
      }
    });

    // WoL form
    const wolForm = this.$<HTMLFormElement>('#wol-form');
    wolForm?.addEventListener('submit', async (e) => {
      e.preventDefault();
      const formData = new FormData(wolForm);
      const request: WolRequest = {
        mac: formData.get('mac') as string,
        interface: (formData.get('interface') as string) || 'eth0',
      };

      this.setState({ loading: true, wolStatus: null });
      try {
        await toolsApi.wol(request);
        this.setState({ wolStatus: 'Magic packet sent successfully', loading: false });
      } catch (error) {
        this.setState({ wolStatus: 'Error: ' + (error instanceof Error ? error.message : 'Unknown error'), loading: false });
      }
    });
  }

  private renderPing(result: string | null, loading: boolean): string {
    return `
      <form id="ping-form">
        <div style="display: flex; gap: var(--spacing-md); align-items: flex-end; margin-bottom: var(--spacing-md);">
          <div class="form-group" style="flex: 1;">
            <label class="form-label">Host</label>
            <input type="text" name="host" class="form-input" placeholder="192.168.1.1 or example.com" required>
          </div>
          <div class="form-group" style="width: 100px;">
            <label class="form-label">Count</label>
            <input type="number" name="count" class="form-input" value="4" min="1" max="20">
          </div>
          <button type="submit" class="btn btn-primary" ${loading ? 'disabled' : ''}>
            ${loading ? 'Running...' : 'Ping'}
          </button>
        </div>
      </form>
      ${result ? `
        <pre style="
          background: var(--color-bg-tertiary);
          padding: var(--spacing-md);
          border-radius: var(--radius-md);
          overflow-x: auto;
          font-family: monospace;
          font-size: 0.875rem;
          white-space: pre-wrap;
          word-break: break-all;
        ">${result}</pre>
      ` : ''}
    `;
  }

  private renderTraceroute(result: string | null, loading: boolean): string {
    return `
      <form id="traceroute-form">
        <div style="display: flex; gap: var(--spacing-md); align-items: flex-end; margin-bottom: var(--spacing-md);">
          <div class="form-group" style="flex: 1;">
            <label class="form-label">Host</label>
            <input type="text" name="host" class="form-input" placeholder="192.168.1.1 or example.com" required>
          </div>
          <button type="submit" class="btn btn-primary" ${loading ? 'disabled' : ''}>
            ${loading ? 'Running...' : 'Traceroute'}
          </button>
        </div>
      </form>
      ${result ? `
        <pre style="
          background: var(--color-bg-tertiary);
          padding: var(--spacing-md);
          border-radius: var(--radius-md);
          overflow-x: auto;
          font-family: monospace;
          font-size: 0.875rem;
          white-space: pre-wrap;
          word-break: break-all;
        ">${result}</pre>
      ` : ''}
    `;
  }

  private renderWol(status: string | null, loading: boolean): string {
    return `
      <form id="wol-form">
        <div style="display: flex; gap: var(--spacing-md); align-items: flex-end; margin-bottom: var(--spacing-md);">
          <div class="form-group" style="flex: 1;">
            <label class="form-label">MAC Address</label>
            <input type="text" name="mac" class="form-input" placeholder="00:11:22:33:44:55" required>
          </div>
          <div class="form-group" style="width: 150px;">
            <label class="form-label">Interface</label>
            <input type="text" name="interface" class="form-input" value="eth0">
          </div>
          <button type="submit" class="btn btn-primary" ${loading ? 'disabled' : ''}>
            ${loading ? 'Sending...' : 'Wake Up'}
          </button>
        </div>
      </form>
      ${status ? `<p style="color: ${status.startsWith('Error') ? 'var(--color-danger)' : 'var(--color-success)'}">${status}</p>` : ''}
    `;
  }

  private renderConntrack(entries: ConntrackEntry[]): string {
    return `
      <div class="table-container">
        <table class="table">
          <thead>
            <tr>
              <th>Protocol</th>
              <th>Source</th>
              <th>Destination</th>
              <th>State</th>
            </tr>
          </thead>
          <tbody>
            ${entries.slice(0, 100).map(entry => `
              <tr>
                <td>${entry.protocol}</td>
                <td>${entry.src}${entry.sport ? ':' + entry.sport : ''}</td>
                <td>${entry.dst}${entry.dport ? ':' + entry.dport : ''}</td>
                <td>${entry.state}</td>
              </tr>
            `).join('') || '<tr><td colspan="4">No connections found</td></tr>'}
          </tbody>
        </table>
        ${entries.length > 100 ? `<p style="margin-top: var(--spacing-md); color: var(--color-text-secondary);">Showing 100 of ${entries.length} connections</p>` : ''}
      </div>
    `;
  }
}
