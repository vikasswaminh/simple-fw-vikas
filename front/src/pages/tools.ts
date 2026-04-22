import { Component } from '@components/component';
import { toolsApi, conntrackApi } from '@api/endpoints';
import { escapeHtml } from '@utils';
import type { ConntrackEntry } from '@schemas';

export class ToolsPage extends Component<{
  pingResult: string | null;
  tracerouteResult: string | null;
  conntrack: ConntrackEntry[];
  wolStatus: string | null;
  loading: boolean;
  activeTab: 'ping' | 'traceroute' | 'wol' | 'arp' | 'conntrack';
}> {
  constructor(element: HTMLElement | string) {
    super(element);
    this.state = {
      pingResult: null, tracerouteResult: null, conntrack: [], wolStatus: null,
      loading: false, activeTab: 'ping',
    };
  }

  async init(): Promise<void> { /* lazy load */ }

  render(): void {
    const { activeTab, pingResult, tracerouteResult, conntrack, wolStatus, loading } = this.state;

    this.element.innerHTML = `
      <div class="page-header">
        <h1 class="page-title">Tools</h1>
      </div>

      <div class="card">
        <div class="tab-bar">
          <button class="tab-btn ${activeTab === 'ping' ? 'active' : ''}" data-tab="ping">Ping</button>
          <button class="tab-btn ${activeTab === 'traceroute' ? 'active' : ''}" data-tab="traceroute">Traceroute</button>
          <button class="tab-btn ${activeTab === 'wol' ? 'active' : ''}" data-tab="wol">Wake-on-LAN</button>
          <button class="tab-btn ${activeTab === 'conntrack' ? 'active' : ''}" data-tab="conntrack">Connections</button>
        </div>

        ${activeTab === 'ping' ? `
          <form id="ping-form" style="display: flex; gap: var(--spacing-md); align-items: flex-end; margin-bottom: var(--spacing-md);">
            <div class="form-group" style="flex: 1; margin: 0;"><input type="text" name="host" class="form-input" placeholder="8.8.8.8" required></div>
            <div class="form-group" style="width: 70px; margin: 0;"><input type="number" name="count" class="form-input" value="4" min="1" max="20"></div>
            <button type="submit" class="btn btn-primary" ${loading ? 'disabled' : ''}>▷ Run</button>
          </form>
          ${pingResult ? `<div class="mono-output">${escapeHtml(pingResult)}</div>` : ''}
        ` : ''}

        ${activeTab === 'traceroute' ? `
          <form id="traceroute-form" style="display: flex; gap: var(--spacing-md); align-items: flex-end; margin-bottom: var(--spacing-md);">
            <div class="form-group" style="flex: 1; margin: 0;"><input type="text" name="host" class="form-input" placeholder="8.8.8.8" required></div>
            <button type="submit" class="btn btn-primary" ${loading ? 'disabled' : ''}>▷ Run</button>
          </form>
          ${tracerouteResult ? `<div class="mono-output">${escapeHtml(tracerouteResult)}</div>` : ''}
        ` : ''}

        ${activeTab === 'wol' ? `
          <form id="wol-form" style="display: flex; gap: var(--spacing-md); align-items: flex-end; margin-bottom: var(--spacing-md);">
            <div class="form-group" style="flex: 1; margin: 0;">
              <label class="form-label">MAC Address</label>
              <input type="text" name="mac" class="form-input" placeholder="00:11:22:33:44:55" required>
            </div>
            <div class="form-group" style="width: 120px; margin: 0;">
              <label class="form-label">Interface</label>
              <input type="text" name="interface" class="form-input" value="eth0">
            </div>
            <button type="submit" class="btn btn-primary" ${loading ? 'disabled' : ''}>▷ Wake Up</button>
          </form>
          ${wolStatus ? `<p style="color: ${wolStatus.startsWith('Error') ? 'var(--color-danger)' : 'var(--color-success)'}; margin-top: var(--spacing-sm);">${wolStatus}</p>` : ''}
        ` : ''}

        ${activeTab === 'conntrack' ? `
          <div class="table-container">
            <table class="table">
              <thead><tr><th>Protocol</th><th>Source</th><th>Destination</th><th>State</th></tr></thead>
              <tbody>
                ${conntrack.slice(0, 100).map((e: ConntrackEntry) => `
                  <tr>
                    <td>${escapeHtml(e.protocol)}</td>
                    <td class="mono">${escapeHtml(e.src)}${e.sport ? ':' + escapeHtml(e.sport) : ''}</td>
                    <td class="mono">${escapeHtml(e.dst)}${e.dport ? ':' + escapeHtml(e.dport) : ''}</td>
                    <td><span class="badge badge-outline badge-sm">${escapeHtml(e.state)}</span></td>
                  </tr>
                `).join('') || '<tr><td colspan="4" style="color: var(--color-text-muted);">No connections</td></tr>'}
              </tbody>
            </table>
          </div>
          ${conntrack.length > 100 ? `<p style="color: var(--color-text-muted); margin-top: var(--spacing-md);">Showing 100 of ${conntrack.length}</p>` : ''}
        ` : ''}
      </div>
    `;

    // Tab events
    this.$$<HTMLButtonElement>('.tab-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        const tab = btn.dataset.tab as typeof activeTab;
        this.setState({ activeTab: tab });
        if (tab === 'conntrack') this.loadConntrack();
      });
    });

    this.bindFormEvents();
  }

  private async loadConntrack(): Promise<void> {
    try {
      const entries = await conntrackApi.getConnections();
      this.setState({ conntrack: entries });
    } catch { /* ignore */ }
  }

  private bindFormEvents(): void {
    this.$<HTMLFormElement>('#ping-form')?.addEventListener('submit', async (e) => {
      e.preventDefault();
      const form = e.target as HTMLFormElement;
      const fd = new FormData(form);
      this.setState({ loading: true, pingResult: null });
      try {
        const r = await toolsApi.ping({ host: fd.get('host') as string, count: parseInt(fd.get('count') as string) || 4 });
        this.setState({ pingResult: r.success ? r.stdout : r.stderr, loading: false });
      } catch (err) {
        this.setState({ pingResult: 'Error: ' + (err instanceof Error ? err.message : 'Unknown'), loading: false });
      }
    });

    this.$<HTMLFormElement>('#traceroute-form')?.addEventListener('submit', async (e) => {
      e.preventDefault();
      const fd = new FormData(e.target as HTMLFormElement);
      this.setState({ loading: true, tracerouteResult: null });
      try {
        const r = await toolsApi.traceroute({ host: fd.get('host') as string });
        this.setState({ tracerouteResult: r.success ? r.stdout : r.stderr, loading: false });
      } catch (err) {
        this.setState({ tracerouteResult: 'Error: ' + (err instanceof Error ? err.message : 'Unknown'), loading: false });
      }
    });

    this.$<HTMLFormElement>('#wol-form')?.addEventListener('submit', async (e) => {
      e.preventDefault();
      const fd = new FormData(e.target as HTMLFormElement);
      this.setState({ loading: true, wolStatus: null });
      try {
        await toolsApi.wol({ mac: fd.get('mac') as string, interface: (fd.get('interface') as string) || 'eth0' });
        this.setState({ wolStatus: 'Magic packet sent successfully', loading: false });
      } catch (err) {
        this.setState({ wolStatus: 'Error: ' + (err instanceof Error ? err.message : 'Unknown'), loading: false });
      }
    });
  }
}
