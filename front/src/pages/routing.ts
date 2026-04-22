import { Component } from '@components/component';
import { routingApi, routesApi } from '@api/endpoints';
import { openModal, closeModal } from '@components/modal';
import { showToast } from '@components/toast';
import { escapeHtml } from '@utils';
import type { OspfConfig, OspfNetwork, BgpConfig, BgpNeighbor, StaticRoute, OspfNeighborStatus } from '@schemas';

export class RoutingPage extends Component<{
  ospf: OspfConfig | null;
  bgp: BgpConfig | null;
  staticRoutes: StaticRoute[];
  routingTable: string;
  ospfNeighbors: OspfNeighborStatus[];
  bgpSummary: string;
  loading: boolean;
  error: string | null;
  activeTab: 'ospf' | 'bgp' | 'static' | 'active';
}> {
  constructor(element: HTMLElement | string) {
    super(element);
    this.state = {
      ospf: null, bgp: null, staticRoutes: [], routingTable: '',
      ospfNeighbors: [], bgpSummary: '',
      loading: true, error: null, activeTab: 'ospf',
    };
  }

  async init(): Promise<void> {
    await this.loadData();
  }

  private async loadData(): Promise<void> {
    try {
      const [ospf, bgp, routes] = await Promise.all([
        routingApi.getOspfConfig(),
        routingApi.getBgpConfig(),
        routesApi.getRoutes(),
      ]);
      this.setState({ ospf, bgp, staticRoutes: routes.routes || [], loading: false });
    } catch (error) {
      this.setState({ error: error instanceof Error ? error.message : 'Failed to load', loading: false });
    }
  }

  private async loadRoutingTable(): Promise<void> {
    try {
      const data = await routingApi.getRoutingTable();
      this.setState({ routingTable: data.table || '' });
    } catch { /* ignore */ }
  }

  private async loadOspfNeighbors(): Promise<void> {
    try {
      const data = await routingApi.getOspfNeighbors();
      this.setState({ ospfNeighbors: data.neighbors || [] });
    } catch { /* ignore */ }
  }

  private async loadBgpSummary(): Promise<void> {
    try {
      const data = await routingApi.getBgpSummary();
      this.setState({ bgpSummary: data.summary || '' });
    } catch { /* ignore */ }
  }

  private openAddNetworkModal(): void {
    openModal({
      title: '+ Add Network',
      body: `
        <div class="form-group"><label class="form-label">Network Prefix</label><input type="text" class="form-input" id="net-prefix" placeholder="192.168.1.0/24"></div>
        <div class="form-group"><label class="form-label">Area</label><input type="number" class="form-input" id="net-area" value="0" min="0"></div>
      `,
      footer: `<button class="btn btn-secondary" data-modal-close>Cancel</button><button class="btn btn-primary" data-modal-submit>Add</button>`,
      onSubmit: async () => {
        const modal = document.querySelector('.modal');
        if (!modal) return;
        const prefix = (modal.querySelector('#net-prefix') as HTMLInputElement)?.value;
        const area = parseInt((modal.querySelector('#net-area') as HTMLInputElement)?.value || '0');
        if (!prefix) { showToast('Prefix required', 'error'); return; }
        const ospf = { ...this.state.ospf! };
        ospf.networks = [...(ospf.networks || []), { prefix, area }];
        try {
          await routingApi.saveOspfConfig(ospf);
          showToast('Network added', 'success');
          closeModal();
          this.loadData();
        } catch { showToast('Failed to add network', 'error'); }
      },
    });
  }

  render(): void {
    const { loading, error, activeTab } = this.state;

    if (loading) {
      this.element.innerHTML = `<div class="loading"><div class="spinner"></div> Loading...</div>`;
      return;
    }

    this.element.innerHTML = `
      <div class="page-header">
        <h1 class="page-title">Routing</h1>
        <div class="page-actions">
          <button id="refresh-btn" class="btn btn-secondary">↻ Refresh</button>
        </div>
      </div>

      <div class="card">
        <div class="tab-bar">
          <button class="tab-btn ${activeTab === 'ospf' ? 'active' : ''}" data-tab="ospf">OSPF</button>
          <button class="tab-btn ${activeTab === 'bgp' ? 'active' : ''}" data-tab="bgp">BGP</button>
          <button class="tab-btn ${activeTab === 'static' ? 'active' : ''}" data-tab="static">Static Routes</button>
          <button class="tab-btn ${activeTab === 'active' ? 'active' : ''}" data-tab="active">Active Routes</button>
        </div>

        ${error ? `<p style="color: var(--color-danger); margin-bottom: var(--spacing-md);">${error}</p>` : ''}

        ${activeTab === 'ospf' ? this.renderOspf() : ''}
        ${activeTab === 'bgp' ? this.renderBgp() : ''}
        ${activeTab === 'static' ? this.renderStatic() : ''}
        ${activeTab === 'active' ? this.renderActive() : ''}
      </div>
    `;

    this.$$<HTMLButtonElement>('.tab-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        const tab = btn.dataset.tab as typeof activeTab;
        this.setState({ activeTab: tab, error: null });
        if (tab === 'active') this.loadRoutingTable();
        if (tab === 'ospf') this.loadOspfNeighbors();
        if (tab === 'bgp') this.loadBgpSummary();
      });
    });

    this.$<HTMLButtonElement>('#refresh-btn')?.addEventListener('click', () => this.loadData());
    this.$<HTMLButtonElement>('#add-ospf-net')?.addEventListener('click', () => this.openAddNetworkModal());
  }

  private renderOspf(): string {
    const ospf = this.state.ospf;
    if (!ospf) return '<p style="color: var(--color-text-muted);">OSPF not configured</p>';
    const { ospfNeighbors } = this.state;
    return `
      <div style="display: flex; align-items: center; gap: var(--spacing-md); margin-bottom: var(--spacing-lg);">
        <label class="toggle"><input type="checkbox" ${ospf.enabled ? 'checked' : ''} id="ospf-enabled"><span class="toggle-track"></span></label>
        <strong>OSPF Enabled</strong>
        <div class="form-group" style="margin: 0; margin-left: var(--spacing-lg);"><span class="form-label" style="display: inline;">Router ID</span>
          <input type="text" class="form-input" value="${escapeHtml(ospf.router_id || '')}" style="width: 160px; display: inline-block; margin-left: var(--spacing-sm);" placeholder="Auto">
        </div>
      </div>
      <div class="table-container">
        <table class="table">
          <thead><tr><th>Network Prefix</th><th>Area</th><th>Area Type</th><th></th></tr></thead>
          <tbody>
            ${ospf.networks?.map((n: OspfNetwork, i: number) => `
              <tr>
                <td class="mono">${escapeHtml(n.prefix)}</td>
                <td>${escapeHtml(String(n.area))}</td>
                <td><span class="badge badge-outline badge-sm">Normal</span></td>
                <td><div class="actions">
                  <button class="btn-icon" title="Edit">✎</button>
                  <button class="btn-icon danger" title="Delete" data-del-ospf="${i}">🗑</button>
                </div></td>
              </tr>
            `).join('') || '<tr><td colspan="4" style="color: var(--color-text-muted);">No networks</td></tr>'}
          </tbody>
        </table>
      </div>
      <button id="add-ospf-net" class="btn btn-secondary" style="margin-top: var(--spacing-md);">+ Add Network</button>

      ${ospfNeighbors.length > 0 ? `
        <h4 style="margin: var(--spacing-lg) 0 var(--spacing-sm);">Neighbor Status</h4>
        <div class="table-container">
          <table class="table">
            <thead><tr><th>Neighbor ID</th><th>IP Address</th><th>State</th><th>Uptime</th></tr></thead>
            <tbody>
              ${ospfNeighbors.map((n: OspfNeighborStatus) => `
                <tr>
                  <td class="mono">${escapeHtml(n.neighbor_id)}</td><td class="mono">${escapeHtml(n.ip_address)}</td>
                  <td><span class="badge ${n.state === 'FULL' ? 'badge-success' : 'badge-warning'} badge-sm">${escapeHtml(n.state)}</span></td>
                  <td>${escapeHtml(n.uptime)}</td>
                </tr>
              `).join('')}
            </tbody>
          </table>
        </div>
      ` : ''}
    `;
  }

  private renderBgp(): string {
    const bgp = this.state.bgp;
    if (!bgp) return '<p style="color: var(--color-text-muted);">BGP not configured</p>';
    return `
      <div style="display: flex; align-items: center; gap: var(--spacing-md); margin-bottom: var(--spacing-lg);">
        <label class="toggle"><input type="checkbox" ${bgp.enabled ? 'checked' : ''}><span class="toggle-track"></span></label>
        <strong>BGP Enabled</strong>
        <span style="margin-left: var(--spacing-lg); color: var(--color-text-secondary);">AS ${escapeHtml(String(bgp.local_as))} | Router ID ${escapeHtml(bgp.router_id)}</span>
      </div>
      <div class="table-container">
        <table class="table">
          <thead><tr><th>Address</th><th>Remote AS</th><th>Description</th><th></th></tr></thead>
          <tbody>
            ${bgp.neighbors?.map((n: BgpNeighbor) => `
              <tr>
                <td class="mono">${escapeHtml(n.address)}</td><td>${escapeHtml(String(n.remote_as))}</td><td>${escapeHtml(n.description) || '—'}</td>
                <td><div class="actions">
                  <button class="btn-icon" title="Edit">✎</button>
                  <button class="btn-icon danger" title="Delete">🗑</button>
                </div></td>
              </tr>
            `).join('') || '<tr><td colspan="4" style="color: var(--color-text-muted);">No neighbors</td></tr>'}
          </tbody>
        </table>
      </div>
      <button class="btn btn-secondary" style="margin-top: var(--spacing-md);">+ Add Neighbor</button>

      ${this.state.bgpSummary ? `
        <h4 style="margin: var(--spacing-lg) 0 var(--spacing-sm);">Peer Summary</h4>
        <div class="mono-output">${escapeHtml(this.state.bgpSummary)}</div>
      ` : ''}
    `;
  }

  private renderStatic(): string {
    const routes = this.state.staticRoutes;
    return `
      <div class="table-container">
        <table class="table">
          <thead><tr><th>Destination</th><th>Gateway</th><th>Interface</th><th>Metric</th><th></th></tr></thead>
          <tbody>
            ${routes.map((r: StaticRoute) => `
              <tr>
                <td class="mono">${escapeHtml(r.destination)}</td><td class="mono">${escapeHtml(r.gateway)}</td>
                <td>${escapeHtml(r.interface) || '—'}</td><td>${escapeHtml(String(r.metric))}</td>
                <td><div class="actions">
                  <button class="btn-icon" title="Edit">✎</button>
                  <button class="btn-icon danger" title="Delete">🗑</button>
                </div></td>
              </tr>
            `).join('') || '<tr><td colspan="5" style="color: var(--color-text-muted);">No static routes</td></tr>'}
          </tbody>
        </table>
      </div>
      <button class="btn btn-secondary" style="margin-top: var(--spacing-md);">+ Add Route</button>
    `;
  }

  private renderActive(): string {
    return `
      <p style="color: var(--color-text-secondary); margin-bottom: var(--spacing-md); font-size: var(--font-size-sm);">
        Kernel routing table from FRR/vtysh. Click Refresh to update.
      </p>
      <div class="mono-output">${escapeHtml(this.state.routingTable) || 'Click Refresh to load routing table.'}</div>
    `;
  }
}
