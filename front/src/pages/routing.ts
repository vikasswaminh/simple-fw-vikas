import { Component } from '@components/component';
import { routingApi, routesApi } from '@api/endpoints';
import type { OspfConfig, OspfNetwork, BgpConfig, BgpNeighbor, StaticRoute, OspfNeighborStatus } from '@schemas';

/**
 * Routing Page Component
 */
export class RoutingPage extends Component<{
  ospf: OspfConfig | null;
  bgp: BgpConfig | null;
  staticRoutes: StaticRoute[];
  routingTable: string;
  ospfNeighbors: OspfNeighborStatus[];
  bgpSummary: string;
  loading: boolean;
  error: string | null;
  activeTab: 'table' | 'ospf' | 'bgp' | 'static';
}> {
  constructor(element: HTMLElement | string) {
    super(element);
    this.state = {
      ospf: null,
      bgp: null,
      staticRoutes: [],
      routingTable: '',
      ospfNeighbors: [],
      bgpSummary: '',
      loading: true,
      error: null,
      activeTab: 'table',
    };
  }

  async init(): Promise<void> {
    await this.loadData();
    await this.loadRoutingTable();
  }

  private async loadData(): Promise<void> {
    try {
      const [ospf, bgp, routes] = await Promise.all([
        routingApi.getOspfConfig(),
        routingApi.getBgpConfig(),
        routesApi.getRoutes(),
      ]);

      this.setState({
        ospf,
        bgp,
        staticRoutes: routes.routes || [],
        loading: false,
      });
    } catch (error) {
      console.error('Failed to load routing config:', error);
      this.setState({
        error: error instanceof Error ? error.message : 'Failed to load routing config',
        loading: false,
      });
    }
  }

  private async loadRoutingTable(): Promise<void> {
    try {
      const data = await routingApi.getRoutingTable();
      this.setState({ routingTable: data.table || '' });
    } catch (error) {
      console.error('Failed to load routing table:', error);
    }
  }

  private async loadOspfNeighbors(): Promise<void> {
    try {
      const data = await routingApi.getOspfNeighbors();
      this.setState({ ospfNeighbors: data.neighbors || [] });
    } catch (error) {
      console.error('Failed to load OSPF neighbors:', error);
      this.setState({ error: error instanceof Error ? error.message : 'Failed to load OSPF neighbors' });
    }
  }

  private async loadBgpSummary(): Promise<void> {
    try {
      const data = await routingApi.getBgpSummary();
      this.setState({ bgpSummary: data.summary || '' });
    } catch (error) {
      console.error('Failed to load BGP summary:', error);
      this.setState({ error: error instanceof Error ? error.message : 'Failed to load BGP summary' });
    }
  }

  render(): void {
    const { ospf, bgp, staticRoutes, loading, error, activeTab } = this.state;

    if (loading) {
      this.element.innerHTML = `
        <div class="loading">
          <div class="spinner"></div>
          <span>Loading routing configuration...</span>
        </div>
      `;
      return;
    }

    this.element.innerHTML = `
      <div class="card">
        <div class="card-header">
          <h3 class="card-title">Routing</h3>
          <button id="refresh-btn" class="btn btn-secondary">Refresh</button>
        </div>

        <div style="display: flex; gap: var(--spacing-sm); margin-bottom: var(--spacing-md); border-bottom: 1px solid var(--color-border);">
          <button class="tab-btn ${activeTab === 'table' ? 'active' : ''}" data-tab="table">Routing Table</button>
          <button class="tab-btn ${activeTab === 'ospf' ? 'active' : ''}" data-tab="ospf">OSPF</button>
          <button class="tab-btn ${activeTab === 'bgp' ? 'active' : ''}" data-tab="bgp">BGP</button>
          <button class="tab-btn ${activeTab === 'static' ? 'active' : ''}" data-tab="static">Static Routes</button>
        </div>

        ${error ? `<p style="color: var(--color-danger); margin-bottom: var(--spacing-md);">${error}</p>` : ''}

        ${activeTab === 'table' ? this.renderRoutingTable() : ''}
        ${activeTab === 'ospf' ? this.renderOspf(ospf) : ''}
        ${activeTab === 'bgp' ? this.renderBgp(bgp) : ''}
        ${activeTab === 'static' ? this.renderStaticRoutes(staticRoutes) : ''}
      </div>
    `;

    // Bind events
    this.$$<HTMLButtonElement>('.tab-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        const tab = btn.dataset.tab as typeof activeTab;
        this.setState({ activeTab: tab, error: null });
        if (tab === 'table') this.loadRoutingTable();
        if (tab === 'ospf') this.loadOspfNeighbors();
        if (tab === 'bgp') this.loadBgpSummary();
      });
    });

    const refreshBtn = this.$<HTMLButtonElement>('#refresh-btn');
    refreshBtn?.addEventListener('click', () => {
      if (activeTab === 'table') this.loadRoutingTable();
      else if (activeTab === 'ospf') { this.loadData(); this.loadOspfNeighbors(); }
      else if (activeTab === 'bgp') { this.loadData(); this.loadBgpSummary(); }
      else if (activeTab === 'static') this.loadData();
    });
  }

  private renderRoutingTable(): string {
    const { routingTable } = this.state;
    return `
      <div>
        <p style="color: var(--color-text-secondary); margin-bottom: var(--spacing-md); font-size: var(--font-size-sm);">
          Kernel routing table from FRR/vtysh. Click Refresh to update.
        </p>
        <pre style="
          background: var(--color-bg-tertiary);
          padding: var(--spacing-md);
          border-radius: var(--radius-md);
          overflow-x: auto;
          font-family: monospace;
          font-size: 0.85rem;
          white-space: pre-wrap;
          word-break: break-all;
          min-height: 100px;
        ">${routingTable || 'No routing table data. Click Refresh to load.'}</pre>
      </div>
    `;
  }

  private renderOspf(ospf: OspfConfig | null): string {
    if (!ospf) return '<p>OSPF not configured</p>';
    const { ospfNeighbors } = this.state;

    return `
      <div>
        <div style="display: flex; align-items: center; gap: var(--spacing-md); margin-bottom: var(--spacing-md);">
          <label style="display: flex; align-items: center; gap: var(--spacing-sm);">
            <input type="checkbox" ${ospf.enabled ? 'checked' : ''} id="ospf-enabled">
            <span>Enable OSPF</span>
          </label>
          <button id="save-ospf" class="btn btn-primary">Save Changes</button>
        </div>

        <div class="form-group">
          <label class="form-label">Router ID</label>
          <input type="text" class="form-input" value="${ospf.router_id || ''}" placeholder="Auto">
        </div>

        <h4 style="margin: var(--spacing-md) 0 var(--spacing-sm);">Networks</h4>
        <div class="table-container">
          <table class="table">
            <thead>
              <tr>
                <th>Network</th>
                <th>Area</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              ${ospf.networks?.map((net: OspfNetwork, idx: number) => `
                <tr>
                  <td>${net.prefix}</td>
                  <td>${net.area}</td>
                  <td>
                    <button class="btn btn-danger btn-sm" data-delete-ospf-net="${idx}">Remove</button>
                  </td>
                </tr>
              `).join('') || '<tr><td colspan="3">No networks configured</td></tr>'}
            </tbody>
          </table>
        </div>

        <button id="add-ospf-net" class="btn btn-secondary" style="margin-top: var(--spacing-md);">
          Add Network
        </button>

        <!-- OSPF Neighbor Status -->
        <h4 style="margin: var(--spacing-lg) 0 var(--spacing-sm);">Neighbor Status</h4>
        <div class="table-container">
          <table class="table">
            <thead>
              <tr>
                <th>Neighbor ID</th>
                <th>IP Address</th>
                <th>State</th>
                <th>Uptime</th>
              </tr>
            </thead>
            <tbody>
              ${ospfNeighbors.length > 0 ? ospfNeighbors.map(n => `
                <tr>
                  <td>${n.neighbor_id}</td>
                  <td>${n.ip_address}</td>
                  <td>
                    <span class="badge ${n.state === 'FULL' ? 'badge-success' : n.state === '2WAY' ? 'badge-info' : 'badge-warning'}">
                      ${n.state}
                    </span>
                  </td>
                  <td>${n.uptime}</td>
                </tr>
              `).join('') : '<tr><td colspan="4">No OSPF neighbors. Click Refresh to load.</td></tr>'}
            </tbody>
          </table>
        </div>
      </div>
    `;
  }

  private renderBgp(bgp: BgpConfig | null): string {
    if (!bgp) return '<p>BGP not configured</p>';
    const { bgpSummary } = this.state;

    return `
      <div>
        <div style="display: flex; align-items: center; gap: var(--spacing-md); margin-bottom: var(--spacing-md);">
          <label style="display: flex; align-items: center; gap: var(--spacing-sm);">
            <input type="checkbox" ${bgp.enabled ? 'checked' : ''} id="bgp-enabled">
            <span>Enable BGP</span>
          </label>
          <button id="save-bgp" class="btn btn-primary">Save Changes</button>
        </div>

        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: var(--spacing-md);">
          <div class="form-group">
            <label class="form-label">Local AS</label>
            <input type="number" class="form-input" value="${bgp.local_as || ''}">
          </div>
          <div class="form-group">
            <label class="form-label">Router ID</label>
            <input type="text" class="form-input" value="${bgp.router_id || ''}">
          </div>
        </div>

        <h4 style="margin: var(--spacing-md) 0 var(--spacing-sm);">Neighbors</h4>
        <div class="table-container">
          <table class="table">
            <thead>
              <tr>
                <th>Address</th>
                <th>Remote AS</th>
                <th>Description</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              ${bgp.neighbors?.map((neighbor: BgpNeighbor, idx: number) => `
                <tr>
                  <td>${neighbor.address}</td>
                  <td>${neighbor.remote_as}</td>
                  <td>${neighbor.description || '—'}</td>
                  <td>
                    <button class="btn btn-danger btn-sm" data-delete-bgp-neighbor="${idx}">Remove</button>
                  </td>
                </tr>
              `).join('') || '<tr><td colspan="4">No neighbors configured</td></tr>'}
            </tbody>
          </table>
        </div>

        <button id="add-bgp-neighbor" class="btn btn-secondary" style="margin-top: var(--spacing-md);">
          Add Neighbor
        </button>

        <!-- BGP Summary -->
        <h4 style="margin: var(--spacing-lg) 0 var(--spacing-sm);">Peer Summary</h4>
        <pre style="
          background: var(--color-bg-tertiary);
          padding: var(--spacing-md);
          border-radius: var(--radius-md);
          overflow-x: auto;
          font-family: monospace;
          font-size: 0.85rem;
          white-space: pre-wrap;
          word-break: break-all;
          min-height: 60px;
        ">${bgpSummary || 'No BGP peer data. Click Refresh to load.'}</pre>
      </div>
    `;
  }

  private renderStaticRoutes(routes: StaticRoute[]): string {
    return `
      <div>
        <div style="margin-bottom: var(--spacing-md);">
          <button id="save-routes" class="btn btn-primary">Save Changes</button>
        </div>

        <div class="table-container">
          <table class="table">
            <thead>
              <tr>
                <th>Destination</th>
                <th>Gateway</th>
                <th>Interface</th>
                <th>Metric</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              ${routes.map((route, idx) => `
                <tr>
                  <td><input type="text" class="form-input" value="${route.destination}" data-route="${idx}" data-field="destination"></td>
                  <td><input type="text" class="form-input" value="${route.gateway}" data-route="${idx}" data-field="gateway"></td>
                  <td><input type="text" class="form-input" value="${route.interface || ''}" data-route="${idx}" data-field="interface"></td>
                  <td><input type="number" class="form-input" value="${route.metric}" data-route="${idx}" data-field="metric" style="width: 80px;"></td>
                  <td>
                    <button class="btn btn-danger btn-sm" data-delete-route="${idx}">Remove</button>
                  </td>
                </tr>
              `).join('') || '<tr><td colspan="5">No static routes configured</td></tr>'}
            </tbody>
          </table>
        </div>

        <button id="add-route" class="btn btn-secondary" style="margin-top: var(--spacing-md);">
          Add Route
        </button>
      </div>
    `;
  }
}
