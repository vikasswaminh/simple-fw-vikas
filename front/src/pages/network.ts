import { Component } from '@components/component';
import { networkApi, toolsApi } from '@api/endpoints';
import type { Interface, ArpEntry, DhcpLease, DnsLocalEntry } from '@schemas';
import { formatBytes } from '@utils';

/**
 * Network Page Component
 */
export class NetworkPage extends Component<{
  interfaces: Interface[];
  arpEntries: ArpEntry[];
  dhcpLeases: DhcpLease[];
  dnsEntries: DnsLocalEntry[];
  loading: boolean;
  error: string | null;
  activeTab: 'interfaces' | 'arp' | 'dhcp' | 'dns';
  dnsNewHostname: string;
  dnsNewIp: string;
}> {
  constructor(element: HTMLElement | string) {
    super(element);
    this.state = {
      interfaces: [],
      arpEntries: [],
      dhcpLeases: [],
      dnsEntries: [],
      loading: true,
      error: null,
      activeTab: 'interfaces',
      dnsNewHostname: '',
      dnsNewIp: '',
    };
  }

  async init(): Promise<void> {
    await this.loadData();
  }

  private async loadData(): Promise<void> {
    this.setState({ loading: true, error: null });
    try {
      const { interfaces } = await networkApi.getInterfaces();
      this.setState({ interfaces, loading: false });
    } catch (error) {
      console.error('Failed to load interfaces:', error);
      this.setState({
        error: error instanceof Error ? error.message : 'Failed to load interfaces',
        loading: false,
      });
    }
  }

  private async loadArp(): Promise<void> {
    try {
      const arpEntries = await toolsApi.getArpTable();
      this.setState({ arpEntries });
    } catch (error) {
      console.error('Failed to load ARP table:', error);
      this.setState({ error: error instanceof Error ? error.message : 'Failed to load ARP table' });
    }
  }

  private async loadDhcp(): Promise<void> {
    try {
      const dhcpLeases = await toolsApi.getDhcpLeases();
      this.setState({ dhcpLeases });
    } catch (error) {
      console.error('Failed to load DHCP leases:', error);
      this.setState({ error: error instanceof Error ? error.message : 'Failed to load DHCP leases' });
    }
  }

  private async loadDns(): Promise<void> {
    try {
      const dnsEntries = await toolsApi.getDnsLocal();
      this.setState({ dnsEntries });
    } catch (error) {
      console.error('Failed to load DNS overrides:', error);
      this.setState({ error: error instanceof Error ? error.message : 'Failed to load DNS overrides' });
    }
  }

  private async saveDns(): Promise<void> {
    try {
      await toolsApi.saveDnsLocal(this.state.dnsEntries);
      this.setState({ error: null });
    } catch (error) {
      console.error('Failed to save DNS overrides:', error);
      this.setState({ error: error instanceof Error ? error.message : 'Failed to save DNS overrides' });
    }
  }

  render(): void {
    const { loading, error, activeTab } = this.state;

    if (loading && this.state.interfaces.length === 0) {
      this.element.innerHTML = `
        <div class="loading">
          <div class="spinner"></div>
          <span>Loading network data...</span>
        </div>
      `;
      return;
    }

    this.element.innerHTML = `
      <div class="card">
        <div class="card-header">
          <h3 class="card-title">Network</h3>
          <button id="refresh-btn" class="btn btn-secondary">Refresh</button>
        </div>

        <div style="display: flex; gap: var(--spacing-sm); margin-bottom: var(--spacing-md); border-bottom: 1px solid var(--color-border);">
          <button class="tab-btn ${activeTab === 'interfaces' ? 'active' : ''}" data-tab="interfaces">Interfaces</button>
          <button class="tab-btn ${activeTab === 'arp' ? 'active' : ''}" data-tab="arp">ARP Table</button>
          <button class="tab-btn ${activeTab === 'dhcp' ? 'active' : ''}" data-tab="dhcp">DHCP Leases</button>
          <button class="tab-btn ${activeTab === 'dns' ? 'active' : ''}" data-tab="dns">DNS Overrides</button>
        </div>

        ${error ? `<p style="color: var(--color-danger); margin-bottom: var(--spacing-md);">${error}</p>` : ''}

        ${activeTab === 'interfaces' ? this.renderInterfaces() : ''}
        ${activeTab === 'arp' ? this.renderArp() : ''}
        ${activeTab === 'dhcp' ? this.renderDhcp() : ''}
        ${activeTab === 'dns' ? this.renderDns() : ''}
      </div>
    `;

    // Bind tab events
    this.$$<HTMLButtonElement>('.tab-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        const tab = btn.dataset.tab as typeof activeTab;
        this.setState({ activeTab: tab, error: null });
        if (tab === 'arp') this.loadArp();
        if (tab === 'dhcp') this.loadDhcp();
        if (tab === 'dns') this.loadDns();
      });
    });

    const refreshBtn = this.$<HTMLButtonElement>('#refresh-btn');
    refreshBtn?.addEventListener('click', () => {
      if (activeTab === 'interfaces') this.loadData();
      else if (activeTab === 'arp') this.loadArp();
      else if (activeTab === 'dhcp') this.loadDhcp();
      else if (activeTab === 'dns') this.loadDns();
    });

    // DNS form events
    if (activeTab === 'dns') {
      this.bindDnsEvents();
    }
  }

  private renderInterfaces(): string {
    const { interfaces } = this.state;
    return `
      <div class="table-container">
        <table class="table">
          <thead>
            <tr>
              <th>Interface</th>
              <th>Role</th>
              <th>Status</th>
              <th>IP Address</th>
              <th>RX / TX</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            ${interfaces.map(iface => `
              <tr>
                <td>${iface.name}</td>
                <td>
                  <select class="form-select" data-iface="${iface.name}" style="width: auto;">
                    <option value="" ${!iface.role ? 'selected' : ''}>None</option>
                    <option value="wan" ${iface.role === 'wan' ? 'selected' : ''}>WAN</option>
                    <option value="lan" ${iface.role === 'lan' ? 'selected' : ''}>LAN</option>
                    <option value="dmz" ${iface.role === 'dmz' ? 'selected' : ''}>DMZ</option>
                  </select>
                </td>
                <td>
                  <span class="badge ${iface.link_up ? 'badge-success' : 'badge-danger'}">
                    ${iface.link_up ? 'Up' : 'Down'}
                  </span>
                </td>
                <td>${iface.ipv4_addrs?.join(', ') || '—'}</td>
                <td>${formatBytes(iface.rx_bytes || 0)} / ${formatBytes(iface.tx_bytes || 0)}</td>
                <td>
                  <button class="btn btn-secondary btn-sm" data-config="${iface.name}">
                    Configure
                  </button>
                </td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>
    `;
  }

  private renderArp(): string {
    const { arpEntries } = this.state;
    return `
      <div class="table-container">
        <table class="table">
          <thead>
            <tr>
              <th>IP Address</th>
              <th>MAC Address</th>
              <th>Interface</th>
              <th>State</th>
            </tr>
          </thead>
          <tbody>
            ${arpEntries.length > 0 ? arpEntries.map(entry => `
              <tr>
                <td>${entry.ip}</td>
                <td style="font-family: monospace;">${entry.mac}</td>
                <td>${entry.interface}</td>
                <td>
                  <span class="badge ${entry.state === 'REACHABLE' ? 'badge-success' : entry.state === 'STALE' ? 'badge-warning' : 'badge-info'}">
                    ${entry.state}
                  </span>
                </td>
              </tr>
            `).join('') : '<tr><td colspan="4">No ARP entries found. Click Refresh to load.</td></tr>'}
          </tbody>
        </table>
      </div>
    `;
  }

  private renderDhcp(): string {
    const { dhcpLeases } = this.state;
    return `
      <div class="table-container">
        <table class="table">
          <thead>
            <tr>
              <th>IP Address</th>
              <th>MAC Address</th>
              <th>Hostname</th>
              <th>Expires</th>
              <th>Client ID</th>
            </tr>
          </thead>
          <tbody>
            ${dhcpLeases.length > 0 ? dhcpLeases.map(lease => `
              <tr>
                <td>${lease.ip}</td>
                <td style="font-family: monospace;">${lease.mac}</td>
                <td>${lease.hostname || '—'}</td>
                <td>${lease.expires}</td>
                <td style="font-family: monospace; font-size: 0.8em;">${lease.client_id || '—'}</td>
              </tr>
            `).join('') : '<tr><td colspan="5">No DHCP leases found. Click Refresh to load.</td></tr>'}
          </tbody>
        </table>
      </div>
    `;
  }

  private renderDns(): string {
    const { dnsEntries } = this.state;
    return `
      <div>
        <div style="margin-bottom: var(--spacing-md);">
          <h4 style="margin-bottom: var(--spacing-sm);">Local DNS Overrides</h4>
          <p style="color: var(--color-text-secondary); font-size: var(--font-size-sm);">
            Custom hostname-to-IP mappings served by the local DNS resolver.
          </p>
        </div>

        <div class="table-container">
          <table class="table">
            <thead>
              <tr>
                <th>Hostname</th>
                <th>IP Address</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              ${dnsEntries.length > 0 ? dnsEntries.map((entry, idx) => `
                <tr>
                  <td>${entry.hostname}</td>
                  <td>${entry.ip}</td>
                  <td>
                    <button class="btn btn-danger btn-sm" data-delete-dns="${idx}">Remove</button>
                  </td>
                </tr>
              `).join('') : '<tr><td colspan="3">No DNS overrides configured. Click Refresh to load.</td></tr>'}
            </tbody>
          </table>
        </div>

        <div style="margin-top: var(--spacing-md); display: flex; gap: var(--spacing-sm); align-items: flex-end;">
          <div class="form-group" style="flex: 1;">
            <label class="form-label">Hostname</label>
            <input type="text" id="dns-hostname" class="form-input" placeholder="myhost.local">
          </div>
          <div class="form-group" style="flex: 1;">
            <label class="form-label">IP Address</label>
            <input type="text" id="dns-ip" class="form-input" placeholder="192.168.1.100">
          </div>
          <button id="add-dns-btn" class="btn btn-primary">Add</button>
        </div>

        ${dnsEntries.length > 0 ? `
          <div style="margin-top: var(--spacing-md);">
            <button id="save-dns-btn" class="btn btn-primary">Save DNS Overrides</button>
          </div>
        ` : ''}
      </div>
    `;
  }

  private bindDnsEvents(): void {
    // Add DNS entry
    const addBtn = this.$<HTMLButtonElement>('#add-dns-btn');
    addBtn?.addEventListener('click', () => {
      const hostnameInput = this.$<HTMLInputElement>('#dns-hostname');
      const ipInput = this.$<HTMLInputElement>('#dns-ip');
      const hostname = hostnameInput?.value.trim();
      const ip = ipInput?.value.trim();
      if (hostname && ip) {
        const dnsEntries = [...this.state.dnsEntries, { hostname, ip }];
        this.setState({ dnsEntries });
      }
    });

    // Delete DNS entries
    this.$$<HTMLButtonElement>('[data-delete-dns]').forEach(btn => {
      btn.addEventListener('click', () => {
        const idx = parseInt(btn.dataset.deleteDns!);
        const dnsEntries = this.state.dnsEntries.filter((_, i) => i !== idx);
        this.setState({ dnsEntries });
      });
    });

    // Save DNS
    const saveBtn = this.$<HTMLButtonElement>('#save-dns-btn');
    saveBtn?.addEventListener('click', () => this.saveDns());
  }
}
