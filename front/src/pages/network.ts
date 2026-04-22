import { Component } from '@components/component';
import { networkApi, toolsApi } from '@api/endpoints';
import { openModal, closeModal } from '@components/modal';
import { showToast } from '@components/toast';
import type { Interface, ArpEntry, DhcpLease, DnsLocalEntry } from '@schemas';
import { formatBytes, escapeHtml } from '@utils';

export class NetworkPage extends Component<{
  interfaces: Interface[];
  arpEntries: ArpEntry[];
  dhcpLeases: DhcpLease[];
  dnsEntries: DnsLocalEntry[];
  loading: boolean;
  error: string | null;
  activeTab: 'interfaces' | 'dhcp' | 'arp';
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
    };
  }

  async init(): Promise<void> {
    await this.loadInterfaces();
  }

  private async loadInterfaces(): Promise<void> {
    this.setState({ loading: true });
    try {
      const { interfaces } = await networkApi.getInterfaces();
      this.setState({ interfaces, loading: false });
    } catch (error) {
      this.setState({ error: error instanceof Error ? error.message : 'Failed to load', loading: false });
    }
  }

  private async loadArp(): Promise<void> {
    try {
      const arpEntries = await toolsApi.getArpTable();
      this.setState({ arpEntries });
    } catch (error) {
      this.setState({ error: error instanceof Error ? error.message : 'Failed to load ARP' });
    }
  }

  private async loadDhcp(): Promise<void> {
    try {
      const dhcpLeases = await toolsApi.getDhcpLeases();
      this.setState({ dhcpLeases });
    } catch (error) {
      this.setState({ error: error instanceof Error ? error.message : 'Failed to load DHCP' });
    }
  }

  private openDnsModal(): void {
    toolsApi.getDnsLocal().then(entries => {
      openModal({
        title: 'DNS Settings',
        size: 'lg',
        body: `
          <p style="margin-bottom: var(--spacing-md); color: var(--color-text-secondary); font-size: var(--font-size-sm);">
            Local DNS hostname-to-IP overrides served by the DNS resolver.
          </p>
          <div id="dns-entries">
            ${entries.map((e: DnsLocalEntry, i: number) => `
              <div class="kv-row" data-dns-idx="${i}">
                <span>${escapeHtml(e.hostname)} → ${escapeHtml(e.ip)}</span>
                <button class="btn-icon danger" data-delete-dns="${i}">✕</button>
              </div>
            `).join('') || '<p style="color: var(--color-text-muted);">No entries</p>'}
          </div>
          <div style="display: flex; gap: var(--spacing-sm); margin-top: var(--spacing-md);">
            <input type="text" class="form-input" id="dns-host" placeholder="hostname.local" style="flex:1;">
            <input type="text" class="form-input" id="dns-ip" placeholder="192.168.1.100" style="flex:1;">
            <button class="btn btn-primary btn-sm" id="dns-add-btn">Add</button>
          </div>
        `,
        footer: `
          <button class="btn btn-secondary" onclick="document.querySelector('.modal-close')?.click()">Cancel</button>
          <button class="btn btn-primary" data-modal-submit>Save</button>
        `,
        onSubmit: async () => {
          try {
            await toolsApi.saveDnsLocal(entries);
            showToast('DNS settings saved', 'success');
            closeModal();
          } catch {
            showToast('Failed to save DNS settings', 'error');
          }
        },
      });
    });
  }

  render(): void {
    const { interfaces, arpEntries, dhcpLeases, loading, error, activeTab } = this.state;

    if (loading && interfaces.length === 0) {
      this.element.innerHTML = `<div class="loading"><div class="spinner"></div> Loading...</div>`;
      return;
    }

    this.element.innerHTML = `
      <div class="page-header">
        <h1 class="page-title">Network</h1>
        <div class="page-actions">
          <button id="dns-settings-btn" class="btn btn-secondary">⊕ DNS Settings</button>
          <button id="refresh-btn" class="btn btn-secondary">↻ Refresh</button>
        </div>
      </div>

      <div class="card">
        <div class="tab-bar">
          <button class="tab-btn ${activeTab === 'interfaces' ? 'active' : ''}" data-tab="interfaces">Interfaces</button>
          <button class="tab-btn ${activeTab === 'dhcp' ? 'active' : ''}" data-tab="dhcp">DHCP Leases</button>
          <button class="tab-btn ${activeTab === 'arp' ? 'active' : ''}" data-tab="arp">ARP Table</button>
        </div>

        ${error ? `<p style="color: var(--color-danger); margin-bottom: var(--spacing-md);">${error}</p>` : ''}

        ${activeTab === 'interfaces' ? this.renderInterfaces(interfaces) : ''}
        ${activeTab === 'dhcp' ? this.renderDhcp(dhcpLeases) : ''}
        ${activeTab === 'arp' ? this.renderArp(arpEntries) : ''}
      </div>
    `;

    this.$$<HTMLButtonElement>('.tab-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        const tab = btn.dataset.tab as typeof activeTab;
        this.setState({ activeTab: tab, error: null });
        if (tab === 'arp') this.loadArp();
        if (tab === 'dhcp') this.loadDhcp();
      });
    });

    this.$<HTMLButtonElement>('#refresh-btn')?.addEventListener('click', () => {
      if (activeTab === 'interfaces') this.loadInterfaces();
      else if (activeTab === 'arp') this.loadArp();
      else if (activeTab === 'dhcp') this.loadDhcp();
    });

    this.$<HTMLButtonElement>('#dns-settings-btn')?.addEventListener('click', () => this.openDnsModal());
  }

  private renderInterfaces(interfaces: Interface[]): string {
    return `
      <div class="table-container">
        <table class="table">
          <thead>
            <tr>
              <th>Interface</th>
              <th>Role</th>
              <th>Status</th>
              <th>IP Address</th>
              <th>MAC</th>
              <th>RX</th>
              <th>TX</th>
            </tr>
          </thead>
          <tbody>
            ${interfaces.map((iface: Interface) => `
              <tr>
                <td><strong>${iface.name}</strong></td>
                <td>
                  <select class="form-select" style="width: 90px; padding: 4px 8px;" data-iface="${iface.name}">
                    <option value="" ${!iface.role || iface.role === 'unset' ? 'selected' : ''}>None</option>
                    <option value="wan" ${iface.role === 'wan' ? 'selected' : ''}>WAN</option>
                    <option value="lan" ${iface.role === 'lan' ? 'selected' : ''}>LAN</option>
                    <option value="dmz" ${iface.role === 'dmz' ? 'selected' : ''}>DMZ</option>
                  </select>
                </td>
                <td>
                  <label class="toggle">
                    <input type="checkbox" ${iface.link_up ? 'checked' : ''} disabled>
                    <span class="toggle-track"></span>
                  </label>
                </td>
                <td class="mono">${iface.ipv4_addrs?.[0] || '—'}</td>
                <td class="mono">${iface.mac || '—'}</td>
                <td class="mono">${formatBytes(iface.rx_bytes || 0)}</td>
                <td class="mono">${formatBytes(iface.tx_bytes || 0)}</td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>
    `;
  }

  private renderDhcp(leases: DhcpLease[]): string {
    return `
      <div class="table-container">
        <table class="table">
          <thead>
            <tr><th>MAC Address</th><th>IP Address</th><th>Hostname</th><th>Expires</th><th>Status</th></tr>
          </thead>
          <tbody>
            ${leases.length > 0 ? leases.map((l: DhcpLease) => `
              <tr>
                <td class="mono">${escapeHtml(l.mac)}</td>
                <td class="mono">${escapeHtml(l.ip)}</td>
                <td>${escapeHtml(l.hostname) || '—'}</td>
                <td>${escapeHtml(l.expires)}</td>
                <td><span class="badge badge-success badge-sm">active</span></td>
              </tr>
            `).join('') : '<tr><td colspan="5" style="color: var(--color-text-muted);">No DHCP leases. Click Refresh to load.</td></tr>'}
          </tbody>
        </table>
      </div>
    `;
  }

  private renderArp(entries: ArpEntry[]): string {
    return `
      <div style="display: flex; justify-content: flex-end; margin-bottom: var(--spacing-md);">
        <button class="btn btn-secondary btn-sm" id="flush-arp-btn">Flush ARP</button>
      </div>
      <div class="table-container">
        <table class="table">
          <thead>
            <tr><th>IP Address</th><th>MAC Address</th><th>Interface</th><th>State</th></tr>
          </thead>
          <tbody>
            ${entries.length > 0 ? entries.map((e: ArpEntry) => `
              <tr>
                <td class="mono">${escapeHtml(e.ip)}</td>
                <td class="mono">${escapeHtml(e.mac)}</td>
                <td>${escapeHtml(e.interface)}</td>
                <td><span class="badge ${e.state === 'REACHABLE' ? 'badge-success' : e.state === 'STALE' ? 'badge-outline' : 'badge-warning'} badge-sm">${e.state}</span></td>
              </tr>
            `).join('') : '<tr><td colspan="4" style="color: var(--color-text-muted);">No ARP entries. Click Refresh to load.</td></tr>'}
          </tbody>
        </table>
      </div>
    `;
  }
}
