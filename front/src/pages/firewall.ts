import { Component } from '@components/component';
import { firewallApi } from '@api/endpoints';
import { formatBytes } from '@utils';
import type { FirewallRule, FirewallConfig, FirewallGroups, RuleCounter, AddressGroup, PortGroup } from '@schemas';

/**
 * Firewall Page Component
 */
export class FirewallPage extends Component<{
  config: FirewallConfig | null;
  groups: FirewallGroups | null;
  counters: RuleCounter[];
  loading: boolean;
  error: string | null;
  editingRule: FirewallRule | null;
  activeTab: 'rules' | 'counters' | 'groups';
}> {
  constructor(element: HTMLElement | string) {
    super(element);
    this.state = {
      config: null,
      groups: null,
      counters: [],
      loading: true,
      error: null,
      editingRule: null,
      activeTab: 'rules',
    };
  }

  async init(): Promise<void> {
    await this.loadData();
  }

  private async loadData(): Promise<void> {
    try {
      const config = await firewallApi.getConfig();
      this.setState({ config, loading: false });
    } catch (error) {
      console.error('Failed to load firewall config:', error);
      this.setState({
        error: error instanceof Error ? error.message : 'Failed to load firewall config',
        loading: false,
      });
    }
  }

  private async loadCounters(): Promise<void> {
    try {
      const data = await firewallApi.getCounters() as { counters: RuleCounter[] };
      this.setState({ counters: data.counters || [] });
    } catch (error) {
      console.error('Failed to load counters:', error);
      this.setState({ error: error instanceof Error ? error.message : 'Failed to load counters' });
    }
  }

  private async loadGroups(): Promise<void> {
    try {
      const groups = await firewallApi.getGroups();
      this.setState({ groups });
    } catch (error) {
      console.error('Failed to load groups:', error);
      this.setState({ error: error instanceof Error ? error.message : 'Failed to load groups' });
    }
  }

  render(): void {
    const { loading, error, activeTab } = this.state;

    if (loading && !this.state.config) {
      this.element.innerHTML = `
        <div class="loading">
          <div class="spinner"></div>
          <span>Loading firewall rules...</span>
        </div>
      `;
      return;
    }

    this.element.innerHTML = `
      <div class="card">
        <div class="card-header">
          <h3 class="card-title">Firewall</h3>
          <div style="display: flex; gap: var(--spacing-sm);">
            ${activeTab === 'rules' ? `
              <button id="preview-btn" class="btn btn-secondary">Preview</button>
              <button id="add-rule-btn" class="btn btn-primary">Add Rule</button>
            ` : ''}
            <button id="refresh-btn" class="btn btn-secondary">Refresh</button>
          </div>
        </div>

        <div style="display: flex; gap: var(--spacing-sm); margin-bottom: var(--spacing-md); border-bottom: 1px solid var(--color-border);">
          <button class="tab-btn ${activeTab === 'rules' ? 'active' : ''}" data-tab="rules">Rulebase</button>
          <button class="tab-btn ${activeTab === 'counters' ? 'active' : ''}" data-tab="counters">Hit Counters</button>
          <button class="tab-btn ${activeTab === 'groups' ? 'active' : ''}" data-tab="groups">Address / Port Groups</button>
        </div>

        ${error ? `<p style="color: var(--color-danger); margin-bottom: var(--spacing-md);">${error}</p>` : ''}

        ${activeTab === 'rules' ? this.renderRules() : ''}
        ${activeTab === 'counters' ? this.renderCounters() : ''}
        ${activeTab === 'groups' ? this.renderGroups() : ''}
      </div>
    `;

    // Bind tab events
    this.$$<HTMLButtonElement>('.tab-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        const tab = btn.dataset.tab as typeof activeTab;
        this.setState({ activeTab: tab, error: null });
        if (tab === 'counters') this.loadCounters();
        if (tab === 'groups') this.loadGroups();
      });
    });

    const refreshBtn = this.$<HTMLButtonElement>('#refresh-btn');
    refreshBtn?.addEventListener('click', () => {
      if (activeTab === 'rules') this.loadData();
      else if (activeTab === 'counters') this.loadCounters();
      else if (activeTab === 'groups') this.loadGroups();
    });
  }

  private renderRules(): string {
    const { config } = this.state;
    return `
      <div class="table-container">
        <table class="table">
          <thead>
            <tr>
              <th>#</th>
              <th>Name</th>
              <th>Direction</th>
              <th>Protocol</th>
              <th>Source</th>
              <th>Destination</th>
              <th>Action</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            ${config?.rules?.map((rule: FirewallRule, idx: number) => `
              <tr>
                <td>${idx + 1}</td>
                <td>${rule.name}</td>
                <td>${rule.direction}</td>
                <td>${rule.protocol}</td>
                <td>${rule.src_ip || 'any'}${rule.src_port ? ':' + rule.src_port : ''}</td>
                <td>${rule.dst_ip || 'any'}${rule.dst_port ? ':' + rule.dst_port : ''}</td>
                <td>
                  <span class="badge ${rule.action === 'accept' ? 'badge-success' : rule.action === 'reject' ? 'badge-warning' : 'badge-danger'}">
                    ${rule.action}
                  </span>
                </td>
                <td>
                  <span class="badge ${rule.enabled ? 'badge-success' : 'badge-warning'}">
                    ${rule.enabled ? 'Enabled' : 'Disabled'}
                  </span>
                </td>
              </tr>
            `).join('') || '<tr><td colspan="8">No rules configured</td></tr>'}
          </tbody>
        </table>
      </div>

      ${this.state.config ? `
        <div style="margin-top: var(--spacing-md); padding: var(--spacing-md); background: var(--color-bg-tertiary); border-radius: var(--radius-md);">
          <strong>Default Policies:</strong>
          <span style="margin-left: var(--spacing-md);">Forward: <span class="badge ${config?.forward_policy === 'accept' ? 'badge-success' : 'badge-danger'}">${config?.forward_policy}</span></span>
          <span style="margin-left: var(--spacing-md);">Input: <span class="badge ${config?.input_policy === 'accept' ? 'badge-success' : 'badge-danger'}">${config?.input_policy}</span></span>
          <span style="margin-left: var(--spacing-md);">Output: <span class="badge ${config?.output_policy === 'accept' ? 'badge-success' : 'badge-danger'}">${config?.output_policy}</span></span>
        </div>
      ` : ''}
    `;
  }

  private renderCounters(): string {
    const { counters } = this.state;
    return `
      <div>
        <p style="color: var(--color-text-secondary); margin-bottom: var(--spacing-md); font-size: var(--font-size-sm);">
          Live rule hit counters from nftables. Click Refresh to update.
        </p>
        <div class="table-container">
          <table class="table">
            <thead>
              <tr>
                <th>Chain</th>
                <th>Rule</th>
                <th>Packets</th>
                <th>Bytes</th>
              </tr>
            </thead>
            <tbody>
              ${counters.length > 0 ? counters.map(c => `
                <tr>
                  <td>${c.chain}</td>
                  <td>${c.comment}</td>
                  <td style="font-family: monospace;">${c.packets.toLocaleString()}</td>
                  <td style="font-family: monospace;">${formatBytes(c.bytes)}</td>
                </tr>
              `).join('') : '<tr><td colspan="4">No counters available. Click Refresh to load.</td></tr>'}
            </tbody>
          </table>
        </div>
      </div>
    `;
  }

  private renderGroups(): string {
    const { groups } = this.state;
    return `
      <div style="display: grid; gap: var(--spacing-lg);">
        <div>
          <h4 style="margin-bottom: var(--spacing-sm);">Address Groups</h4>
          <div class="table-container">
            <table class="table">
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Addresses</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                ${groups?.address_groups && groups.address_groups.length > 0 ? groups.address_groups.map((g: AddressGroup, idx: number) => `
                  <tr>
                    <td><strong>${g.name}</strong></td>
                    <td style="font-family: monospace; font-size: 0.85em;">${g.addresses.join(', ')}</td>
                    <td>
                      <button class="btn btn-danger btn-sm" data-delete-ag="${idx}">Remove</button>
                    </td>
                  </tr>
                `).join('') : '<tr><td colspan="3">No address groups defined. Click Refresh to load.</td></tr>'}
              </tbody>
            </table>
          </div>
        </div>

        <div>
          <h4 style="margin-bottom: var(--spacing-sm);">Port Groups</h4>
          <div class="table-container">
            <table class="table">
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Ports</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                ${groups?.port_groups && groups.port_groups.length > 0 ? groups.port_groups.map((g: PortGroup, idx: number) => `
                  <tr>
                    <td><strong>${g.name}</strong></td>
                    <td style="font-family: monospace; font-size: 0.85em;">${g.ports.join(', ')}</td>
                    <td>
                      <button class="btn btn-danger btn-sm" data-delete-pg="${idx}">Remove</button>
                    </td>
                  </tr>
                `).join('') : '<tr><td colspan="3">No port groups defined. Click Refresh to load.</td></tr>'}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    `;
  }
}
