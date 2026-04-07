import { Component } from '@components/component';
import { natApi } from '@api/endpoints';
import type { NatConfig, MasqueradeRule, PortForwardRule } from '@schemas';

/**
 * NAT Page Component
 */
export class NatPage extends Component<{
  config: NatConfig | null;
  loading: boolean;
  error: string | null;
  activeTab: 'masquerade' | 'port-forward';
}> {
  constructor(element: HTMLElement | string) {
    super(element);
    this.state = {
      config: null,
      loading: true,
      error: null,
      activeTab: 'masquerade',
    };
  }

  async init(): Promise<void> {
    await this.loadData();
  }

  private async loadData(): Promise<void> {
    try {
      const config = await natApi.getConfig();
      this.setState({ config, loading: false });
    } catch (error) {
      console.error('Failed to load NAT config:', error);
      this.setState({
        error: error instanceof Error ? error.message : 'Failed to load NAT config',
        loading: false,
      });
    }
  }

  render(): void {
    const { config, loading, error, activeTab } = this.state;

    if (loading) {
      this.element.innerHTML = `
        <div class="loading">
          <div class="spinner"></div>
          <span>Loading NAT configuration...</span>
        </div>
      `;
      return;
    }

    this.element.innerHTML = `
      <div class="card">
        <div class="card-header">
          <h3 class="card-title">NAT Configuration</h3>
          <button id="add-rule-btn" class="btn btn-primary">Add Rule</button>
        </div>

        <!-- Tabs -->
        <div style="display: flex; gap: var(--spacing-sm); margin-bottom: var(--spacing-md); border-bottom: 1px solid var(--color-border);">
          <button class="tab-btn ${activeTab === 'masquerade' ? 'active' : ''}" data-tab="masquerade">
            Masquerade (SNAT)
          </button>
          <button class="tab-btn ${activeTab === 'port-forward' ? 'active' : ''}" data-tab="port-forward">
            Port Forward (DNAT)
          </button>
        </div>

        ${error ? `<p style="color: var(--color-danger)">${error}</p>` : ''}

        ${activeTab === 'masquerade' ? `
          <div class="table-container">
            <table class="table">
              <thead>
                <tr>
                  <th>Outgoing Interface</th>
                  <th>Source Network</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                ${config?.masquerade?.map((rule, idx) => `
                  <tr>
                    <td>${rule.out_interface}</td>
                    <td>${rule.source_cidr || 'any'}</td>
                    <td>
                      <button class="btn btn-danger btn-sm" data-delete-masq="${idx}">Delete</button>
                    </td>
                  </tr>
                `).join('') || '<tr><td colspan="3">No masquerade rules configured</td></tr>'}
              </tbody>
            </table>
          </div>
        ` : `
          <div class="table-container">
            <table class="table">
              <thead>
                <tr>
                  <th>Protocol</th>
                  <th>External Port</th>
                  <th>Forward To</th>
                  <th>In Interface</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                ${config?.port_forward?.map((rule, idx) => `
                  <tr>
                    <td>${rule.protocol}</td>
                    <td>${rule.dest_port}</td>
                    <td>${rule.forward_to}</td>
                    <td>${rule.in_interface}</td>
                    <td>
                      <button class="btn btn-danger btn-sm" data-delete-pf="${idx}">Delete</button>
                    </td>
                  </tr>
                `).join('') || '<tr><td colspan="5">No port forwarding rules configured</td></tr>'}
              </tbody>
            </table>
          </div>
        `}
      </div>
    `;

    // Bind tab events
    this.$$<HTMLButtonElement>('.tab-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        const tab = btn.dataset.tab as 'masquerade' | 'port-forward';
        this.setState({ activeTab: tab });
      });
    });
  }
}
