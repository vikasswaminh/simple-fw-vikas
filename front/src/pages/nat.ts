import { Component } from '@components/component';
import { natApi } from '@api/endpoints';
import { openModal, closeModal } from '@components/modal';
import { showToast } from '@components/toast';
import type { NatConfig, MasqueradeRule, PortForwardRule } from '@schemas';

export class NatPage extends Component<{
  config: NatConfig | null;
  loading: boolean;
  error: string | null;
  activeTab: 'masquerade' | 'port-forward' | 'static';
}> {
  constructor(element: HTMLElement | string) {
    super(element);
    this.state = { config: null, loading: true, error: null, activeTab: 'masquerade' };
  }

  async init(): Promise<void> {
    await this.loadData();
  }

  private async loadData(): Promise<void> {
    try {
      const config = await natApi.getConfig();
      this.setState({ config, loading: false });
    } catch (error) {
      this.setState({ error: error instanceof Error ? error.message : 'Failed to load', loading: false });
    }
  }

  private openAddMasqueradeModal(): void {
    openModal({
      title: '+ Add Masquerade Rule',
      body: `
        <div class="form-group"><label class="form-label">Out Interface</label><input type="text" class="form-input" id="masq-iface" placeholder="eth0"></div>
        <div class="form-group"><label class="form-label">Source CIDR</label><input type="text" class="form-input" id="masq-cidr" placeholder="192.168.1.0/24"></div>
        <div class="form-group"><label class="form-label">Description</label><input type="text" class="form-input" id="masq-desc" placeholder="LAN to WAN"></div>
      `,
      footer: `<button class="btn btn-secondary" onclick="document.querySelector('.modal-close')?.click()">Cancel</button><button class="btn btn-primary" data-modal-submit>Add</button>`,
      onSubmit: async () => {
        const modal = document.querySelector('.modal');
        if (!modal) return;
        const iface = (modal.querySelector('#masq-iface') as HTMLInputElement)?.value;
        const cidr = (modal.querySelector('#masq-cidr') as HTMLInputElement)?.value;
        if (!iface) { showToast('Interface required', 'error'); return; }
        const config = { ...this.state.config! };
        config.masquerade = [...(config.masquerade || []), { out_interface: iface, source_cidr: cidr || undefined }];
        try {
          await natApi.saveConfig(config);
          showToast('Masquerade rule added', 'success');
          closeModal();
          this.loadData();
        } catch { showToast('Failed to add rule', 'error'); }
      },
    });
  }

  private openAddPortForwardModal(): void {
    openModal({
      title: '+ Add Port Forward Rule',
      body: `
        <div class="form-group"><label class="form-label">In Interface</label><input type="text" class="form-input" id="pf-iface" placeholder="eth0"></div>
        <div class="grid-2">
          <div class="form-group"><label class="form-label">Protocol</label>
            <select class="form-select" id="pf-proto"><option value="tcp">TCP</option><option value="udp">UDP</option></select>
          </div>
          <div class="form-group"><label class="form-label">Destination Port</label><input type="text" class="form-input" id="pf-dport" placeholder="80"></div>
        </div>
        <div class="form-group"><label class="form-label">Forward To (IP:Port)</label><input type="text" class="form-input" id="pf-fwd" placeholder="192.168.1.100:8080"></div>
      `,
      footer: `<button class="btn btn-secondary" onclick="document.querySelector('.modal-close')?.click()">Cancel</button><button class="btn btn-primary" data-modal-submit>Add</button>`,
      onSubmit: async () => {
        const modal = document.querySelector('.modal');
        if (!modal) return;
        const config = { ...this.state.config! };
        config.port_forward = [...(config.port_forward || []), {
          in_interface: (modal.querySelector('#pf-iface') as HTMLInputElement)?.value || 'eth0',
          protocol: (modal.querySelector('#pf-proto') as HTMLSelectElement)?.value || 'tcp',
          dest_port: (modal.querySelector('#pf-dport') as HTMLInputElement)?.value || '',
          forward_to: (modal.querySelector('#pf-fwd') as HTMLInputElement)?.value || '',
        }];
        try {
          await natApi.saveConfig(config);
          showToast('Port forward rule added', 'success');
          closeModal();
          this.loadData();
        } catch { showToast('Failed to add rule', 'error'); }
      },
    });
  }

  private async deleteMasquerade(idx: number): Promise<void> {
    try {
      await natApi.deleteMasquerade(idx);
      showToast('Rule deleted', 'success');
      this.loadData();
    } catch { showToast('Failed to delete', 'error'); }
  }

  private async deletePortForward(idx: number): Promise<void> {
    try {
      await natApi.deletePortForward(idx);
      showToast('Rule deleted', 'success');
      this.loadData();
    } catch { showToast('Failed to delete', 'error'); }
  }

  render(): void {
    const { loading, error, activeTab } = this.state;

    if (loading) {
      this.element.innerHTML = `<div class="loading"><div class="spinner"></div> Loading...</div>`;
      return;
    }

    this.element.innerHTML = `
      <div class="page-header">
        <h1 class="page-title">NAT</h1>
        <div class="page-actions">
          <button id="add-rule-btn" class="btn btn-primary">+ Add Rule</button>
        </div>
      </div>

      <div class="card">
        <div class="tab-bar">
          <button class="tab-btn ${activeTab === 'masquerade' ? 'active' : ''}" data-tab="masquerade">Masquerade (SNAT)</button>
          <button class="tab-btn ${activeTab === 'port-forward' ? 'active' : ''}" data-tab="port-forward">Port Forward (DNAT)</button>
          <button class="tab-btn ${activeTab === 'static' ? 'active' : ''}" data-tab="static">1:1 NAT</button>
        </div>

        ${error ? `<p style="color: var(--color-danger); margin-bottom: var(--spacing-md);">${error}</p>` : ''}

        ${activeTab === 'masquerade' ? this.renderMasquerade() : ''}
        ${activeTab === 'port-forward' ? this.renderPortForward() : ''}
        ${activeTab === 'static' ? this.renderStatic() : ''}
      </div>
    `;

    this.$$<HTMLButtonElement>('.tab-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        this.setState({ activeTab: btn.dataset.tab as typeof activeTab, error: null });
      });
    });

    this.$<HTMLButtonElement>('#add-rule-btn')?.addEventListener('click', () => {
      if (activeTab === 'masquerade') this.openAddMasqueradeModal();
      else if (activeTab === 'port-forward') this.openAddPortForwardModal();
    });

    this.$$<HTMLButtonElement>('[data-delete-masq]').forEach(btn => {
      btn.addEventListener('click', () => this.deleteMasquerade(parseInt(btn.dataset.deleteMasq!)));
    });
    this.$$<HTMLButtonElement>('[data-delete-pf]').forEach(btn => {
      btn.addEventListener('click', () => this.deletePortForward(parseInt(btn.dataset.deletePf!)));
    });
  }

  private renderMasquerade(): string {
    const rules = this.state.config?.masquerade || [];
    return `
      <div class="table-container">
        <table class="table">
          <thead><tr><th>Out Interface</th><th>Source CIDR</th><th>Description</th><th>Enabled</th><th></th></tr></thead>
          <tbody>
            ${rules.length > 0 ? rules.map((r: MasqueradeRule, idx: number) => `
              <tr>
                <td class="mono">${r.out_interface}</td>
                <td class="mono">${r.source_cidr || 'any'}</td>
                <td>—</td>
                <td><label class="toggle"><input type="checkbox" checked disabled><span class="toggle-track"></span></label></td>
                <td><div class="actions">
                  <button class="btn-icon" title="Edit">✎</button>
                  <button class="btn-icon danger" title="Delete" data-delete-masq="${idx}">🗑</button>
                </div></td>
              </tr>
            `).join('') : '<tr><td colspan="5" style="color: var(--color-text-muted);">No masquerade rules</td></tr>'}
          </tbody>
        </table>
      </div>
    `;
  }

  private renderPortForward(): string {
    const rules = this.state.config?.port_forward || [];
    return `
      <div class="table-container">
        <table class="table">
          <thead><tr><th>In Interface</th><th>Protocol</th><th>Dest Port</th><th>Forward To</th><th>Enabled</th><th></th></tr></thead>
          <tbody>
            ${rules.length > 0 ? rules.map((r: PortForwardRule, idx: number) => `
              <tr>
                <td class="mono">${r.in_interface}</td>
                <td style="text-transform: uppercase;">${r.protocol}</td>
                <td class="mono">${r.dest_port}</td>
                <td class="mono">${r.forward_to}</td>
                <td><label class="toggle"><input type="checkbox" checked disabled><span class="toggle-track"></span></label></td>
                <td><div class="actions">
                  <button class="btn-icon" title="Edit">✎</button>
                  <button class="btn-icon danger" title="Delete" data-delete-pf="${idx}">🗑</button>
                </div></td>
              </tr>
            `).join('') : '<tr><td colspan="6" style="color: var(--color-text-muted);">No port forward rules</td></tr>'}
          </tbody>
        </table>
      </div>
    `;
  }

  private renderStatic(): string {
    return `
      <div style="padding: var(--spacing-xl); text-align: center; color: var(--color-text-muted);">
        <p>1:1 NAT (Static SNAT) rules can be configured here.</p>
        <p style="margin-top: var(--spacing-sm);">Use the API to manage static SNAT rules.</p>
      </div>
    `;
  }
}
