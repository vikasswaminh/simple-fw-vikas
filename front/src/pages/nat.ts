import { Component } from '@components/component';
import { natApi } from '@api/endpoints';
import { openModal, closeModal } from '@components/modal';
import { showToast } from '@components/toast';
import { escapeHtml } from '@utils';
import type { NatConfig, MasqueradeRule, PortForwardRule, SnatRule } from '@schemas';

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

  private openMasqueradeModal(idx?: number): void {
    const isEdit = typeof idx === 'number';
    const existing = isEdit ? this.state.config?.masquerade[idx] : undefined;

    openModal({
      title: isEdit ? '✎ Edit Masquerade Rule' : '+ Add Masquerade Rule',
      body: `
        <div class="form-group"><label class="form-label">Out Interface</label><input type="text" class="form-input" id="masq-iface" placeholder="eth0" value="${escapeHtml(existing?.out_interface ?? '')}"></div>
        <div class="form-group"><label class="form-label">Source CIDR</label><input type="text" class="form-input" id="masq-cidr" placeholder="192.168.1.0/24" value="${escapeHtml(existing?.source_cidr ?? '')}"></div>
      `,
      footer: `<button class="btn btn-secondary" data-modal-close>Cancel</button><button class="btn btn-primary" data-modal-submit>${isEdit ? 'Save Changes' : 'Add'}</button>`,
      onSubmit: async () => {
        const modal = document.querySelector('.modal');
        if (!modal) return;
        const iface = (modal.querySelector('#masq-iface') as HTMLInputElement)?.value;
        const cidr = (modal.querySelector('#masq-cidr') as HTMLInputElement)?.value;
        if (!iface) { showToast('Interface required', 'error'); return; }
        const config = { ...this.state.config! };
        const rule: MasqueradeRule = { out_interface: iface, source_cidr: cidr || '' };
        const masq = [...(config.masquerade || [])];
        if (isEdit) masq[idx] = rule; else masq.push(rule);
        config.masquerade = masq;
        try {
          await natApi.saveConfig(config);
          showToast(isEdit ? 'Masquerade rule updated' : 'Masquerade rule added', 'success');
          closeModal();
          this.loadData();
        } catch { showToast(isEdit ? 'Failed to update rule' : 'Failed to add rule', 'error'); }
      },
    });
  }

  private openPortForwardModal(idx?: number): void {
    const isEdit = typeof idx === 'number';
    const existing = isEdit ? this.state.config?.port_forward[idx] : undefined;
    const sel = (want: string, have: string | undefined) => (have === want ? 'selected' : '');
    const proto = existing?.protocol ?? 'tcp';

    openModal({
      title: isEdit ? '✎ Edit Port Forward Rule' : '+ Add Port Forward Rule',
      body: `
        <div class="form-group"><label class="form-label">In Interface</label><input type="text" class="form-input" id="pf-iface" placeholder="eth0" value="${escapeHtml(existing?.in_interface ?? '')}"></div>
        <div class="grid-2">
          <div class="form-group"><label class="form-label">Protocol</label>
            <select class="form-select" id="pf-proto">
              <option value="tcp" ${sel('tcp', proto)}>TCP</option>
              <option value="udp" ${sel('udp', proto)}>UDP</option>
            </select>
          </div>
          <div class="form-group"><label class="form-label">Destination Port</label><input type="text" class="form-input" id="pf-dport" placeholder="80" value="${existing?.dest_port != null ? escapeHtml(String(existing.dest_port)) : ''}"></div>
        </div>
        <div class="form-group"><label class="form-label">Forward To (IP:Port)</label><input type="text" class="form-input" id="pf-fwd" placeholder="192.168.1.100:8080" value="${escapeHtml(existing?.forward_to ?? '')}"></div>
      `,
      footer: `<button class="btn btn-secondary" data-modal-close>Cancel</button><button class="btn btn-primary" data-modal-submit>${isEdit ? 'Save Changes' : 'Add'}</button>`,
      onSubmit: async () => {
        const modal = document.querySelector('.modal');
        if (!modal) return;
        const config = { ...this.state.config! };
        const rule = {
          in_interface: (modal.querySelector('#pf-iface') as HTMLInputElement)?.value || 'eth0',
          protocol: (modal.querySelector('#pf-proto') as HTMLSelectElement)?.value || 'tcp',
          dest_port: (modal.querySelector('#pf-dport') as HTMLInputElement)?.value || '',
          forward_to: (modal.querySelector('#pf-fwd') as HTMLInputElement)?.value || '',
        } as unknown as PortForwardRule;
        const pf = [...(config.port_forward || [])];
        if (isEdit) pf[idx] = rule; else pf.push(rule);
        config.port_forward = pf;
        try {
          await natApi.saveConfig(config);
          showToast(isEdit ? 'Port forward updated' : 'Port forward rule added', 'success');
          closeModal();
          this.loadData();
        } catch { showToast(isEdit ? 'Failed to update rule' : 'Failed to add rule', 'error'); }
      },
    });
  }

  private async deleteMasquerade(idx: number): Promise<void> {
    try {
      // Backend indexes are 1-based for delete (matches deleteSnat).
      await natApi.deleteMasquerade(idx + 1);
      showToast('Rule deleted', 'success');
      this.loadData();
    } catch { showToast('Failed to delete', 'error'); }
  }

  private async deletePortForward(idx: number): Promise<void> {
    try {
      await natApi.deletePortForward(idx + 1);
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
      if (activeTab === 'masquerade') this.openMasqueradeModal();
      else if (activeTab === 'port-forward') this.openPortForwardModal();
      else if (activeTab === 'static') this.openSnatModal();
    });

    this.$$<HTMLButtonElement>('[data-delete-masq]').forEach(btn => {
      btn.addEventListener('click', () => this.deleteMasquerade(parseInt(btn.dataset.deleteMasq!)));
    });
    this.$$<HTMLButtonElement>('[data-delete-pf]').forEach(btn => {
      btn.addEventListener('click', () => this.deletePortForward(parseInt(btn.dataset.deletePf!)));
    });
    this.$$<HTMLButtonElement>('[data-edit-masq]').forEach(btn => {
      btn.addEventListener('click', () => this.openMasqueradeModal(parseInt(btn.dataset.editMasq!)));
    });
    this.$$<HTMLButtonElement>('[data-edit-pf]').forEach(btn => {
      btn.addEventListener('click', () => this.openPortForwardModal(parseInt(btn.dataset.editPf!)));
    });
    this.$$<HTMLButtonElement>('[data-delete-snat]').forEach(btn => {
      btn.addEventListener('click', () => this.deleteSnat(parseInt(btn.dataset.deleteSnat!)));
    });
    this.$$<HTMLButtonElement>('[data-edit-snat]').forEach(btn => {
      btn.addEventListener('click', () => this.openSnatModal(parseInt(btn.dataset.editSnat!)));
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
                <td class="mono">${escapeHtml(r.out_interface)}</td>
                <td class="mono">${escapeHtml(r.source_cidr || 'any')}</td>
                <td>—</td>
                <td><label class="toggle"><input type="checkbox" checked disabled><span class="toggle-track"></span></label></td>
                <td><div class="actions">
                  <button class="btn-icon" title="Edit" data-edit-masq="${idx}">✎</button>
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
                <td class="mono">${escapeHtml(r.in_interface)}</td>
                <td style="text-transform: uppercase;">${escapeHtml(r.protocol)}</td>
                <td class="mono">${escapeHtml(String(r.dest_port))}</td>
                <td class="mono">${escapeHtml(r.forward_to)}</td>
                <td><label class="toggle"><input type="checkbox" checked disabled><span class="toggle-track"></span></label></td>
                <td><div class="actions">
                  <button class="btn-icon" title="Edit" data-edit-pf="${idx}">✎</button>
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
    const rules = this.state.config?.snat || [];
    return `
      <div class="table-container">
        <table class="table">
          <thead><tr><th>Source CIDR</th><th>Translated To</th><th>Out Interface</th><th>Enabled</th><th></th></tr></thead>
          <tbody>
            ${rules.length > 0 ? rules.map((r: SnatRule, idx: number) => `
              <tr>
                <td class="mono">${escapeHtml(r.source_cidr)}</td>
                <td class="mono">${escapeHtml(r.to_address)}</td>
                <td class="mono">${escapeHtml(r.out_interface ?? '') || '—'}</td>
                <td><label class="toggle"><input type="checkbox" checked disabled><span class="toggle-track"></span></label></td>
                <td><div class="actions">
                  <button class="btn-icon" title="Edit" data-edit-snat="${idx}">✎</button>
                  <button class="btn-icon danger" title="Delete" data-delete-snat="${idx}">🗑</button>
                </div></td>
              </tr>
            `).join('') : '<tr><td colspan="5" style="color: var(--color-text-muted);">No static SNAT rules</td></tr>'}
          </tbody>
        </table>
      </div>
    `;
  }

  private openSnatModal(idx?: number): void {
    const isEdit = typeof idx === 'number';
    const existing = isEdit ? this.state.config?.snat[idx] : undefined;

    openModal({
      title: isEdit ? '✎ Edit 1:1 NAT Rule' : '+ Add 1:1 NAT Rule',
      body: `
        <div class="form-group"><label class="form-label">Source CIDR</label><input type="text" class="form-input" id="snat-src" placeholder="10.10.0.0/24" value="${escapeHtml(existing?.source_cidr ?? '')}"></div>
        <div class="form-group"><label class="form-label">Translated Source Address</label><input type="text" class="form-input" id="snat-to" placeholder="203.0.113.5" value="${escapeHtml(existing?.to_address ?? '')}"></div>
        <div class="form-group"><label class="form-label">Out Interface (optional)</label><input type="text" class="form-input" id="snat-oif" placeholder="eth0" value="${escapeHtml(existing?.out_interface ?? '')}"></div>
      `,
      footer: `<button class="btn btn-secondary" data-modal-close>Cancel</button><button class="btn btn-primary" data-modal-submit>${isEdit ? 'Save Changes' : 'Add'}</button>`,
      onSubmit: async () => {
        const modal = document.querySelector('.modal');
        if (!modal) return;
        const src = (modal.querySelector('#snat-src') as HTMLInputElement)?.value.trim();
        const to = (modal.querySelector('#snat-to') as HTMLInputElement)?.value.trim();
        const oif = (modal.querySelector('#snat-oif') as HTMLInputElement)?.value.trim();
        if (!src || !to) { showToast('Source CIDR and translated address required', 'error'); return; }

        const rule: SnatRule = { source_cidr: src, to_address: to, out_interface: oif || undefined };
        const config = { ...this.state.config! };
        const snat = [...(config.snat || [])];
        if (isEdit) snat[idx] = rule; else snat.push(rule);
        config.snat = snat;

        try {
          await natApi.saveConfig(config);
          showToast(isEdit ? '1:1 NAT rule updated' : '1:1 NAT rule added', 'success');
          closeModal();
          this.loadData();
        } catch { showToast(isEdit ? 'Failed to update rule' : 'Failed to add rule', 'error'); }
      },
    });
  }

  private async deleteSnat(idx: number): Promise<void> {
    try {
      // Backend indexes are 1-based for delete.
      await natApi.deleteSnat(idx + 1);
      showToast('Rule deleted', 'success');
      this.loadData();
    } catch { showToast('Failed to delete', 'error'); }
  }
}
