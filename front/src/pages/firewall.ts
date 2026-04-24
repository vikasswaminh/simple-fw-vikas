import { Component } from '@components/component';
import { firewallApi } from '@api/endpoints';
import { openModal, closeModal } from '@components/modal';
import { showToast } from '@components/toast';
import { formatBytes, escapeHtml } from '@utils';
import type { FirewallRule, FirewallConfig, FirewallGroups, RuleCounter, AddressGroup, PortGroup, NftPreview } from '@schemas';

export class FirewallPage extends Component<{
  config: FirewallConfig | null;
  counters: RuleCounter[];
  groups: FirewallGroups | null;
  loading: boolean;
  error: string | null;
  search: string;
}> {
  constructor(element: HTMLElement | string) {
    super(element);
    this.state = {
      config: null,
      counters: [],
      groups: null,
      loading: true,
      error: null,
      search: '',
    };
  }

  async init(): Promise<void> {
    await this.loadData();
  }

  private async loadData(): Promise<void> {
    try {
      const [config, counterData] = await Promise.all([
        firewallApi.getConfig(),
        firewallApi.getCounters().catch(() => ({ counters: [] })),
      ]);
      this.setState({
        config,
        counters: (counterData as { counters: RuleCounter[] }).counters || [],
        loading: false,
      });
    } catch (error) {
      this.setState({ error: error instanceof Error ? error.message : 'Failed to load', loading: false });
    }
  }

  private getFilteredRules(): FirewallRule[] {
    const rules = this.state.config?.rules || [];
    const s = this.state.search.toLowerCase();
    if (!s) return rules;
    return rules.filter((r: FirewallRule) =>
      r.name.toLowerCase().includes(s) ||
      (r.src_ip || '').toLowerCase().includes(s) ||
      (r.dst_ip || '').toLowerCase().includes(s) ||
      r.protocol.toLowerCase().includes(s)
    );
  }

  private getCounter(ruleName: string): { packets: number; bytes: number } {
    const c = this.state.counters.find((c: RuleCounter) => c.comment === ruleName);
    return c ? { packets: c.packets, bytes: c.bytes } : { packets: 0, bytes: 0 };
  }

  private openRuleModal(idx?: number): void {
    const isEdit = typeof idx === 'number';
    const existing = isEdit ? this.state.config?.rules[idx] : undefined;
    // For select elements, `selected` attribute must match the rule's current value.
    const sel = (want: string, have: string | undefined) => (have === want ? 'selected' : '');
    const proto = existing?.protocol ?? 'any';
    const dir = existing?.direction ?? 'forward';
    const action = existing?.action ?? 'accept';

    openModal({
      title: isEdit ? '✎ Edit Firewall Rule' : '+ Add Firewall Rule',
      size: 'lg',
      body: `
        <div class="grid-2">
          <div class="form-group"><label class="form-label">Name</label><input type="text" class="form-input" id="rule-name" placeholder="Rule name" value="${escapeHtml(existing?.name ?? '')}"></div>
          <div class="form-group"><label class="form-label">Direction</label>
            <select class="form-select" id="rule-dir">
              <option value="forward" ${sel('forward', dir)}>Forward</option>
              <option value="input" ${sel('input', dir)}>Input</option>
              <option value="output" ${sel('output', dir)}>Output</option>
            </select>
          </div>
        </div>
        <div class="grid-2">
          <div class="form-group"><label class="form-label">Protocol</label>
            <select class="form-select" id="rule-proto">
              <option value="any" ${sel('any', proto)}>Any</option>
              <option value="tcp" ${sel('tcp', proto)}>TCP</option>
              <option value="udp" ${sel('udp', proto)}>UDP</option>
              <option value="icmp" ${sel('icmp', proto)}>ICMP</option>
              <option value="tcp+udp" ${sel('tcp+udp', proto)}>TCP+UDP</option>
            </select>
          </div>
          <div class="form-group"><label class="form-label">Action</label>
            <select class="form-select" id="rule-action">
              <option value="accept" ${sel('accept', action)}>Allow</option>
              <option value="drop" ${sel('drop', action)}>Deny</option>
              <option value="reject" ${sel('reject', action)}>Reject</option>
              <option value="log" ${sel('log', action)}>Log</option>
            </select>
          </div>
        </div>
        <div class="grid-2">
          <div class="form-group"><label class="form-label">Source IP</label><input type="text" class="form-input" id="rule-src" placeholder="any" value="${escapeHtml(existing?.src_ip ?? '')}"></div>
          <div class="form-group"><label class="form-label">Source Port</label><input type="text" class="form-input" id="rule-sport" placeholder="any" value="${escapeHtml(existing?.src_port ?? '')}"></div>
        </div>
        <div class="grid-2">
          <div class="form-group"><label class="form-label">Destination IP</label><input type="text" class="form-input" id="rule-dst" placeholder="any" value="${escapeHtml(existing?.dst_ip ?? '')}"></div>
          <div class="form-group"><label class="form-label">Destination Port</label><input type="text" class="form-input" id="rule-dport" placeholder="any" value="${escapeHtml(existing?.dst_port ?? '')}"></div>
        </div>
        <div class="form-group"><label class="form-label">Comment</label><input type="text" class="form-input" id="rule-comment" placeholder="Optional description" value="${escapeHtml(existing?.comment ?? '')}"></div>
        <div style="display: flex; align-items: center; gap: var(--spacing-md);">
          <label class="toggle"><input type="checkbox" id="rule-enabled" ${(existing?.enabled ?? true) ? 'checked' : ''}><span class="toggle-track"></span></label> <span style="font-size: var(--font-size-sm);">Enabled</span>
          <label class="toggle"><input type="checkbox" id="rule-log" ${existing?.log ? 'checked' : ''}><span class="toggle-track"></span></label> <span style="font-size: var(--font-size-sm);">Log</span>
        </div>
      `,
      footer: `
        <button class="btn btn-secondary" data-modal-close>Cancel</button>
        <button class="btn btn-primary" data-modal-submit>${isEdit ? 'Save Changes' : 'Add Rule'}</button>
      `,
      onSubmit: async () => {
        const modal = document.querySelector('.modal');
        if (!modal) return;
        const getValue = (id: string) => (modal.querySelector(`#${id}`) as HTMLInputElement)?.value || '';
        const getChecked = (id: string) => (modal.querySelector(`#${id}`) as HTMLInputElement)?.checked ?? false;

        const newRule: FirewallRule = {
          name: getValue('rule-name') || 'New Rule',
          direction: getValue('rule-dir') as FirewallRule['direction'],
          protocol: getValue('rule-proto') as FirewallRule['protocol'],
          action: getValue('rule-action') as FirewallRule['action'],
          src_ip: getValue('rule-src') || undefined,
          src_port: getValue('rule-sport') || undefined,
          dst_ip: getValue('rule-dst') || undefined,
          dst_port: getValue('rule-dport') || undefined,
          comment: getValue('rule-comment') || undefined,
          enabled: getChecked('rule-enabled'),
          log: getChecked('rule-log'),
          ipv6: existing?.ipv6 ?? false,
        };

        try {
          const rules = [...(this.state.config?.rules || [])];
          if (isEdit) {
            rules[idx] = newRule;
          } else {
            rules.push(newRule);
          }
          await firewallApi.saveConfig({ ...this.state.config!, rules });
          showToast(isEdit ? 'Rule updated' : 'Rule added successfully', 'success');
          closeModal();
          this.loadData();
        } catch {
          showToast(isEdit ? 'Failed to update rule' : 'Failed to add rule', 'error');
        }
      },
    });
  }

  private async toggleRule(idx: number, enabled: boolean): Promise<void> {
    const rules = [...(this.state.config?.rules || [])];
    if (!rules[idx]) return;
    rules[idx] = { ...rules[idx], enabled };
    try {
      await firewallApi.saveConfig({ ...this.state.config!, rules });
      showToast(`Rule ${enabled ? 'enabled' : 'disabled'}`, 'success');
      this.loadData();
    } catch {
      showToast('Failed to toggle rule', 'error');
      // Reload to restore the checkbox to its server-side state.
      this.loadData();
    }
  }

  private async openPreviewModal(): Promise<void> {
    if (!this.state.config) return;
    try {
      const preview: NftPreview = await firewallApi.preview(this.state.config);
      openModal({
        title: '◉ nftables Preview',
        size: 'lg',
        body: `
          <p style="color: var(--color-text-muted); margin-bottom: var(--spacing-sm);">
            Dry-run output for ${preview.rule_count} rule(s). This is what will be loaded on Apply.
          </p>
          <pre class="mono" style="background: var(--color-bg-subtle); padding: var(--spacing-md); border-radius: var(--radius-sm); max-height: 60vh; overflow: auto; white-space: pre-wrap; font-size: var(--font-size-sm);">${escapeHtml(preview.nft_script)}</pre>
        `,
        footer: '<button class="btn btn-secondary" data-modal-submit>Close</button>',
        onSubmit: () => closeModal(),
      });
    } catch {
      showToast('Failed to generate nft preview', 'error');
    }
  }

  private openAliasesModal(): void {
    firewallApi.getGroups().then(groups => {
      openModal({
        title: 'Aliases (Address & Port Groups)',
        size: 'lg',
        body: `
          <h4 style="margin-bottom: var(--spacing-sm);">Address Groups</h4>
          <div class="table-container" style="margin-bottom: var(--spacing-lg);">
            <table class="table">
              <thead><tr><th>Name</th><th>Addresses</th></tr></thead>
              <tbody>
                ${groups.address_groups?.length ? groups.address_groups.map((g: AddressGroup) => `
                  <tr><td><strong>${escapeHtml(g.name)}</strong></td><td class="mono">${g.addresses.map((a: string) => escapeHtml(a)).join(', ')}</td></tr>
                `).join('') : '<tr><td colspan="2" style="color: var(--color-text-muted);">None</td></tr>'}
              </tbody>
            </table>
          </div>
          <h4 style="margin-bottom: var(--spacing-sm);">Port Groups</h4>
          <div class="table-container">
            <table class="table">
              <thead><tr><th>Name</th><th>Ports</th></tr></thead>
              <tbody>
                ${groups.port_groups?.length ? groups.port_groups.map((g: PortGroup) => `
                  <tr><td><strong>${escapeHtml(g.name)}</strong></td><td class="mono">${g.ports.map((p: string) => escapeHtml(p)).join(', ')}</td></tr>
                `).join('') : '<tr><td colspan="2" style="color: var(--color-text-muted);">None</td></tr>'}
              </tbody>
            </table>
          </div>
        `,
        footer: '<button class="btn btn-secondary" data-modal-submit>Close</button>',
        onSubmit: () => closeModal(),
      });
    });
  }

  private async deleteRule(idx: number): Promise<void> {
    const rules = [...(this.state.config?.rules || [])];
    rules.splice(idx, 1);
    try {
      await firewallApi.saveConfig({ ...this.state.config!, rules });
      showToast('Rule deleted', 'success');
      this.loadData();
    } catch {
      showToast('Failed to delete rule', 'error');
    }
  }

  private async copyRule(idx: number): Promise<void> {
    const rules = [...(this.state.config?.rules || [])];
    const copy = { ...rules[idx], name: rules[idx].name + ' (copy)' };
    rules.splice(idx + 1, 0, copy);
    try {
      await firewallApi.saveConfig({ ...this.state.config!, rules });
      showToast('Rule duplicated', 'success');
      this.loadData();
    } catch {
      showToast('Failed to copy rule', 'error');
    }
  }

  render(): void {
    const { config, loading, error, search } = this.state;

    if (loading && !config) {
      this.element.innerHTML = `<div class="loading"><div class="spinner"></div> Loading...</div>`;
      return;
    }

    const rules = this.getFilteredRules();

    this.element.innerHTML = `
      <div class="page-header">
        <h1 class="page-title">Firewall Rules</h1>
        <div class="page-actions">
          <button id="aliases-btn" class="btn btn-secondary">◇ Aliases</button>
          <button id="preview-btn" class="btn btn-secondary">◉ Preview nft</button>
          <button id="add-rule-btn" class="btn btn-primary">+ Add Rule</button>
        </div>
      </div>

      <div class="card">
        <input type="text" class="form-input search-input" id="search-input" placeholder="Search rules by name, IP, or group..." value="${search}" style="margin-bottom: var(--spacing-md); max-width: 400px;">

        ${error ? `<p style="color: var(--color-danger); margin-bottom: var(--spacing-md);">${error}</p>` : ''}

        <div class="table-container">
          <table class="table">
            <thead>
              <tr>
                <th>#</th>
                <th>Name</th>
                <th>Dir</th>
                <th>Proto</th>
                <th>Source</th>
                <th>Src Port</th>
                <th>Destination</th>
                <th>Dst Port</th>
                <th>Action</th>
                <th>Packets</th>
                <th>Bytes</th>
                <th>Enabled</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              ${rules.length > 0 ? rules.map((rule: FirewallRule, idx: number) => {
                const c = this.getCounter(rule.name);
                return `
                <tr>
                  <td style="color: var(--color-text-muted);">${idx + 1}</td>
                  <td><strong>${escapeHtml(rule.name)}</strong></td>
                  <td>${escapeHtml(rule.direction)}</td>
                  <td style="text-transform: uppercase;">${escapeHtml(rule.protocol)}</td>
                  <td class="mono">${escapeHtml(rule.src_ip || 'any')}</td>
                  <td class="mono">${escapeHtml(rule.src_port || 'any')}</td>
                  <td class="mono">${escapeHtml(rule.dst_ip || 'any')}</td>
                  <td class="mono">${escapeHtml(rule.dst_port || 'any')}</td>
                  <td>
                    <span class="badge ${rule.action === 'accept' ? 'badge-success' : rule.action === 'drop' ? 'badge-danger' : rule.action === 'reject' ? 'badge-warning' : 'badge-info'} badge-sm">
                      ${escapeHtml(rule.action === 'accept' ? 'allow' : rule.action)}
                    </span>
                  </td>
                  <td class="mono">${c.packets.toLocaleString()}</td>
                  <td class="mono">${formatBytes(c.bytes)}</td>
                  <td>
                    <label class="toggle">
                      <input type="checkbox" ${rule.enabled ? 'checked' : ''} data-toggle-rule="${idx}">
                      <span class="toggle-track"></span>
                    </label>
                  </td>
                  <td>
                    <div class="actions">
                      <button class="btn-icon" title="Edit" data-edit-rule="${idx}">✎</button>
                      <button class="btn-icon" title="Copy" data-copy-rule="${idx}">❐</button>
                      <button class="btn-icon danger" title="Delete" data-delete-rule="${idx}">🗑</button>
                    </div>
                  </td>
                </tr>`;
              }).join('') : '<tr><td colspan="13" style="color: var(--color-text-muted);">No rules configured</td></tr>'}
            </tbody>
          </table>
        </div>
      </div>
    `;

    // Bind events
    this.$<HTMLButtonElement>('#add-rule-btn')?.addEventListener('click', () => this.openRuleModal());
    this.$<HTMLButtonElement>('#aliases-btn')?.addEventListener('click', () => this.openAliasesModal());
    this.$<HTMLButtonElement>('#preview-btn')?.addEventListener('click', () => this.openPreviewModal());
    this.$<HTMLInputElement>('#search-input')?.addEventListener('input', (e) => {
      this.setState({ search: (e.target as HTMLInputElement).value });
    });

    // Row actions
    this.$$<HTMLButtonElement>('[data-delete-rule]').forEach(btn => {
      btn.addEventListener('click', () => this.deleteRule(parseInt(btn.dataset.deleteRule!)));
    });
    this.$$<HTMLButtonElement>('[data-copy-rule]').forEach(btn => {
      btn.addEventListener('click', () => this.copyRule(parseInt(btn.dataset.copyRule!)));
    });
    this.$$<HTMLButtonElement>('[data-edit-rule]').forEach(btn => {
      btn.addEventListener('click', () => this.openRuleModal(parseInt(btn.dataset.editRule!)));
    });
    this.$$<HTMLInputElement>('[data-toggle-rule]').forEach(cb => {
      cb.addEventListener('change', () => this.toggleRule(parseInt(cb.dataset.toggleRule!), cb.checked));
    });
  }
}
