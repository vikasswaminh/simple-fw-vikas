import { Component } from '@components/component';
import { systemApi, configApi, toolsApi, authApi } from '@api/endpoints';
import { showToast } from '@components/toast';
import { openModal, closeModal } from '@components/modal';
import { escapeHtml } from '@utils';

export class SettingsPage extends Component<{
  settings: Record<string, unknown> | null;
  backups: Array<{ name: string; size: number }>;
  ntpStatus: Record<string, string> | null;
  loading: boolean;
  error: string | null;
  activeTab: 'general' | 'dns' | 'ntp' | 'backup' | 'admin' | 'syslog' | 'system';
}> {
  constructor(element: HTMLElement | string) {
    super(element);
    this.state = {
      settings: null, backups: [], ntpStatus: null,
      loading: true, error: null, activeTab: 'general',
    };
  }

  async init(): Promise<void> {
    await this.loadData();
  }

  private async loadData(): Promise<void> {
    try {
      const [settings, backups] = await Promise.all([
        systemApi.getSettings(), configApi.getBackups(),
      ]);
      this.setState({ settings, backups, loading: false });
    } catch (error) {
      this.setState({ error: error instanceof Error ? error.message : 'Failed to load', loading: false });
    }
  }

  private async loadNtp(): Promise<void> {
    try {
      const ntpStatus = await toolsApi.getNtpStatus() as Record<string, string>;
      this.setState({ ntpStatus });
    } catch { /* ignore */ }
  }

  render(): void {
    const { loading, error, activeTab } = this.state;

    if (loading) {
      this.element.innerHTML = `<div class="loading"><div class="spinner"></div> Loading...</div>`;
      return;
    }

    this.element.innerHTML = `
      <div class="page-header">
        <h1 class="page-title">Settings</h1>
      </div>

      <div class="card">
        <div class="tab-bar" style="flex-wrap: wrap;">
          ${['general', 'dns', 'ntp', 'backup', 'admin', 'syslog', 'system'].map(t =>
            `<button class="tab-btn ${activeTab === t ? 'active' : ''}" data-tab="${t}">${this.tabLabel(t)}</button>`
          ).join('')}
        </div>

        ${error ? `<p style="color: var(--color-danger); margin-bottom: var(--spacing-md);">${error}</p>` : ''}

        ${activeTab === 'general' ? this.renderGeneral() : ''}
        ${activeTab === 'dns' ? this.renderDns() : ''}
        ${activeTab === 'ntp' ? this.renderNtp() : ''}
        ${activeTab === 'backup' ? this.renderBackup() : ''}
        ${activeTab === 'admin' ? this.renderAdmin() : ''}
        ${activeTab === 'syslog' ? this.renderSyslog() : ''}
        ${activeTab === 'system' ? this.renderSystem() : ''}
      </div>
    `;

    this.$$<HTMLButtonElement>('.tab-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        const tab = btn.dataset.tab as typeof activeTab;
        this.setState({ activeTab: tab, error: null });
        if (tab === 'ntp') this.loadNtp();
      });
    });

    // Form bindings
    if (activeTab === 'general') this.bindGeneralForm();
    if (activeTab === 'admin') this.bindAdminForm();
    if (activeTab === 'backup') this.bindBackupTab();
    if (activeTab === 'dns') this.bindDnsTab();
    if (activeTab === 'system') this.bindSystemTab();
  }

  private bindBackupTab(): void {
    this.$<HTMLButtonElement>('#download-backup-btn')?.addEventListener('click', () => this.downloadBackup());
    this.$<HTMLButtonElement>('#import-backup-btn')?.addEventListener('click', () => this.importBackup());
    this.$$<HTMLButtonElement>('[data-restore]').forEach(btn => {
      btn.addEventListener('click', () => this.openRestoreModal(btn.dataset.restore!));
    });
  }

  private async downloadBackup(): Promise<void> {
    try {
      const data = await configApi.export();
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      const stamp = new Date().toISOString().replace(/[:.]/g, '-');
      a.href = url;
      a.download = `quickfw-backup-${stamp}.json`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      showToast('Backup downloaded', 'success');
    } catch { showToast('Failed to export backup', 'error'); }
  }

  private importBackup(): void {
    const input = this.$<HTMLInputElement>('#import-file-input');
    const file = input?.files?.[0];
    if (!file) { showToast('Choose a backup file first', 'error'); return; }
    const reader = new FileReader();
    reader.onload = async () => {
      try {
        const parsed = JSON.parse(reader.result as string);
        await configApi.import(parsed);
        showToast('Backup imported', 'success');
        this.loadData();
      } catch { showToast('Failed to import backup (invalid JSON or server error)', 'error'); }
    };
    reader.onerror = () => showToast('Failed to read file', 'error');
    reader.readAsText(file);
  }

  private openRestoreModal(name: string): void {
    openModal({
      title: `Restore backup: ${name}`,
      body: `
        <p style="color: var(--color-text-secondary); margin-bottom: var(--spacing-md);">
          Restoring will overwrite the current configuration. Enter your admin password to confirm.
        </p>
        <div class="form-group"><label class="form-label">Admin Password</label><input type="password" class="form-input" id="restore-pw"></div>
      `,
      footer: `<button class="btn btn-secondary" data-modal-close>Cancel</button><button class="btn btn-danger" data-modal-submit>Restore</button>`,
      onSubmit: async () => {
        const modal = document.querySelector('.modal');
        const pw = (modal?.querySelector('#restore-pw') as HTMLInputElement)?.value;
        if (!pw) { showToast('Password required', 'error'); return; }
        try {
          await configApi.restore(name, pw);
          showToast('Configuration restored', 'success');
          closeModal();
        } catch { showToast('Restore failed', 'error'); }
      },
    });
  }

  private bindDnsTab(): void {
    this.$<HTMLButtonElement>('#load-dns-btn')?.addEventListener('click', () => this.openDnsOverridesModal());
  }

  private async openDnsOverridesModal(): Promise<void> {
    try {
      const entries = await toolsApi.getDnsLocal();
      openModal({
        title: 'DNS Overrides',
        size: 'lg',
        body: `
          <p style="margin-bottom: var(--spacing-md); color: var(--color-text-secondary); font-size: var(--font-size-sm);">
            Hostname-to-IP overrides served by the local DNS resolver.
          </p>
          <div class="table-container">
            <table class="table">
              <thead><tr><th>Hostname</th><th>IP</th></tr></thead>
              <tbody>
                ${entries.length ? entries.map(e => `<tr><td class="mono">${escapeHtml(e.hostname)}</td><td class="mono">${escapeHtml(e.ip)}</td></tr>`).join('') : '<tr><td colspan="2" style="color: var(--color-text-muted);">No entries</td></tr>'}
              </tbody>
            </table>
          </div>
          <p style="margin-top: var(--spacing-md); color: var(--color-text-muted); font-size: var(--font-size-xs);">
            Manage entries on the Network → DNS Settings page.
          </p>
        `,
        footer: '<button class="btn btn-secondary" data-modal-submit>Close</button>',
        onSubmit: () => closeModal(),
      });
    } catch { showToast('Failed to load DNS overrides', 'error'); }
  }

  private bindSystemTab(): void {
    this.$<HTMLButtonElement>('#reboot-btn')?.addEventListener('click', () => this.openConfirmModal({
      title: 'Reboot System',
      message: 'The appliance will restart and management traffic will be interrupted for ~60 seconds.',
      confirmLabel: 'Reboot',
      onConfirm: (pw) => systemApi.reboot(pw),
      successMsg: 'Rebooting…',
      failMsg: 'Reboot failed',
    }));
    this.$<HTMLButtonElement>('#factory-reset-btn')?.addEventListener('click', () => this.openConfirmModal({
      title: 'Factory Reset',
      message: 'This wipes firewall, NAT, routing, roles, and settings — then reboots. Admin password is preserved. This cannot be undone.',
      confirmLabel: 'Factory Reset',
      onConfirm: (pw) => systemApi.factoryReset(pw),
      successMsg: 'Factory reset applied — rebooting',
      failMsg: 'Factory reset failed',
    }));
  }

  private openConfirmModal(opts: {
    title: string;
    message: string;
    confirmLabel: string;
    onConfirm: (password: string) => Promise<unknown>;
    successMsg: string;
    failMsg: string;
  }): void {
    openModal({
      title: opts.title,
      body: `
        <p style="color: var(--color-text-secondary); margin-bottom: var(--spacing-md);">${escapeHtml(opts.message)}</p>
        <div class="form-group"><label class="form-label">Admin Password</label><input type="password" class="form-input" id="confirm-pw"></div>
      `,
      footer: `<button class="btn btn-secondary" data-modal-close>Cancel</button><button class="btn btn-danger" data-modal-submit>${escapeHtml(opts.confirmLabel)}</button>`,
      onSubmit: async () => {
        const modal = document.querySelector('.modal');
        const pw = (modal?.querySelector('#confirm-pw') as HTMLInputElement)?.value;
        if (!pw) { showToast('Password required', 'error'); return; }
        try {
          await opts.onConfirm(pw);
          showToast(opts.successMsg, 'success');
          closeModal();
        } catch { showToast(opts.failMsg, 'error'); }
      },
    });
  }

  private tabLabel(t: string): string {
    const map: Record<string, string> = {
      general: 'General', dns: 'DNS', ntp: 'NTP', backup: 'Backup',
      admin: 'Admin & Users', syslog: 'Syslog', system: 'System',
    };
    return map[t] || t;
  }

  private renderGeneral(): string {
    const s = this.state.settings;
    return `
      <div style="max-width: 500px;">
        <h4 style="margin-bottom: var(--spacing-md);">General</h4>
        <form id="general-form">
          <div class="form-group"><label class="form-label">Hostname</label><input type="text" name="hostname" class="form-input" value="${escapeHtml(String(s?.hostname || ''))}"></div>
          <div class="form-group"><label class="form-label">Timezone</label>
            <select name="timezone" class="form-select">
              ${['UTC','America/New_York','America/Chicago','America/Denver','America/Los_Angeles','Europe/London','Europe/Berlin','Asia/Tokyo','Asia/Kolkata','Australia/Sydney'].map(tz =>
                `<option value="${tz}" ${s?.timezone === tz ? 'selected' : ''}>${tz}</option>`
              ).join('')}
            </select>
          </div>
          <h4 style="margin: var(--spacing-lg) 0 var(--spacing-md);">SSH Access</h4>
          <div style="display: flex; align-items: center; gap: var(--spacing-md); margin-bottom: var(--spacing-md);">
            <label class="toggle"><input type="checkbox" checked><span class="toggle-track"></span></label><span>Enable SSH</span>
          </div>
          <div class="form-group"><label class="form-label">SSH Port</label><input type="number" class="form-input" value="22" style="width: 100px;"></div>
          <h4 style="margin: var(--spacing-lg) 0 var(--spacing-md);">Web UI</h4>
          <div class="grid-2">
            <div class="form-group"><label class="form-label">HTTPS Port</label><input type="number" class="form-input" value="443"></div>
            <div class="form-group"><label class="form-label">Session Timeout (min)</label><input type="number" class="form-input" value="30"></div>
          </div>
          <button type="submit" class="btn btn-primary" style="margin-top: var(--spacing-md);">💾 Save All</button>
        </form>
      </div>
    `;
  }

  private bindGeneralForm(): void {
    this.$<HTMLFormElement>('#general-form')?.addEventListener('submit', async (e) => {
      e.preventDefault();
      const fd = new FormData(e.target as HTMLFormElement);
      try {
        await systemApi.saveSettings({ hostname: fd.get('hostname') as string, timezone: fd.get('timezone') as string } as Record<string, unknown>);
        showToast('Settings saved', 'success');
      } catch { showToast('Failed to save', 'error'); }
    });
  }

  private renderDns(): string {
    return `
      <div style="max-width: 500px;">
        <h4 style="margin-bottom: var(--spacing-md);">DNS Settings</h4>
        <p style="color: var(--color-text-secondary); font-size: var(--font-size-sm); margin-bottom: var(--spacing-md);">
          Configure DNS resolver and local overrides. Managed via dnsmasq.
        </p>
        <button class="btn btn-secondary" id="load-dns-btn">Load DNS Overrides</button>
      </div>
    `;
  }

  private renderNtp(): string {
    const ntp = this.state.ntpStatus;
    return `
      <div>
        <div style="display: flex; justify-content: space-between; margin-bottom: var(--spacing-md);">
          <h4>NTP / Time Synchronization</h4>
          <button class="btn btn-secondary btn-sm" id="refresh-ntp">↻ Refresh</button>
        </div>
        ${ntp ? `
          <div class="table-container">
            <table class="table">
              <thead><tr><th>Property</th><th>Value</th></tr></thead>
              <tbody>
                ${Object.entries(ntp).map(([k, v]) => `<tr><td style="font-weight: 500;">${escapeHtml(k)}</td><td>${escapeHtml(v as string)}</td></tr>`).join('')}
              </tbody>
            </table>
          </div>
        ` : '<p style="color: var(--color-text-muted);">Click Refresh to load NTP status.</p>'}
      </div>
    `;
  }

  private renderBackup(): string {
    const backups = this.state.backups;
    return `
      <div class="grid-2">
        <div>
          <h4 style="margin-bottom: var(--spacing-md);">Export</h4>
          <button class="btn btn-primary" id="download-backup-btn">Download Backup</button>
        </div>
        <div>
          <h4 style="margin-bottom: var(--spacing-md);">Import</h4>
          <div style="display: flex; gap: var(--spacing-sm);">
            <input type="file" accept=".json,.yaml,.yml" class="form-input" id="import-file-input">
            <button class="btn btn-secondary" id="import-backup-btn">Import</button>
          </div>
        </div>
      </div>
      <h4 style="margin: var(--spacing-lg) 0 var(--spacing-md);">Available Backups</h4>
      <div class="table-container">
        <table class="table">
          <thead><tr><th>Name</th><th>Size</th><th></th></tr></thead>
          <tbody>
            ${backups.map(b => `
              <tr><td>${escapeHtml(b.name)}</td><td>${this.fmtBytes(b.size)}</td>
              <td><button class="btn btn-secondary btn-sm" data-restore="${escapeHtml(b.name)}">Restore</button></td></tr>
            `).join('') || '<tr><td colspan="3" style="color: var(--color-text-muted);">No backups</td></tr>'}
          </tbody>
        </table>
      </div>
    `;
  }

  private renderAdmin(): string {
    return `
      <div style="max-width: 400px;">
        <h4 style="margin-bottom: var(--spacing-md);">Change Admin Password</h4>
        <form id="password-form">
          <div class="form-group"><label class="form-label">Current Password</label><input type="password" name="current" class="form-input" required></div>
          <div class="form-group"><label class="form-label">New Password</label><input type="password" name="new" class="form-input" required minlength="8"></div>
          <div class="form-group"><label class="form-label">Confirm</label><input type="password" name="confirm" class="form-input" required minlength="8"></div>
          <p style="color: var(--color-text-muted); font-size: var(--font-size-xs); margin-bottom: var(--spacing-md);">Min 8 characters.</p>
          <button type="submit" class="btn btn-primary">Change Password</button>
        </form>
      </div>
    `;
  }

  private bindAdminForm(): void {
    this.$<HTMLFormElement>('#password-form')?.addEventListener('submit', async (e) => {
      e.preventDefault();
      const fd = new FormData(e.target as HTMLFormElement);
      const newPw = fd.get('new') as string;
      if (newPw !== fd.get('confirm')) { showToast('Passwords do not match', 'error'); return; }
      try {
        await authApi.changePassword({ current_password: fd.get('current') as string, new_password: newPw });
        showToast('Password changed', 'success');
        (e.target as HTMLFormElement).reset();
      } catch { showToast('Failed to change password', 'error'); }
    });
  }

  private renderSyslog(): string {
    return `
      <div style="max-width: 500px;">
        <h4 style="margin-bottom: var(--spacing-md);">Syslog Forwarding</h4>
        <p style="color: var(--color-text-secondary); font-size: var(--font-size-sm); margin-bottom: var(--spacing-md);">
          Configure remote syslog server for log forwarding.
        </p>
        <div class="form-group"><label class="form-label">Syslog Server</label><input type="text" class="form-input" placeholder="192.168.1.10"></div>
        <div class="form-group"><label class="form-label">Port</label><input type="number" class="form-input" value="514" style="width: 100px;"></div>
        <div class="form-group"><label class="form-label">Protocol</label>
          <select class="form-select" style="width: 120px;"><option>UDP</option><option>TCP</option></select>
        </div>
        <button class="btn btn-primary">Save</button>
      </div>
    `;
  }

  private renderSystem(): string {
    return `
      <div>
        <h4 style="margin-bottom: var(--spacing-md); color: var(--color-danger);">Danger Zone</h4>
        <div class="card" style="border-color: var(--color-danger); margin-bottom: var(--spacing-md);">
          <div style="display: flex; justify-content: space-between; align-items: center;">
            <div><strong>Reboot System</strong><p style="color: var(--color-text-secondary); font-size: var(--font-size-sm);">Temporarily interrupts connectivity.</p></div>
            <button class="btn btn-danger" id="reboot-btn">Reboot</button>
          </div>
        </div>
        <div class="card" style="border-color: var(--color-danger);">
          <div style="display: flex; justify-content: space-between; align-items: center;">
            <div><strong>Factory Reset</strong><p style="color: var(--color-text-secondary); font-size: var(--font-size-sm);">Cannot be undone.</p></div>
            <button class="btn btn-danger" id="factory-reset-btn">Reset</button>
          </div>
        </div>
      </div>
    `;
  }

  private fmtBytes(b: number): string {
    if (b === 0) return '0 B';
    const u = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(b) / Math.log(1024));
    return `${(b / Math.pow(1024, i)).toFixed(1)} ${u[i]}`;
  }
}
