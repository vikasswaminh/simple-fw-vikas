import { Component } from '@components/component';
import { systemApi, configApi, toolsApi, authApi } from '@api/endpoints';
import { showToast } from '@components/toast';

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
          <div class="form-group"><label class="form-label">Hostname</label><input type="text" name="hostname" class="form-input" value="${s?.hostname || ''}"></div>
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
                ${Object.entries(ntp).map(([k, v]) => `<tr><td style="font-weight: 500;">${k}</td><td>${v}</td></tr>`).join('')}
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
          <button class="btn btn-primary">Download Backup</button>
        </div>
        <div>
          <h4 style="margin-bottom: var(--spacing-md);">Import</h4>
          <div style="display: flex; gap: var(--spacing-sm);">
            <input type="file" accept=".json,.yaml,.yml" class="form-input">
            <button class="btn btn-secondary">Import</button>
          </div>
        </div>
      </div>
      <h4 style="margin: var(--spacing-lg) 0 var(--spacing-md);">Available Backups</h4>
      <div class="table-container">
        <table class="table">
          <thead><tr><th>Name</th><th>Size</th><th></th></tr></thead>
          <tbody>
            ${backups.map(b => `
              <tr><td>${b.name}</td><td>${this.fmtBytes(b.size)}</td>
              <td><button class="btn btn-secondary btn-sm">Restore</button></td></tr>
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
            <button class="btn btn-danger">Reboot</button>
          </div>
        </div>
        <div class="card" style="border-color: var(--color-danger);">
          <div style="display: flex; justify-content: space-between; align-items: center;">
            <div><strong>Factory Reset</strong><p style="color: var(--color-text-secondary); font-size: var(--font-size-sm);">Cannot be undone.</p></div>
            <button class="btn btn-danger">Reset</button>
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
