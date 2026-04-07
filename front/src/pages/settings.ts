import { Component } from '@components/component';
import { systemApi, configApi, toolsApi, authApi } from '@api/endpoints';

/**
 * Settings Page Component
 */
export class SettingsPage extends Component<{
  settings: Record<string, unknown> | null;
  backups: Array<{ name: string; size: number }>;
  ntpStatus: Record<string, string> | null;
  loading: boolean;
  error: string | null;
  success: string | null;
  activeTab: 'general' | 'backup' | 'account' | 'ntp' | 'system';
}> {
  constructor(element: HTMLElement | string) {
    super(element);
    this.state = {
      settings: null,
      backups: [],
      ntpStatus: null,
      loading: true,
      error: null,
      success: null,
      activeTab: 'general',
    };
  }

  async init(): Promise<void> {
    await this.loadData();
  }

  private async loadData(): Promise<void> {
    try {
      const [settings, backups] = await Promise.all([
        systemApi.getSettings(),
        configApi.getBackups(),
      ]);
      this.setState({ settings, backups, loading: false });
    } catch (error) {
      console.error('Failed to load settings:', error);
      this.setState({
        error: error instanceof Error ? error.message : 'Failed to load settings',
        loading: false,
      });
    }
  }

  private async loadNtpStatus(): Promise<void> {
    try {
      const ntpStatus = await toolsApi.getNtpStatus() as Record<string, string>;
      this.setState({ ntpStatus });
    } catch (error) {
      console.error('Failed to load NTP status:', error);
      this.setState({ error: error instanceof Error ? error.message : 'Failed to load NTP status' });
    }
  }

  render(): void {
    const { settings, backups, loading, error, success, activeTab } = this.state;

    if (loading) {
      this.element.innerHTML = `
        <div class="loading">
          <div class="spinner"></div>
          <span>Loading settings...</span>
        </div>
      `;
      return;
    }

    this.element.innerHTML = `
      <div class="card">
        <div class="card-header">
          <h3 class="card-title">Settings</h3>
        </div>

        <div style="display: flex; gap: var(--spacing-sm); margin-bottom: var(--spacing-md); border-bottom: 1px solid var(--color-border); flex-wrap: wrap;">
          <button class="tab-btn ${activeTab === 'general' ? 'active' : ''}" data-tab="general">General</button>
          <button class="tab-btn ${activeTab === 'account' ? 'active' : ''}" data-tab="account">Account</button>
          <button class="tab-btn ${activeTab === 'ntp' ? 'active' : ''}" data-tab="ntp">NTP / Time</button>
          <button class="tab-btn ${activeTab === 'backup' ? 'active' : ''}" data-tab="backup">Backup & Restore</button>
          <button class="tab-btn ${activeTab === 'system' ? 'active' : ''}" data-tab="system">System</button>
        </div>

        ${error ? `<p style="color: var(--color-danger); margin-bottom: var(--spacing-md);">${error}</p>` : ''}
        ${success ? `<p style="color: var(--color-success); margin-bottom: var(--spacing-md);">${success}</p>` : ''}

        ${activeTab === 'general' ? this.renderGeneral(settings) : ''}
        ${activeTab === 'account' ? this.renderAccount() : ''}
        ${activeTab === 'ntp' ? this.renderNtp() : ''}
        ${activeTab === 'backup' ? this.renderBackup(backups) : ''}
        ${activeTab === 'system' ? this.renderSystem() : ''}
      </div>
    `;

    this.$$<HTMLButtonElement>('.tab-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        const tab = btn.dataset.tab as typeof activeTab;
        this.setState({ activeTab: tab, error: null, success: null });
        if (tab === 'ntp') this.loadNtpStatus();
      });
    });

    // Bind account form
    if (activeTab === 'account') {
      this.bindAccountEvents();
    }
  }

  private renderGeneral(settings: Record<string, unknown> | null): string {
    return `
      <form id="settings-form">
        <div class="form-group">
          <label class="form-label">Hostname</label>
          <input type="text" name="hostname" class="form-input" value="${settings?.hostname || ''}">
        </div>

        <div class="form-group">
          <label class="form-label">Timezone</label>
          <select name="timezone" class="form-select">
            <option value="UTC" ${settings?.timezone === 'UTC' ? 'selected' : ''}>UTC</option>
            <option value="America/New_York" ${settings?.timezone === 'America/New_York' ? 'selected' : ''}>America/New York</option>
            <option value="America/Chicago" ${settings?.timezone === 'America/Chicago' ? 'selected' : ''}>America/Chicago</option>
            <option value="America/Denver" ${settings?.timezone === 'America/Denver' ? 'selected' : ''}>America/Denver</option>
            <option value="America/Los_Angeles" ${settings?.timezone === 'America/Los_Angeles' ? 'selected' : ''}>America/Los Angeles</option>
            <option value="Europe/London" ${settings?.timezone === 'Europe/London' ? 'selected' : ''}>Europe/London</option>
            <option value="Europe/Berlin" ${settings?.timezone === 'Europe/Berlin' ? 'selected' : ''}>Europe/Berlin</option>
            <option value="Asia/Tokyo" ${settings?.timezone === 'Asia/Tokyo' ? 'selected' : ''}>Asia/Tokyo</option>
            <option value="Asia/Kolkata" ${settings?.timezone === 'Asia/Kolkata' ? 'selected' : ''}>Asia/Kolkata</option>
            <option value="Australia/Sydney" ${settings?.timezone === 'Australia/Sydney' ? 'selected' : ''}>Australia/Sydney</option>
          </select>
        </div>

        <div style="margin-top: var(--spacing-lg);">
          <button type="submit" class="btn btn-primary">Save Settings</button>
        </div>
      </form>
    `;
  }

  private renderAccount(): string {
    return `
      <div>
        <h4 style="margin-bottom: var(--spacing-md);">Change Admin Password</h4>
        <form id="password-form" style="max-width: 400px;">
          <div class="form-group">
            <label class="form-label">Current Password</label>
            <input type="password" name="current_password" class="form-input" required>
          </div>
          <div class="form-group">
            <label class="form-label">New Password</label>
            <input type="password" name="new_password" class="form-input" required minlength="8">
          </div>
          <div class="form-group">
            <label class="form-label">Confirm New Password</label>
            <input type="password" name="confirm_password" class="form-input" required minlength="8">
          </div>
          <p style="color: var(--color-text-secondary); font-size: var(--font-size-sm); margin-bottom: var(--spacing-md);">
            Password must be at least 8 characters.
          </p>
          <button type="submit" class="btn btn-primary">Change Password</button>
        </form>
      </div>
    `;
  }

  private bindAccountEvents(): void {
    const form = this.$<HTMLFormElement>('#password-form');
    form?.addEventListener('submit', async (e) => {
      e.preventDefault();
      const formData = new FormData(form);
      const currentPassword = formData.get('current_password') as string;
      const newPassword = formData.get('new_password') as string;
      const confirmPassword = formData.get('confirm_password') as string;

      if (newPassword !== confirmPassword) {
        this.setState({ error: 'New passwords do not match', success: null });
        return;
      }

      try {
        await authApi.changePassword({
          current_password: currentPassword,
          new_password: newPassword,
        });
        this.setState({ success: 'Password changed successfully', error: null });
        form.reset();
      } catch (error) {
        this.setState({
          error: error instanceof Error ? error.message : 'Failed to change password',
          success: null,
        });
      }
    });
  }

  private renderNtp(): string {
    const { ntpStatus } = this.state;
    return `
      <div>
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: var(--spacing-md);">
          <h4>NTP / Time Synchronization</h4>
          <button id="refresh-ntp" class="btn btn-secondary">Refresh</button>
        </div>

        ${ntpStatus ? `
          <div class="table-container">
            <table class="table">
              <thead>
                <tr>
                  <th>Property</th>
                  <th>Value</th>
                </tr>
              </thead>
              <tbody>
                ${Object.entries(ntpStatus).map(([key, value]) => `
                  <tr>
                    <td style="font-weight: 500;">${key}</td>
                    <td>${value}</td>
                  </tr>
                `).join('')}
              </tbody>
            </table>
          </div>
        ` : `
          <p style="color: var(--color-text-secondary);">Click Refresh to load NTP status.</p>
        `}
      </div>
    `;
  }

  private renderBackup(backups: Array<{ name: string; size: number }>): string {
    return `
      <div style="display: grid; gap: var(--spacing-lg);">
        <div>
          <h4 style="margin-bottom: var(--spacing-md);">Export Configuration</h4>
          <button id="export-btn" class="btn btn-primary">Download Backup</button>
        </div>

        <div style="border-top: 1px solid var(--color-border); padding-top: var(--spacing-lg);">
          <h4 style="margin-bottom: var(--spacing-md);">Import Configuration</h4>
          <div style="display: flex; gap: var(--spacing-md);">
            <input type="file" id="import-file" accept=".json,.yaml,.yml" class="form-input">
            <button id="import-btn" class="btn btn-secondary">Import</button>
          </div>
        </div>

        <div style="border-top: 1px solid var(--color-border); padding-top: var(--spacing-lg);">
          <h4 style="margin-bottom: var(--spacing-md);">Available Backups</h4>
          <div class="table-container">
            <table class="table">
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Size</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                ${backups.map(backup => `
                  <tr>
                    <td>${backup.name}</td>
                    <td>${this.formatBytes(backup.size)}</td>
                    <td>
                      <button class="btn btn-secondary btn-sm" data-restore="${backup.name}">Restore</button>
                    </td>
                  </tr>
                `).join('') || '<tr><td colspan="3">No backups available</td></tr>'}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    `;
  }

  private renderSystem(): string {
    return `
      <div style="display: grid; gap: var(--spacing-lg);">
        <div>
          <h4 style="margin-bottom: var(--spacing-md); color: var(--color-danger);">Danger Zone</h4>
          <p style="color: var(--color-text-secondary); margin-bottom: var(--spacing-md);">
            These actions are irreversible. Please proceed with caution.
          </p>

          <div style="display: grid; gap: var(--spacing-md);">
            <div class="card" style="border-color: var(--color-danger);">
              <div style="display: flex; justify-content: space-between; align-items: center;">
                <div>
                  <h5>Reboot System</h5>
                  <p style="color: var(--color-text-secondary); font-size: var(--font-size-sm);">
                    Restart the firewall appliance. This will temporarily interrupt network connectivity.
                  </p>
                </div>
                <button id="reboot-btn" class="btn btn-danger">Reboot</button>
              </div>
            </div>

            <div class="card" style="border-color: var(--color-danger);">
              <div style="display: flex; justify-content: space-between; align-items: center;">
                <div>
                  <h5>Factory Reset</h5>
                  <p style="color: var(--color-text-secondary); font-size: var(--font-size-sm);">
                    Reset all configuration to factory defaults. This cannot be undone.
                  </p>
                </div>
                <button id="reset-btn" class="btn btn-danger">Reset</button>
              </div>
            </div>
          </div>
        </div>
      </div>
    `;
  }

  private formatBytes(bytes: number): string {
    if (bytes === 0) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(1024));
    return `${(bytes / Math.pow(1024, i)).toFixed(1)} ${units[i]}`;
  }
}
