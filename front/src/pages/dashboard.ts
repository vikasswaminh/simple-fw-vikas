import { Component } from '@components/component';
import { store } from '@state/store';
import { systemApi } from '@api/endpoints';
import { formatBytes, formatUptime, formatTime } from '@utils';
import type { SystemInfo, TrafficSnapshot } from '@schemas';

/**
 * Dashboard Page Component
 */
export class DashboardPage extends Component<{
  systemInfo: SystemInfo | null;
  traffic: TrafficSnapshot | null;
  loading: boolean;
  error: string | null;
}> {
  private refreshInterval: ReturnType<typeof setInterval> | null = null;

  constructor(element: HTMLElement | string) {
    super(element);
    this.state = {
      systemInfo: null,
      traffic: null,
      loading: true,
      error: null,
    };
  }

  init(): void {
    this.loadData();
    this.startAutoRefresh();
  }

  destroy(): void {
    this.stopAutoRefresh();
    super.destroy();
  }

  private async loadData(): Promise<void> {
    this.setState({ loading: true, error: null });

    try {
      const [systemInfo, traffic] = await Promise.all([
        systemApi.getInfo(),
        systemApi.getTraffic(),
      ]);

      this.setState({ systemInfo, traffic, loading: false });

      // Update global store
      store.setState({ systemInfo, traffic });
    } catch (error) {
      console.error('Failed to load dashboard data:', error);
      this.setState({
        loading: false,
        error: error instanceof Error ? error.message : 'Failed to load data',
      });
    }
  }

  private startAutoRefresh(): void {
    this.refreshInterval = setInterval(() => {
      this.loadData();
    }, 5000);
  }

  private stopAutoRefresh(): void {
    if (this.refreshInterval) {
      clearInterval(this.refreshInterval);
      this.refreshInterval = null;
    }
  }

  render(): void {
    const { systemInfo, traffic, loading, error } = this.state;

    if (loading && !systemInfo) {
      this.element.innerHTML = `
        <div class="loading">
          <div class="spinner"></div>
          <span>Loading dashboard...</span>
        </div>
      `;
      return;
    }

    if (error && !systemInfo) {
      this.element.innerHTML = `
        <div class="card">
          <div class="card-header">
            <h3 class="card-title">Error</h3>
          </div>
          <p style="color: var(--color-danger)">${error}</p>
          <button class="btn btn-primary" style="margin-top: var(--spacing-md)">
            Retry
          </button>
        </div>
      `;

      const retryBtn = this.$<HTMLButtonElement>('.btn');
      retryBtn?.addEventListener('click', () => this.loadData());
      return;
    }

    if (!systemInfo) {
      this.element.innerHTML = '<p>No data available</p>';
      return;
    }

    this.element.innerHTML = `
      <div class="dashboard-grid" style="
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
        gap: var(--spacing-lg);
      ">
        <!-- System Info Card -->
        <div class="card">
          <div class="card-header">
            <h3 class="card-title">System Information</h3>
            <span class="badge badge-success">Online</span>
          </div>
          <div style="display: grid; gap: var(--spacing-sm);">
            <div style="display: flex; justify-content: space-between;">
              <span style="color: var(--color-text-secondary)">Hostname</span>
              <span>${systemInfo.hostname}</span>
            </div>
            <div style="display: flex; justify-content: space-between;">
              <span style="color: var(--color-text-secondary)">Version</span>
              <span>${systemInfo.version}</span>
            </div>
            <div style="display: flex; justify-content: space-between;">
              <span style="color: var(--color-text-secondary)">Uptime</span>
              <span>${formatUptime(systemInfo.uptime)}</span>
            </div>
            <div style="display: flex; justify-content: space-between;">
              <span style="color: var(--color-text-secondary)">CPU Usage</span>
              <span>${systemInfo.cpu_percent}%</span>
            </div>
            <div style="display: flex; justify-content: space-between;">
              <span style="color: var(--color-text-secondary)">Memory</span>
              <span>${systemInfo.mem_used_mb} MB / ${systemInfo.mem_total_mb} MB</span>
            </div>
          </div>
        </div>

        <!-- Traffic Card -->
        <div class="card">
          <div class="card-header">
            <h3 class="card-title">Network Traffic</h3>
          </div>
          ${traffic ? `
            <div style="display: grid; gap: var(--spacing-md);">
              <div style="display: grid; grid-template-columns: repeat(2, 1fr); gap: var(--spacing-md);">
                <div style="text-align: center; padding: var(--spacing-md); background: var(--color-bg-tertiary); border-radius: var(--radius-md);">
                  <div style="font-size: 0.75rem; color: var(--color-text-secondary); margin-bottom: var(--spacing-xs);">RX</div>
                  <div style="font-size: 1.25rem; font-weight: 600; color: var(--color-success);">${formatBytes(traffic.rx_rate)}</div>
                  <div style="font-size: 0.75rem; color: var(--color-text-muted);">/s</div>
                </div>
                <div style="text-align: center; padding: var(--spacing-md); background: var(--color-bg-tertiary); border-radius: var(--radius-md);">
                  <div style="font-size: 0.75rem; color: var(--color-text-secondary); margin-bottom: var(--spacing-xs);">TX</div>
                  <div style="font-size: 1.25rem; font-weight: 600; color: var(--color-primary);">${formatBytes(traffic.tx_rate)}</div>
                  <div style="font-size: 0.75rem; color: var(--color-text-muted);">/s</div>
                </div>
              </div>
              <div style="display: flex; justify-content: space-between; font-size: var(--font-size-sm); color: var(--color-text-secondary);">
                <span>Total RX: ${formatBytes(traffic.rx_total)}</span>
                <span>Total TX: ${formatBytes(traffic.tx_total)}</span>
              </div>
            </div>
          ` : '<p>No traffic data available</p>'}
        </div>

        <!-- Quick Actions Card -->
        <div class="card">
          <div class="card-header">
            <h3 class="card-title">Quick Actions</h3>
          </div>
          <div style="display: grid; grid-template-columns: repeat(2, 1fr); gap: var(--spacing-md);">
            <a href="/network" data-navigate class="btn btn-secondary">
              Configure Network
            </a>
            <a href="/firewall" data-navigate class="btn btn-secondary">
              Edit Firewall Rules
            </a>
            <a href="/nat" data-navigate class="btn btn-secondary">
              Configure NAT
            </a>
            <a href="/routing" data-navigate class="btn btn-secondary">
              Routing Protocols
            </a>
          </div>
        </div>
      </div>
    `;
  }
}
