import { Component } from '@components/component';
import { store } from '@state/store';
import { systemApi, conntrackApi, networkApi, auditApi, routesApi } from '@api/endpoints';
import type { ServicesMap } from '@api/endpoints';
import { formatBytes, formatUptime, formatTimeAgo, escapeHtml } from '@utils';
import type { SystemInfo, TrafficSnapshot, Interface, AuditEntry } from '@schemas';

/**
 * Dashboard Page — matches reference design with 8 widgets
 */
export class DashboardPage extends Component<{
  systemInfo: SystemInfo | null;
  traffic: TrafficSnapshot | null;
  interfaces: Interface[];
  sessionCount: number;
  auditEntries: AuditEntry[];
  defaultGateway: string;
  gatewayIface: string;
  services: ServicesMap;
  loading: boolean;
  error: string | null;
  autoRefresh: boolean;
}> {
  private refreshInterval: ReturnType<typeof setInterval> | null = null;

  constructor(element: HTMLElement | string) {
    super(element);
    this.state = {
      systemInfo: null,
      traffic: null,
      interfaces: [],
      sessionCount: 0,
      auditEntries: [],
      defaultGateway: '',
      gatewayIface: '',
      services: {},
      loading: true,
      error: null,
      autoRefresh: true,
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
    try {
      const [systemInfo, traffic, ifaceData, conntrack, audit, services] = await Promise.all([
        systemApi.getInfo(),
        systemApi.getTraffic(),
        networkApi.getInterfaces().catch(() => ({ interfaces: [] })),
        conntrackApi.getConnections().catch(() => []),
        auditApi.getLog().catch(() => []),
        systemApi.getServices().catch(() => ({} as ServicesMap)),
      ]);

      // Try to get default gateway from routes
      let defaultGateway = '';
      let gatewayIface = '';
      try {
        const routeData = await routesApi.getRoutes();
        const defRoute = routeData.routes?.find((r: { destination: string }) => r.destination === 'default' || r.destination === '0.0.0.0/0');
        if (defRoute) {
          defaultGateway = defRoute.gateway;
          gatewayIface = defRoute.interface || '';
        }
      } catch { /* ignore */ }

      this.setState({
        systemInfo,
        traffic,
        interfaces: ifaceData.interfaces || [],
        sessionCount: Array.isArray(conntrack) ? conntrack.length : 0,
        auditEntries: Array.isArray(audit) ? audit.slice(0, 5) : [],
        defaultGateway,
        gatewayIface,
        services,
        loading: false,
      });

      store.setState({ systemInfo, traffic });

      // Update session count in header
      const sessionEl = document.getElementById('session-count');
      if (sessionEl) sessionEl.textContent = `⚡ ${this.state.sessionCount} sessions`;
    } catch (error) {
      this.setState({
        loading: false,
        error: error instanceof Error ? error.message : 'Failed to load data',
      });
    }
  }

  private startAutoRefresh(): void {
    this.refreshInterval = setInterval(() => {
      if (this.state.autoRefresh) this.loadData();
    }, 5000);
  }

  private stopAutoRefresh(): void {
    if (this.refreshInterval) {
      clearInterval(this.refreshInterval);
      this.refreshInterval = null;
    }
  }

  render(): void {
    const { systemInfo, traffic, interfaces, loading, error, autoRefresh, sessionCount, auditEntries, defaultGateway, gatewayIface } = this.state;

    if (loading && !systemInfo) {
      this.element.innerHTML = `<div class="loading"><div class="spinner"></div> Loading dashboard...</div>`;
      return;
    }

    if (error && !systemInfo) {
      this.element.innerHTML = `
        <div class="card"><p style="color: var(--color-danger)">${error}</p>
        <button class="btn btn-primary" style="margin-top: var(--spacing-md);">Retry</button></div>`;
      this.$<HTMLButtonElement>('.btn')?.addEventListener('click', () => this.loadData());
      return;
    }

    const si = systemInfo!;
    const cpuPct = si.cpu_usage_percent ?? 0;
    const memPct = si.memory_total_mb > 0 ? Math.round((si.memory_used_mb / si.memory_total_mb) * 100) : 0;

    this.element.innerHTML = `
      <!-- Page Header -->
      <div class="page-header">
        <h1 class="page-title">Dashboard</h1>
        <div class="page-actions">
          <span style="font-size: var(--font-size-sm); color: var(--color-text-muted);">⚡ ${sessionCount} sessions</span>
          <label class="toggle" title="Auto-refresh">
            <input type="checkbox" id="auto-refresh-toggle" ${autoRefresh ? 'checked' : ''}>
            <span class="toggle-track"></span>
          </label>
          <span style="font-size: var(--font-size-xs); color: var(--color-text-muted);">Auto-refresh</span>
        </div>
      </div>

      <!-- Interface Status Cards (top row) -->
      <div class="grid-4" style="margin-bottom: var(--spacing-lg);">
        ${interfaces.slice(0, 4).map((iface: Interface) => `
          <div class="iface-card">
            <div class="iface-header">
              <span class="iface-name">${escapeHtml(iface.name)}</span>
              <span class="badge ${iface.link_up ? 'badge-success' : 'badge-danger'} badge-sm">
                ${iface.link_up ? 'up' : 'down'}
              </span>
            </div>
            <div class="iface-meta">
              ${escapeHtml(iface.role ? iface.role.toUpperCase() : 'None')} — ${escapeHtml(iface.ipv4_addrs?.[0] || '—')}
            </div>
            <div class="iface-meta">
              RX/TX &nbsp;
              <span style="color: var(--color-success);">${formatBytes(iface.rx_bytes || 0)}</span> /
              <span style="color: var(--color-primary);">${formatBytes(iface.tx_bytes || 0)}</span>
            </div>
          </div>
        `).join('')}
      </div>

      <!-- Main Widgets Grid (2 columns) -->
      <div class="grid-2" style="margin-bottom: var(--spacing-lg);">
        <!-- System Info Card -->
        <div class="card">
          <div class="card-title"><span class="icon">ℹ</span> System Info</div>
          <div style="margin-top: var(--spacing-md);">
            <div class="kv-row"><span class="kv-label">Hostname</span><span class="kv-value">${escapeHtml(si.hostname)}</span></div>
            <div class="kv-row"><span class="kv-label">Version</span><span class="kv-value">${escapeHtml(si.version)}</span></div>
            <div class="kv-row"><span class="kv-label">Uptime</span><span class="kv-value">${formatUptime(si.uptime_seconds)}</span></div>
            <div class="kv-row">
              <span class="kv-label">CPU</span>
              <span class="kv-value">${cpuPct}%</span>
            </div>
            <div class="progress" style="margin-bottom: 8px;"><div class="progress-bar ${cpuPct > 80 ? 'danger' : cpuPct > 60 ? 'warning' : ''}" style="width: ${cpuPct}%"></div></div>
            <div class="kv-row">
              <span class="kv-label">Memory</span>
              <span class="kv-value">${si.memory_used_mb} / ${si.memory_total_mb} MB</span>
            </div>
            <div class="progress"><div class="progress-bar ${memPct > 80 ? 'danger' : memPct > 60 ? 'warning' : ''}" style="width: ${memPct}%"></div></div>
          </div>
        </div>

        <!-- Traffic Card -->
        <div class="card">
          <div class="card-title"><span class="icon">📊</span> Traffic</div>
          ${traffic ? `
            <div style="margin-top: var(--spacing-md);">
              <div class="kv-row">
                <span class="kv-label" style="color: var(--color-success);">⬇ RX Rate</span>
                <span class="kv-value">${formatBytes(traffic.rx_rate)}/s</span>
              </div>
              <div class="kv-row">
                <span class="kv-label" style="color: var(--color-primary);">⬆ TX Rate</span>
                <span class="kv-value">${formatBytes(traffic.tx_rate)}/s</span>
              </div>
              <div class="kv-row">
                <span class="kv-label">Total RX</span>
                <span class="kv-value">${formatBytes(traffic.rx_total)}</span>
              </div>
              <div class="kv-row">
                <span class="kv-label">Total TX</span>
                <span class="kv-value">${formatBytes(traffic.tx_total)}</span>
              </div>
            </div>
          ` : '<p style="color: var(--color-text-muted); margin-top: var(--spacing-md);">No traffic data</p>'}
        </div>
      </div>

      <!-- Services + Gateway row -->
      <div class="grid-2" style="margin-bottom: var(--spacing-lg);">
        <!-- Services Card — live from GET /api/services (systemctl is-active) -->
        <div class="card">
          <div class="card-title"><span class="icon">⚡</span> Services</div>
          <div style="margin-top: var(--spacing-md);">
            ${(() => {
              const labels: Record<string, string> = {
                dns: 'DNS Resolver',
                dhcp: 'DHCP Server',
                ntp: 'NTP',
                ssh: 'SSH',
                syslog: 'Syslog',
              };
              return Object.entries(labels).map(([key, label]) => {
                const svc = this.state.services[key];
                const active = svc?.active ?? false;
                return `
                  <div class="kv-row">
                    <span class="kv-label">${label}</span>
                    <span class="badge ${active ? 'badge-success' : 'badge-danger'} badge-sm">
                      ${active ? 'running' : 'stopped'}
                    </span>
                  </div>
                `;
              }).join('');
            })()}
          </div>
        </div>

        <!-- Gateway Card -->
        <div class="card">
          <div class="card-title"><span class="icon">🌐</span> Gateway</div>
          <div style="margin-top: var(--spacing-md);">
            <div class="kv-row"><span class="kv-label">Gateway</span><span class="kv-value">${defaultGateway || '—'}</span></div>
            <div class="kv-row"><span class="kv-label">Interface</span><span class="kv-value">${gatewayIface || '—'}</span></div>
            <div class="kv-row"><span class="kv-label">Latency</span><span class="kv-value">—</span></div>
            <div class="kv-row"><span class="kv-label">Packet Loss</span><span class="badge badge-success badge-sm">0%</span></div>
          </div>
        </div>
      </div>

      <!-- Recent Alerts -->
      <div class="card" style="margin-bottom: var(--spacing-lg);">
        <div class="card-title"><span class="icon">⚠</span> Recent Alerts</div>
        <div style="margin-top: var(--spacing-md);">
          ${auditEntries.length > 0 ? auditEntries.map((entry: AuditEntry) => `
            <div class="alert-row">
              <span class="alert-icon ${entry.status >= 400 ? 'danger' : 'info'}">${entry.status >= 400 ? '⚠' : 'ℹ'}</span>
              <span class="alert-message">${escapeHtml(entry.method)} ${escapeHtml(entry.endpoint)} — ${escapeHtml(entry.user)}</span>
              <span class="alert-time">${formatTimeAgo(entry.timestamp)}</span>
            </div>
          `).join('') : '<p style="color: var(--color-text-muted);">No recent alerts</p>'}
        </div>
      </div>

      <!-- Quick Actions -->
      <div class="card">
        <div class="card-title">Quick Actions</div>
        <div class="grid-4" style="margin-top: var(--spacing-md);">
          <a href="/network" data-navigate class="btn btn-secondary" style="padding: var(--spacing-md); justify-content: center;">
            ⇌ &nbsp;Network
          </a>
          <a href="/firewall" data-navigate class="btn btn-secondary" style="padding: var(--spacing-md); justify-content: center;">
            ◎ &nbsp;Firewall
          </a>
          <a href="/nat" data-navigate class="btn btn-secondary" style="padding: var(--spacing-md); justify-content: center;">
            ⇄ &nbsp;NAT
          </a>
          <a href="/routing" data-navigate class="btn btn-secondary" style="padding: var(--spacing-md); justify-content: center;">
            ⇋ &nbsp;Routing
          </a>
        </div>
      </div>
    `;

    // Bind auto-refresh toggle
    const toggle = this.$<HTMLInputElement>('#auto-refresh-toggle');
    toggle?.addEventListener('change', () => {
      this.setState({ autoRefresh: toggle.checked });
    });
  }
}
