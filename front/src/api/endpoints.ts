import { api } from './client';
import {
  // System
  SystemInfoSchema,
  TrafficSnapshotSchema,
  SystemSettingsSchema,
  type SystemInfo,
  type TrafficSnapshot,
  type SystemSettings,
  // Network
  InterfaceSchema,
  InterfaceRolesConfigSchema,
  StaticRoutesConfigSchema,
  type Interface,
  type InterfaceConfig,
  type InterfaceRolesConfig,
  type StaticRoute,
  type StaticRoutesConfig,
  type DhcpLease,
  type ArpEntry,
  type DnsLocalEntry,
  // Firewall
  FirewallConfigSchema,
  FirewallGroupsSchema,
  type FirewallConfig,
  type FirewallGroups,
  type NftPreview,
  // NAT
  NatConfigSchema,
  type NatConfig,
  type MasqueradeRule,
  type PortForwardRule,
  // Routing
  OspfConfigSchema,
  BgpConfigSchema,
  type OspfConfig,
  type BgpConfig,
  type RipConfig,
  type RouteEntry,
  type OspfNeighborStatus,
  type BgpPeerStatus,
  // Audit
  AuditLogSchema,
  type AuditEntry,
  // Tools
  type PingRequest,
  type PingResponse,
  type TracerouteRequest,
  type TracerouteResponse,
  type WolRequest,
  type ConntrackEntry,
  // Auth
  type LoginRequest,
  type LoginResponse,
  type PasswordChangeRequest,
} from '@schemas';

/**
 * System API endpoints
 */
export interface ServiceStatus { unit: string; active: boolean }
export type ServicesMap = Record<string, ServiceStatus>;

export const systemApi = {
  getInfo: () => api.get<SystemInfo>('/api/system/info', SystemInfoSchema),
  getTraffic: () => api.get<TrafficSnapshot>('/api/system/traffic', TrafficSnapshotSchema),
  getServices: () => api.get<ServicesMap>('/api/services'),
  getSettings: () => api.get<SystemSettings>('/api/settings'),
  saveSettings: (settings: SystemSettings) => api.post('/api/settings', settings),
  reboot: (password: string) => api.post('/api/system/reboot', { confirm_password: password }),
  factoryReset: (password: string) => api.post('/api/system/factory-reset', { confirm_password: password }),
};

/**
 * Network/Interface API endpoints
 */
export const networkApi = {
  getInterfaces: () => api.get<{ interfaces: Interface[] }>('/api/interfaces'),
  getInterface: (name: string) => api.get<Interface>(`/api/interfaces/${name}`),
  configure: (config: InterfaceConfig) => api.post('/api/interfaces/config', config),
  getRoles: () => api.get<InterfaceRolesConfig>('/api/interfaces/roles'),
  saveRoles: (roles: InterfaceRolesConfig) => api.post('/api/interfaces/roles', roles),
};

/**
 * Routes API endpoints
 */
export const routesApi = {
  getRoutes: () => api.get<StaticRoutesConfig>('/api/routes'),
  saveRoutes: (routes: StaticRoutesConfig) => api.post('/api/routes', routes),
};

/**
 * Firewall API endpoints
 */
export const firewallApi = {
  getConfig: () => api.get<FirewallConfig>('/api/firewall', FirewallConfigSchema),
  saveConfig: (config: FirewallConfig) => api.post('/api/firewall', config),
  preview: (config: FirewallConfig) =>
    api.post<NftPreview>('/api/firewall?dry_run=true', config),
  getCounters: () => api.get('/api/firewall/counters'),
  getGroups: () => api.get<FirewallGroups>('/api/firewall/groups', FirewallGroupsSchema),
  saveGroups: (groups: FirewallGroups) => api.post('/api/firewall/groups', groups),
};

/**
 * NAT API endpoints
 */
export const natApi = {
  getConfig: () => api.get<NatConfig>('/api/nat', NatConfigSchema),
  saveConfig: (config: NatConfig) => api.post('/api/nat', config),
  deleteMasquerade: (index: number) => api.delete(`/api/nat/masquerade/${index}`),
  deletePortForward: (index: number) => api.delete(`/api/nat/port_forward/${index}`),
  deleteSnat: (index: number) => api.delete(`/api/nat/snat/${index}`),
};

/**
 * Routing Protocol API endpoints
 */
export const routingApi = {
  // OSPF
  getOspfConfig: () => api.get<OspfConfig>('/api/routing/ospf'),
  saveOspfConfig: (config: OspfConfig) => api.post('/api/routing/ospf', config),
  getOspfNeighbors: () => api.get<{ neighbors: OspfNeighborStatus[] }>('/api/routing/ospf/neighbors'),

  // BGP
  getBgpConfig: () => api.get<BgpConfig>('/api/routing/bgp'),
  saveBgpConfig: (config: BgpConfig) => api.post('/api/routing/bgp', config),
  getBgpSummary: () => api.get<{ summary: string }>('/api/routing/bgp/summary'),

  // General
  getRoutingTable: (protocol?: string) =>
    api.get<{ table: string }>(`/api/routing/table${protocol ? `?protocol=${protocol}` : ''}`),
  getActiveProtocols: () => api.get('/api/routing/protocols'),
};

/**
 * Audit API endpoints
 */
export const auditApi = {
  getLog: () => api.get<AuditEntry[]>('/api/audit', AuditLogSchema),
};

/**
 * Local log viewer (Phase J — admin-only).
 */
export type LogSource = 'audit' | 'system' | 'firewall';
export interface LogResponse { source: LogSource; lines: string[]; truncated: boolean }
export const logsApi = {
  get: (source: LogSource, tail = 200) =>
    api.get<LogResponse>(`/api/logs?source=${source}&tail=${tail}`),
};

/**
 * Firmware upgrade (Phase I — admin-only).
 *
 * `upload` sends the raw ISO bytes as the request body with
 * Content-Type: application/octet-stream. The API client's post() always
 * JSON-stringifies its body, so we hit fetch() directly here.
 */
export const firmwareApi = {
  status: () => api.get<{ available: boolean; exit?: number; stdout?: string; stderr?: string }>('/api/system/upgrade-status'),
  upload: async (file: File): Promise<{ apply_exit: number; apply_stdout: string; apply_stderr: string }> => {
    const csrf = typeof document !== 'undefined'
      ? (document.cookie.split(';').map(p => p.trim()).find(p => p.startsWith('quickfw_csrf='))?.slice('quickfw_csrf='.length) || '')
      : '';
    const r = await fetch('/api/system/firmware-upload', {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/octet-stream', 'X-CSRF-Token': csrf },
      body: file,
    });
    const body = await r.json() as { apply_exit?: number; apply_stdout?: string; apply_stderr?: string; error?: string };
    if (!r.ok) {
      throw new Error(body.error || `HTTP ${r.status}`);
    }
    return {
      apply_exit: body.apply_exit ?? -1,
      apply_stdout: body.apply_stdout ?? '',
      apply_stderr: body.apply_stderr ?? '',
    };
  },
};

/**
 * Tools API endpoints
 */
export const toolsApi = {
  getArpTable: () => api.get<ArpEntry[]>('/api/tools/arp'),
  flushArp: () => api.post('/api/tools/arp/flush', {}),
  getDhcpLeases: () => api.get<DhcpLease[]>('/api/tools/dhcp-leases'),
  getDnsLocal: () => api.get<DnsLocalEntry[]>('/api/tools/dns-local'),
  saveDnsLocal: (entries: DnsLocalEntry[]) => api.post('/api/tools/dns-local', entries),
  ping: (request: PingRequest) => api.post<PingResponse>('/api/tools/ping', request),
  traceroute: (request: TracerouteRequest) =>
    api.post<TracerouteResponse>('/api/tools/traceroute', request),
  wol: (request: WolRequest) => api.post('/api/tools/wol', request),
  getNtpStatus: () => api.get('/api/tools/ntp-status'),
};

/**
 * Conntrack API endpoints
 */
export const conntrackApi = {
  getConnections: () => api.get<ConntrackEntry[]>('/api/conntrack'),
};

/**
 * Config Management API endpoints
 */
export const configApi = {
  export: () => api.get('/api/config/export'),
  getBackups: () => api.get<Array<{ name: string; size: number }>>('/api/config/backups'),
  restore: (name: string, password: string) =>
    api.post('/api/config/restore', { name, confirm_password: password }),
  import: (config: unknown) => api.post('/api/config/import', config),
};

/**
 * Auth API endpoints
 */
export const authApi = {
  login: (credentials: LoginRequest) => api.post<LoginResponse>('/api/auth/login', credentials),
  logout: () => api.post('/api/auth/logout', {}),
  changePassword: (request: PasswordChangeRequest) =>
    api.post('/api/auth/password', request),
  getWsToken: () => api.get('/api/auth/ws-token'),
};

/**
 * Users API endpoints — admin-only (backend gates with require_role(Admin)).
 */
export interface UserDto { username: string; role: 'admin' | 'operator' | 'readonly' }
/**
 * Syslog forwarding (Settings → Syslog).
 */
export interface SyslogConfig {
  enabled: boolean;
  server: string;
  port: number;
  protocol: 'udp' | 'tcp' | string;
  facility?: string;
}
export const syslogApi = {
  get: () => api.get<SyslogConfig>('/api/syslog'),
  save: (config: SyslogConfig) => api.post('/api/syslog', config),
};

export const usersApi = {
  list: () => api.get<UserDto[]>('/api/users'),
  create: (req: { username: string; password: string; role: string }) =>
    api.post('/api/users', req),
  delete: (username: string) => api.delete(`/api/users/${encodeURIComponent(username)}`),
  setRole: (username: string, role: string) =>
    api.post(`/api/users/${encodeURIComponent(username)}/role`, { role }),
  setPassword: (username: string, password: string) =>
    api.post(`/api/users/${encodeURIComponent(username)}/password`, { password }),
};
