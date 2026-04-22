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
 * Tools API endpoints
 */
export const toolsApi = {
  getArpTable: () => api.get<ArpEntry[]>('/api/tools/arp'),
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
