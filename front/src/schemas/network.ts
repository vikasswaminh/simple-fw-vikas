import { z } from 'zod';
import {
  InterfaceNameSchema,
  CidrSchema,
  IpAddressSchema,
  MacAddressSchema,
} from './common';

/**
 * Network-related validation schemas
 */

// Interface role
export const InterfaceRoleSchema = z.enum(['wan', 'lan', 'dmz', 'unset']);

// Interface information
export const InterfaceSchema = z.object({
  name: InterfaceNameSchema,
  mac: MacAddressSchema.nullish(),
  link_up: z.boolean(),
  ipv4_addrs: z.array(z.string()),
  mtu: z.number().int().min(68).max(9000).default(1500),
  speed: z.string().nullish(),
  description: z.string().max(128).nullish(),
  role: InterfaceRoleSchema,
  zone: z.string().nullish(),
  rx_bytes: z.number().int().nonnegative().default(0),
  tx_bytes: z.number().int().nonnegative().default(0),
  rx_packets: z.number().int().nonnegative().default(0),
  tx_packets: z.number().int().nonnegative().default(0),
  rx_errors: z.number().int().nonnegative().default(0),
  tx_errors: z.number().int().nonnegative().default(0),
  rx_dropped: z.number().int().nonnegative().default(0),
  tx_dropped: z.number().int().nonnegative().default(0),
});

// Interface configuration request
export const InterfaceConfigSchema = z.object({
  name: InterfaceNameSchema,
  mode: z.enum(['dhcp', 'static', '']).nullish(),
  address: z.string().nullish(),
  gateway: z.string().ip().nullish(),
  dns: z.array(z.string().ip()).nullish(),
  mtu: z.number().int().min(68).max(9000).nullish(),
  enabled: z.boolean().nullish(),
  description: z.string().max(128).nullish(),
  role: InterfaceRoleSchema.nullish(),
});

// Interface role mapping
export const InterfaceRoleMappingSchema = z.object({
  interface: InterfaceNameSchema,
  role: z.string(),
  zone: z.string(),
});

// Interface roles config
export const InterfaceRolesConfigSchema = z.object({
  roles: z.array(InterfaceRoleMappingSchema),
});

// Static route
export const StaticRouteSchema = z.object({
  destination: z.union([CidrSchema, z.literal('default')]),
  gateway: IpAddressSchema,
  interface: InterfaceNameSchema.nullish(),
  metric: z.number().int().min(0).max(65535).default(100),
});

// Static routes config
export const StaticRoutesConfigSchema = z.object({
  routes: z.array(StaticRouteSchema),
});

// DHCP lease
export const DhcpLeaseSchema = z.object({
  expires: z.string(),
  mac: MacAddressSchema,
  ip: IpAddressSchema,
  hostname: z.string(),
  client_id: z.string(),
});

// ARP entry
export const ArpEntrySchema = z.object({
  ip: IpAddressSchema,
  mac: MacAddressSchema,
  interface: InterfaceNameSchema,
  state: z.enum(['REACHABLE', 'STALE', 'DELAY', 'PROBE', 'FAILED', 'NOARP', 'INCOMPLETE', 'PERMANENT']),
});

// DNS local override
export const DnsLocalEntrySchema = z.object({
  hostname: z.string().min(1).max(253),
  ip: z.string().ip(),
});

// NTP status
export const NtpStatusSchema = z.record(z.string());

// Export types
export type InterfaceRole = z.infer<typeof InterfaceRoleSchema>;
export type Interface = z.infer<typeof InterfaceSchema>;
export type InterfaceConfig = z.infer<typeof InterfaceConfigSchema>;
export type InterfaceRoleMapping = z.infer<typeof InterfaceRoleMappingSchema>;
export type InterfaceRolesConfig = z.infer<typeof InterfaceRolesConfigSchema>;
export type StaticRoute = z.infer<typeof StaticRouteSchema>;
export type StaticRoutesConfig = z.infer<typeof StaticRoutesConfigSchema>;
export type DhcpLease = z.infer<typeof DhcpLeaseSchema>;
export type ArpEntry = z.infer<typeof ArpEntrySchema>;
export type DnsLocalEntry = z.infer<typeof DnsLocalEntrySchema>;
export type NtpStatus = z.infer<typeof NtpStatusSchema>;
