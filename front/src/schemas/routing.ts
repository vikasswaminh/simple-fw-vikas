import { z } from 'zod';
import { CidrSchema, IpAddressSchema, InterfaceNameSchema } from './common';

/**
 * Routing protocol validation schemas
 */

// OSPF network statement
export const OspfNetworkSchema = z.object({
  prefix: CidrSchema,
  area: z.number().int().min(0),
});

// OSPF area
export const OspfAreaSchema = z.object({
  area_id: z.number().int().min(0),
  area_type: z.enum(['normal', 'stub', 'nssa']).default('normal'),
  authentication: z.string().optional(),
});

// OSPF configuration
export const OspfConfigSchema = z.object({
  enabled: z.boolean().default(false),
  router_id: IpAddressSchema,
  networks: z.array(OspfNetworkSchema),
  areas: z.array(OspfAreaSchema),
  passive_interfaces: z.array(InterfaceNameSchema),
  redistribute: z.array(z.enum(['connected', 'static', 'kernel', 'bgp'])),
  default_information_originate: z.boolean().default(false),
  log_adjacency_changes: z.boolean().default(true),
});

// BGP neighbor
export const BgpNeighborSchema = z.object({
  address: IpAddressSchema,
  remote_as: z.number().int().min(1).max(65535),
  description: z.string().max(256).optional(),
  password: z.string().optional(),
  timers_keepalive: z.number().int().min(1).default(60),
  timers_hold: z.number().int().min(3).default(180),
  passive: z.boolean().default(false),
  ebgp_multihop: z.number().int().min(1).max(255).optional(),
  update_source: z.string().optional(),
});

// BGP neighbor address-family settings
export const BgpNeighborAfSchema = z.object({
  address: IpAddressSchema,
  activate: z.boolean().default(false),
  prefix_list_in: z.string().optional(),
  prefix_list_out: z.string().optional(),
  route_map_in: z.string().optional(),
  route_map_out: z.string().optional(),
  next_hop_self: z.boolean().default(false),
  soft_reconfiguration: z.boolean().default(false),
});

// BGP address family
export const BgpAddressFamilySchema = z.object({
  afi: z.enum(['ipv4', 'ipv6']),
  safi: z.enum(['unicast', 'multicast']).default('unicast'),
  networks: z.array(CidrSchema),
  neighbors: z.array(BgpNeighborAfSchema),
  maximum_paths: z.number().int().min(1).default(1),
  redistribute: z.array(z.string()),
});

// BGP configuration
export const BgpConfigSchema = z.object({
  enabled: z.boolean().default(false),
  local_as: z.number().int().min(1).max(65535),
  router_id: IpAddressSchema,
  neighbors: z.array(BgpNeighborSchema),
  address_families: z.array(BgpAddressFamilySchema),
  redistribute: z.array(z.string()),
});

// RIP configuration
export const RipConfigSchema = z.object({
  enabled: z.boolean().default(false),
  router_id: IpAddressSchema.optional(),
  networks: z.array(CidrSchema),
  interfaces: z.array(InterfaceNameSchema),
  passive_interfaces: z.array(InterfaceNameSchema),
  redistribute_connected: z.boolean().default(false),
  redistribute_static: z.boolean().default(false),
  redistribute_ospf: z.boolean().default(false),
  redistribute_bgp: z.boolean().default(false),
  version: z.number().int().min(1).max(2).default(2),
  poison_reverse: z.boolean().default(true),
  triggered_updates: z.boolean().default(true),
});

// Routing table entry
export const RouteEntrySchema = z.object({
  destination: z.string(),
  gateway: z.string(),
  interface: z.string().optional(),
  protocol: z.string(),
  metric: z.number().int().nonnegative(),
  flags: z.string().optional(),
});

// Routing table
export const RoutingTableSchema = z.object({
  table: z.string(),
});

// OSPF neighbor status
export const OspfNeighborStatusSchema = z.object({
  neighbor_id: IpAddressSchema,
  ip_address: IpAddressSchema,
  state: z.enum(['DOWN', 'INIT', '2WAY', 'EXSTART', 'EXCHANGE', 'LOADING', 'FULL']),
  uptime: z.string(),
});

// BGP peer status
export const BgpPeerStatusSchema = z.object({
  remote_as: z.number(),
  ip_address: IpAddressSchema,
  state: z.enum(['IDLE', 'CONNECT', 'ACTIVE', 'OPENSENT', 'OPENCONFIRM', 'ESTABLISHED']),
  prefixes: z.number().int().nonnegative(),
  uptime: z.string(),
});

// Active protocols summary
export const ActiveProtocolsSchema = z.object({
  ospf: z.object({
    enabled: z.boolean(),
    router_id: z.string(),
    networks: z.number().int(),
  }),
  bgp: z.object({
    enabled: z.boolean(),
    local_as: z.number(),
    router_id: z.string(),
    neighbors: z.number().int(),
  }),
});

// Export types
export type OspfNetwork = z.infer<typeof OspfNetworkSchema>;
export type OspfArea = z.infer<typeof OspfAreaSchema>;
export type OspfConfig = z.infer<typeof OspfConfigSchema>;
export type BgpNeighbor = z.infer<typeof BgpNeighborSchema>;
export type BgpNeighborAf = z.infer<typeof BgpNeighborAfSchema>;
export type BgpAddressFamily = z.infer<typeof BgpAddressFamilySchema>;
export type BgpConfig = z.infer<typeof BgpConfigSchema>;
export type RipConfig = z.infer<typeof RipConfigSchema>;
export type RouteEntry = z.infer<typeof RouteEntrySchema>;
export type RoutingTable = z.infer<typeof RoutingTableSchema>;
export type OspfNeighborStatus = z.infer<typeof OspfNeighborStatusSchema>;
export type BgpPeerStatus = z.infer<typeof BgpPeerStatusSchema>;
export type ActiveProtocols = z.infer<typeof ActiveProtocolsSchema>;
