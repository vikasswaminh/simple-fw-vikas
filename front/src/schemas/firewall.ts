import { z } from 'zod';
import {
  InterfaceNameSchema,
  CidrSchema,
  PortRangeSchema,
  DayOfWeekSchema,
  TimeStringSchema,
} from './common';

/**
 * Firewall-related validation schemas
 */

// Firewall direction
export const FirewallDirectionSchema = z.enum(['forward', 'input', 'output']);

// Firewall action
export const FirewallActionSchema = z.enum(['accept', 'drop', 'reject', 'log']);

// Firewall protocol
export const FirewallProtocolSchema = z.enum(['tcp', 'udp', 'icmp', 'tcp+udp', 'any']);

// Rule schedule (time-based rules)
export const RuleScheduleSchema = z.object({
  days: z.array(DayOfWeekSchema),
  start: TimeStringSchema,
  end: TimeStringSchema,
});

// Firewall rule
export const FirewallRuleSchema = z.object({
  name: z.string().min(1).max(64),
  enabled: z.boolean().default(true),
  direction: FirewallDirectionSchema.default('forward'),
  protocol: FirewallProtocolSchema.default('any'),
  in_interface: z.union([InterfaceNameSchema, z.literal('')]).optional(),
  out_interface: z.union([InterfaceNameSchema, z.literal('')]).optional(),
  src_zone: z.string().max(32).optional(),
  dst_zone: z.string().max(32).optional(),
  src_ip: z.union([CidrSchema, z.literal(''), z.literal('any')]).optional(),
  dst_ip: z.union([CidrSchema, z.literal(''), z.literal('any')]).optional(),
  src_port: z.union([PortRangeSchema, z.literal(''), z.literal('any')]).optional(),
  dst_port: z.union([PortRangeSchema, z.literal(''), z.literal('any')]).optional(),
  action: FirewallActionSchema.default('accept'),
  log: z.boolean().default(false),
  comment: z.string().max(256).optional(),
  schedule: RuleScheduleSchema.optional(),
  ipv6: z.boolean().default(false),
});

// Firewall configuration
export const FirewallConfigSchema = z.object({
  rules: z.array(FirewallRuleSchema),
  forward_policy: FirewallActionSchema.default('drop'),
  input_policy: FirewallActionSchema.default('drop'),
  output_policy: FirewallActionSchema.default('accept'),
  zones: z.array(
    z.object({
      interface: InterfaceNameSchema,
      zone: z.string().max(32),
      role: z.string().optional(),
    })
  ),
});

// Address group
export const AddressGroupSchema = z.object({
  name: z.string().min(1).max(64),
  addresses: z.array(CidrSchema),
});

// Port group
export const PortGroupSchema = z.object({
  name: z.string().min(1).max(64),
  ports: z.array(z.union([z.number().int().min(1).max(65535), PortRangeSchema])),
});

// Firewall groups
export const FirewallGroupsSchema = z.object({
  address_groups: z.array(AddressGroupSchema),
  port_groups: z.array(PortGroupSchema),
});

// Rule counter (hit counts)
export const RuleCounterSchema = z.object({
  chain: z.string(),
  comment: z.string(),
  packets: z.number().int().nonnegative(),
  bytes: z.number().int().nonnegative(),
});

// Firewall counters response
export const FirewallCountersSchema = z.object({
  counters: z.array(RuleCounterSchema),
});

// NFT preview response
export const NftPreviewSchema = z.object({
  dry_run: z.boolean(),
  nft_script: z.string(),
  rule_count: z.number().int().nonnegative(),
});

// Export types
export type FirewallDirection = z.infer<typeof FirewallDirectionSchema>;
export type FirewallAction = z.infer<typeof FirewallActionSchema>;
export type FirewallProtocol = z.infer<typeof FirewallProtocolSchema>;
export type RuleSchedule = z.infer<typeof RuleScheduleSchema>;
export type FirewallRule = z.infer<typeof FirewallRuleSchema>;
export type FirewallConfig = z.infer<typeof FirewallConfigSchema>;
export type AddressGroup = z.infer<typeof AddressGroupSchema>;
export type PortGroup = z.infer<typeof PortGroupSchema>;
export type FirewallGroups = z.infer<typeof FirewallGroupsSchema>;
export type RuleCounter = z.infer<typeof RuleCounterSchema>;
export type FirewallCounters = z.infer<typeof FirewallCountersSchema>;
export type NftPreview = z.infer<typeof NftPreviewSchema>;
