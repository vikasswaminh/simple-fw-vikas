import { z } from 'zod';
import { InterfaceNameSchema, CidrSchema, IpAddressSchema, PortSchema } from './common';

/**
 * NAT-related validation schemas
 */

// Masquerade (SNAT) rule
export const MasqueradeRuleSchema = z.object({
  out_interface: InterfaceNameSchema,
  source_cidr: z.union([CidrSchema, z.literal('')]),
});

// Port forwarding (DNAT) rule
export const PortForwardRuleSchema = z.object({
  protocol: z.enum(['tcp', 'udp']),
  dest_port: PortSchema,
  forward_to: z.string().regex(/^[^:]+:\d{1,5}$/, 'Must be in format ip:port'),
  in_interface: InterfaceNameSchema,
});

// Source NAT rule
export const SnatRuleSchema = z.object({
  source_cidr: CidrSchema,
  to_address: IpAddressSchema,
  out_interface: InterfaceNameSchema.nullish(),
});

// NAT configuration
export const NatConfigSchema = z.object({
  masquerade: z.array(MasqueradeRuleSchema),
  port_forward: z.array(PortForwardRuleSchema),
  snat: z.array(SnatRuleSchema),
});

// Export types
export type MasqueradeRule = z.infer<typeof MasqueradeRuleSchema>;
export type PortForwardRule = z.infer<typeof PortForwardRuleSchema>;
export type SnatRule = z.infer<typeof SnatRuleSchema>;
export type NatConfig = z.infer<typeof NatConfigSchema>;
