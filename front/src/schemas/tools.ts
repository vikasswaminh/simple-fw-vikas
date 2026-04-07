import { z } from 'zod';
import { MacAddressSchema, InterfaceNameSchema } from './common';

/**
 * Network tools validation schemas
 */

// Ping request
export const PingRequestSchema = z.object({
  host: z.string().min(1).max(253),
  count: z.number().int().min(1).max(20).default(4),
});

// Ping response
export const PingResponseSchema = z.object({
  success: z.boolean(),
  stdout: z.string(),
  stderr: z.string(),
});

// Traceroute request
export const TracerouteRequestSchema = z.object({
  host: z.string().min(1).max(253),
});

// Traceroute response
export const TracerouteResponseSchema = z.object({
  success: z.boolean(),
  stdout: z.string(),
  stderr: z.string(),
});

// Wake-on-LAN request
export const WolRequestSchema = z.object({
  mac: MacAddressSchema,
  interface: InterfaceNameSchema.default('eth0'),
});

// Wake-on-LAN response
export const WolResponseSchema = z.object({
  message: z.string(),
  mac: z.string(),
  interface: z.string(),
});

// Connection tracking entry
export const ConntrackEntrySchema = z.object({
  protocol: z.string(),
  src: z.string(),
  dst: z.string(),
  sport: z.string(),
  dport: z.string(),
  state: z.string(),
  bytes: z.number().int().optional(),
});

// Conntrack response
export const ConntrackResponseSchema = z.array(ConntrackEntrySchema);

// Export types
export type PingRequest = z.infer<typeof PingRequestSchema>;
export type PingResponse = z.infer<typeof PingResponseSchema>;
export type TracerouteRequest = z.infer<typeof TracerouteRequestSchema>;
export type TracerouteResponse = z.infer<typeof TracerouteResponseSchema>;
export type WolRequest = z.infer<typeof WolRequestSchema>;
export type WolResponse = z.infer<typeof WolResponseSchema>;
export type ConntrackEntry = z.infer<typeof ConntrackEntrySchema>;
