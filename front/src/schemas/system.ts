import { z } from 'zod';
import { HostnameSchema } from './common';

/**
 * System-related validation schemas
 */

// System information response
export const SystemInfoSchema = z.object({
  hostname: HostnameSchema,
  version: z.string(),
  uptime_seconds: z.number().nonnegative(),
  boot_time: z.string(),
  cpu_usage_percent: z.number().min(0).max(100),
  load_avg_1: z.number().nonnegative(),
  load_avg_5: z.number().nonnegative(),
  load_avg_15: z.number().nonnegative(),
  memory_total_mb: z.number().int().positive(),
  memory_used_mb: z.number().int().positive(),
  memory_free_mb: z.number().int().positive(),
  memory_percent: z.number().min(0).max(100),
});

// Traffic snapshot
export const TrafficSnapshotSchema = z.object({
  active_connections: z.number().int().nonnegative(),
  total_rx_bytes: z.number().int().nonnegative(),
  total_tx_bytes: z.number().int().nonnegative(),
  total_rx_packets: z.number().int().nonnegative(),
  total_tx_packets: z.number().int().nonnegative(),
});

// System settings
export const SystemSettingsSchema = z.object({
  hostname: HostnameSchema,
  timezone: z.string(),
  ntp_servers: z.array(z.string()),
  dns_servers: z.array(z.string().ip()),
});

// Export types
export type SystemInfo = z.infer<typeof SystemInfoSchema>;
export type TrafficSnapshot = z.infer<typeof TrafficSnapshotSchema>;
export type SystemSettings = z.infer<typeof SystemSettingsSchema>;
