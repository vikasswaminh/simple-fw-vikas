import { z } from 'zod';
import { HostnameSchema, TimestampSchema } from './common';

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

// Syslog configuration
export const SyslogConfigSchema = z.object({
  enabled: z.boolean(),
  remote_server: z.string().optional(),
  remote_port: z.number().int().min(1).max(65535).default(514),
  local_logging: z.boolean().default(true),
});

// Config export
export const ConfigExportSchema = z.object({
  exported_at: z.string().datetime(),
  settings: z.record(z.unknown()),
  firewall: z.record(z.unknown()),
  nat: z.record(z.unknown()),
  roles: z.record(z.unknown()),
  routes: z.record(z.unknown()),
});

// Backup info
export const BackupInfoSchema = z.object({
  name: z.string(),
  size: z.number().int().nonnegative(),
  created_at: z.string().datetime().optional(),
});

// Reboot request
export const RebootRequestSchema = z.object({
  confirm_password: z.string().min(1),
});

// Export types
export type SystemInfo = z.infer<typeof SystemInfoSchema>;
export type TrafficSnapshot = z.infer<typeof TrafficSnapshotSchema>;
export type SystemSettings = z.infer<typeof SystemSettingsSchema>;
export type SyslogConfig = z.infer<typeof SyslogConfigSchema>;
export type ConfigExport = z.infer<typeof ConfigExportSchema>;
export type BackupInfo = z.infer<typeof BackupInfoSchema>;
export type RebootRequest = z.infer<typeof RebootRequestSchema>;
