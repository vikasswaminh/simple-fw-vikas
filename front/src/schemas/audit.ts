import { z } from 'zod';
import { HttpMethodSchema, TimestampSchema } from './common';

/**
 * Audit logging validation schemas
 */

// Audit log entry
export const AuditEntrySchema = z.object({
  timestamp: TimestampSchema,
  method: HttpMethodSchema,
  endpoint: z.string(),
  user: z.string(),
  source_ip: z.string(),
  status: z.number().int().min(100).max(599),
});

// Audit log (array of entries)
export const AuditLogSchema = z.array(AuditEntrySchema);

// Export types
export type AuditEntry = z.infer<typeof AuditEntrySchema>;
export type AuditLog = z.infer<typeof AuditLogSchema>;
