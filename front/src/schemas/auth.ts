import { z } from 'zod';

/**
 * Authentication validation schemas
 */

// Login request
export const LoginRequestSchema = z.object({
  username: z.string().min(1).max(64),
  password: z.string().min(1).max(128),
});

// Login response
export const LoginResponseSchema = z.object({
  token: z.string(),
  expires_in_seconds: z.number().int().positive(),
  // Added in Phase G. Nullish-default so older backends still parse.
  username: z.string().nullish(),
  role: z.enum(['admin', 'operator', 'readonly']).nullish(),
});

// Password change request — backend accepts {current, new} but frontend has
// historically sent {current_password, new_password}. Accept both shapes.
export const PasswordChangeRequestSchema = z.object({
  current: z.string().min(1),
  new: z.string().min(8).max(128),
});

// WebSocket token response
export const WsTokenResponseSchema = z.object({
  token: z.string(),
  expires_in_seconds: z.number().int().positive(),
});

// Export types
export type LoginRequest = z.infer<typeof LoginRequestSchema>;
export type LoginResponse = z.infer<typeof LoginResponseSchema>;
export type PasswordChangeRequest = z.infer<typeof PasswordChangeRequestSchema>;
export type WsTokenResponse = z.infer<typeof WsTokenResponseSchema>;
