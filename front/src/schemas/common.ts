import { z } from 'zod';

/**
 * Common validation schemas used across the application
 */

// IPv4 Address validation
export const IpAddressSchema = z
  .string()
  .regex(
    /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/,
    'Invalid IPv4 address'
  );

// IPv6 Address validation (simplified)
export const Ipv6AddressSchema = z
  .string()
  .regex(
    /^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::1$|^::$/,
    'Invalid IPv6 address'
  );

// CIDR notation validation (IPv4)
export const CidrSchema = z
  .string()
  .regex(
    /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\/(?:[0-9]|[1-2][0-9]|3[0-2])$/,
    'Invalid CIDR notation (e.g., 192.168.1.0/24)'
  );

// Port number validation (1-65535)
export const PortSchema = z.number().int().min(1).max(65535);

// Port range string validation (e.g., "80,443,8080-8090")
export const PortRangeSchema = z
  .string()
  .regex(
    /^(\d{1,5})(-\d{1,5})?(,(\d{1,5})(-\d{1,5})?)*$/,
    'Invalid port or port range (e.g., 80,443,8080-8090)'
  )
  .refine(
    value => {
      const parts = value.split(',');
      return parts.every(part => {
        if (part.includes('-')) {
          const [start, end] = part.split('-').map(Number);
          return start >= 1 && start <= 65535 && end >= 1 && end <= 65535 && start <= end;
        }
        const port = Number(part);
        return port >= 1 && port <= 65535;
      });
    },
    'Port numbers must be between 1 and 65535'
  );

// Network interface name validation
export const InterfaceNameSchema = z
  .string()
  .regex(
    /^[a-zA-Z0-9._-]{1,15}$/,
    'Interface name must be 1-15 alphanumeric characters, dots, underscores, or hyphens'
  );

// MAC address validation
export const MacAddressSchema = z
  .string()
  .regex(
    /^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$/,
    'Invalid MAC address format (e.g., aa:bb:cc:dd:ee:ff)'
  );

// Hostname validation
export const HostnameSchema = z
  .string()
  .min(1)
  .max(64)
  .regex(
    /^[a-zA-Z0-9][a-zA-Z0-9.-]*$/,
    'Hostname must start with alphanumeric and contain only letters, numbers, dots, and hyphens'
  );

// Domain name validation
export const DomainNameSchema = z
  .string()
  .min(1)
  .max(253)
  .regex(
    /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$/,
    'Invalid domain name'
  );

// Timestamp in seconds
export const TimestampSchema = z.number().int().positive();

// Pagination parameters
export const PaginationSchema = z.object({
  page: z.number().int().min(0).default(0),
  pageSize: z.number().int().min(1).max(1000).default(100),
});

// API Response wrapper factory
export const ApiResponseSchema = <T extends z.ZodType>(dataSchema: T) =>
  z.object({
    success: z.boolean(),
    data: dataSchema.optional(),
    error: z.string().optional(),
    message: z.string().optional(),
  });

// HTTP Method enum
export const HttpMethodSchema = z.enum(['GET', 'POST', 'PUT', 'DELETE', 'PATCH']);

// Generic ID parameter
export const IdParamSchema = z.union([z.string(), z.number()]);

// Time string (HH:MM)
export const TimeStringSchema = z
  .string()
  .regex(/^([01]?[0-9]|2[0-3]):[0-5][0-9]$/, 'Invalid time format (HH:MM)');

// Day of week
export const DayOfWeekSchema = z.enum(['mon', 'tue', 'wed', 'thu', 'fri', 'sat', 'sun']);

// Export types
export type IpAddress = z.infer<typeof IpAddressSchema>;
export type Ipv6Address = z.infer<typeof Ipv6AddressSchema>;
export type Cidr = z.infer<typeof CidrSchema>;
export type Port = z.infer<typeof PortSchema>;
export type PortRange = z.infer<typeof PortRangeSchema>;
export type InterfaceName = z.infer<typeof InterfaceNameSchema>;
export type MacAddress = z.infer<typeof MacAddressSchema>;
export type Hostname = z.infer<typeof HostnameSchema>;
export type DomainName = z.infer<typeof DomainNameSchema>;
export type HttpMethod = z.infer<typeof HttpMethodSchema>;
export type DayOfWeek = z.infer<typeof DayOfWeekSchema>;
