/**
 * Formatting utilities
 */

/**
 * Format bytes to human-readable string
 */
export function formatBytes(bytes: number): string {
  if (bytes === 0 || bytes == null) return '0 B';

  const units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
  const k = 1024;
  const i = Math.floor(Math.log(bytes) / Math.log(k));

  return `${(bytes / Math.pow(k, i)).toFixed(i === 0 ? 0 : 1)} ${units[i]}`;
}

/**
 * Format uptime in seconds to human-readable string
 */
export function formatUptime(seconds: number): string {
  if (!seconds) return '—';

  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);

  const parts: string[] = [];
  if (days > 0) parts.push(`${days}d`);
  if (hours > 0) parts.push(`${hours}h`);
  if (minutes > 0 || parts.length === 0) parts.push(`${minutes}m`);

  return parts.join(' ');
}

/**
 * Format timestamp to local string
 */
export function formatTime(timestamp: number | string | Date): string {
  if (!timestamp) return '—';

  const date = typeof timestamp === 'number' ? new Date(timestamp * 1000) : new Date(timestamp);

  if (isNaN(date.getTime())) return String(timestamp);

  return date.toLocaleString();
}

/**
 * Format time ago (e.g., "5 minutes ago")
 */
export function formatTimeAgo(timestamp: number | string | Date): string {
  if (!timestamp) return '—';

  const date = typeof timestamp === 'number' ? new Date(timestamp * 1000) : new Date(timestamp);
  const now = new Date();

  if (isNaN(date.getTime())) return String(timestamp);

  const diffSeconds = Math.floor((now.getTime() - date.getTime()) / 1000);

  if (diffSeconds < 60) return `${diffSeconds}s ago`;
  if (diffSeconds < 3600) return `${Math.floor(diffSeconds / 60)}m ago`;
  if (diffSeconds < 86400) return `${Math.floor(diffSeconds / 3600)}h ago`;
  return `${Math.floor(diffSeconds / 86400)}d ago`;
}

/**
 * Format number with thousands separator
 */
export function formatNumber(num: number): string {
  if (num == null) return '—';
  return num.toLocaleString();
}

/**
 * Format percentage
 */
export function formatPercent(value: number, decimals = 1): string {
  if (value == null) return '—';
  return `${value.toFixed(decimals)}%`;
}

/**
 * Format MAC address (normalize separators)
 */
export function formatMacAddress(mac: string): string {
  if (!mac) return '';
  // Normalize to lowercase with colon separators
  return mac.toLowerCase().replace(/-/g, ':');
}

/**
 * Escape HTML entities
 */
export function escapeHtml(text: string): string {
  if (!text) return '';

  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

/**
 * Truncate text with ellipsis
 */
export function truncate(text: string, maxLength: number): string {
  if (!text || text.length <= maxLength) return text;
  return `${text.slice(0, maxLength - 3)}...`;
}

/**
 * Format file size with appropriate unit
 */
export function formatFileSize(bytes: number): string {
  return formatBytes(bytes);
}

/**
 * Format duration in milliseconds
 */
export function formatDuration(ms: number): string {
  if (ms < 1000) return `${ms}ms`;
  if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`;
  return `${(ms / 60000).toFixed(1)}m`;
}
