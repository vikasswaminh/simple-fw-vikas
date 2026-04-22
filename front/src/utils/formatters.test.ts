import { describe, it, expect } from 'vitest';
import { escapeHtml } from './formatters';

describe('escapeHtml', () => {
  it('escapes < and >', () => {
    expect(escapeHtml('<script>')).toBe('&lt;script&gt;');
  });

  it('escapes double quotes', () => {
    expect(escapeHtml('foo"bar')).toBe('foo&quot;bar');
  });

  it('escapes ampersands', () => {
    expect(escapeHtml('A & B')).toBe('A &amp; B');
  });

  it('returns empty string for null', () => {
    expect(escapeHtml(null as unknown as string)).toBe('');
  });

  it('returns empty string for undefined', () => {
    expect(escapeHtml(undefined as unknown as string)).toBe('');
  });

  it('returns empty string for empty string', () => {
    expect(escapeHtml('')).toBe('');
  });

  it('handles XSS payload safely', () => {
    const payload = `<img src=x onerror="alert(1)">`;
    const escaped = escapeHtml(payload);
    expect(escaped).not.toContain('<img');
    expect(escaped).toContain('&lt;img');
    expect(escaped).toContain('&quot;');
  });
});
