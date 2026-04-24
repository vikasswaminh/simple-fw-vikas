import { describe, it, expect } from 'vitest';
import {
  FirewallRuleSchema,
  FirewallConfigSchema,
  NftPreviewSchema,
} from './firewall';

describe('FirewallRuleSchema', () => {
  it('accepts a minimal rule with defaults', () => {
    const r = FirewallRuleSchema.parse({ name: 'allow-ssh' });
    expect(r.enabled).toBe(true);
    expect(r.direction).toBe('forward');
    expect(r.action).toBe('accept');
    expect(r.protocol).toBe('any');
    expect(r.log).toBe(false);
    expect(r.ipv6).toBe(false);
  });

  it('rejects empty name', () => {
    expect(() => FirewallRuleSchema.parse({ name: '' })).toThrow();
  });

  it('rejects name > 64 chars', () => {
    const longName = 'a'.repeat(65);
    expect(() => FirewallRuleSchema.parse({ name: longName })).toThrow();
  });

  it('rejects invalid action', () => {
    expect(() => FirewallRuleSchema.parse({ name: 'r', action: 'bogus' })).toThrow();
  });

  it('accepts all four valid actions', () => {
    for (const a of ['accept', 'drop', 'reject', 'log']) {
      const r = FirewallRuleSchema.parse({ name: 'r', action: a });
      expect(r.action).toBe(a);
    }
  });

  it('treats Rust null as optional (nullish)', () => {
    // Rust serializes Option::None as JSON null — Zod .nullish() must accept it.
    const r = FirewallRuleSchema.parse({
      name: 'r',
      src_ip: null,
      dst_ip: null,
      src_port: null,
      dst_port: null,
      comment: null,
      schedule: null,
    });
    expect(r.src_ip).toBeNull();
    expect(r.dst_ip).toBeNull();
    expect(r.comment).toBeNull();
  });

  it('accepts "any" as src/dst literal alongside CIDRs', () => {
    expect(() =>
      FirewallRuleSchema.parse({ name: 'r', src_ip: 'any', dst_ip: 'any' }),
    ).not.toThrow();
  });

  it('rejects schedule with invalid time format', () => {
    expect(() =>
      FirewallRuleSchema.parse({
        name: 'r',
        schedule: { days: ['mon'], start: '25:99', end: '09:00' },
      }),
    ).toThrow();
  });
});

describe('FirewallConfigSchema', () => {
  it('accepts an empty config with defaults', () => {
    const c = FirewallConfigSchema.parse({ rules: [], zones: [] });
    expect(c.forward_policy).toBe('drop');
    expect(c.input_policy).toBe('drop');
    expect(c.output_policy).toBe('accept');
  });

  it('rejects a zone with an invalid interface name', () => {
    expect(() =>
      FirewallConfigSchema.parse({
        rules: [],
        zones: [{ interface: 'eth0; drop', zone: 'lan' }],
      }),
    ).toThrow();
  });

  it('rejects a zone with a zone name > 32 chars', () => {
    expect(() =>
      FirewallConfigSchema.parse({
        rules: [],
        zones: [{ interface: 'eth0', zone: 'z'.repeat(33) }],
      }),
    ).toThrow();
  });
});

describe('NftPreviewSchema', () => {
  it('accepts a well-formed preview response', () => {
    const p = NftPreviewSchema.parse({
      dry_run: true,
      nft_script: 'add rule ...',
      rule_count: 3,
    });
    expect(p.rule_count).toBe(3);
    expect(p.dry_run).toBe(true);
  });

  it('rejects negative rule_count', () => {
    expect(() =>
      NftPreviewSchema.parse({ dry_run: true, nft_script: '', rule_count: -1 }),
    ).toThrow();
  });
});
