import { describe, it, expect } from 'vitest';
import { MasqueradeRuleSchema, SnatRuleSchema, NatConfigSchema } from './nat';

describe('MasqueradeRuleSchema', () => {
  it('accepts a valid rule', () => {
    const r = MasqueradeRuleSchema.parse({
      out_interface: 'eth0',
      source_cidr: '192.168.1.0/24',
    });
    expect(r.out_interface).toBe('eth0');
  });

  it('accepts empty source_cidr (masquerade all)', () => {
    expect(() =>
      MasqueradeRuleSchema.parse({ out_interface: 'eth0', source_cidr: '' }),
    ).not.toThrow();
  });

  it('rejects invalid interface name', () => {
    expect(() =>
      MasqueradeRuleSchema.parse({
        out_interface: 'eth0; drop',
        source_cidr: '192.168.1.0/24',
      }),
    ).toThrow();
  });
});

describe('SnatRuleSchema (Phase C)', () => {
  it('accepts a valid 1:1 rule', () => {
    const r = SnatRuleSchema.parse({
      source_cidr: '10.10.0.0/24',
      to_address: '203.0.113.5',
      out_interface: 'eth0',
    });
    expect(r.source_cidr).toBe('10.10.0.0/24');
    expect(r.to_address).toBe('203.0.113.5');
  });

  it('accepts rule without out_interface', () => {
    const r = SnatRuleSchema.parse({
      source_cidr: '10.10.0.0/24',
      to_address: '203.0.113.5',
    });
    expect(r.out_interface ?? null).toBeNull();
  });

  it('rejects invalid to_address', () => {
    expect(() =>
      SnatRuleSchema.parse({
        source_cidr: '10.10.0.0/24',
        to_address: 'not-an-ip',
      }),
    ).toThrow();
  });

  it('rejects invalid source_cidr', () => {
    expect(() =>
      SnatRuleSchema.parse({
        source_cidr: 'bogus',
        to_address: '203.0.113.5',
      }),
    ).toThrow();
  });
});

describe('NatConfigSchema', () => {
  it('accepts a config with all three rule types', () => {
    const c = NatConfigSchema.parse({
      masquerade: [{ out_interface: 'eth0', source_cidr: '192.168.1.0/24' }],
      port_forward: [
        {
          protocol: 'tcp',
          dest_port: 8080,
          forward_to: '192.168.1.100:80',
          in_interface: 'eth0',
        },
      ],
      snat: [
        {
          source_cidr: '10.10.0.0/24',
          to_address: '203.0.113.5',
          out_interface: 'eth0',
        },
      ],
    });
    expect(c.masquerade).toHaveLength(1);
    expect(c.port_forward).toHaveLength(1);
    expect(c.snat).toHaveLength(1);
  });

  it('rejects port_forward with non-numeric dest_port', () => {
    expect(() =>
      NatConfigSchema.parse({
        masquerade: [],
        snat: [],
        port_forward: [
          {
            protocol: 'tcp',
            dest_port: 'eighty',
            forward_to: '192.168.1.100:80',
            in_interface: 'eth0',
          },
        ],
      }),
    ).toThrow();
  });

  it('rejects port_forward with invalid forward_to format', () => {
    expect(() =>
      NatConfigSchema.parse({
        masquerade: [],
        snat: [],
        port_forward: [
          {
            protocol: 'tcp',
            dest_port: 80,
            forward_to: '192.168.1.100',
            in_interface: 'eth0',
          },
        ],
      }),
    ).toThrow();
  });
});
