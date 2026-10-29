import { describe, expect, it } from 'vitest';
import { blockImpact, parseCidr } from './cidr';
import { fmtDuration, parseTtl } from './format';

describe('parseCidr', () => {
  it('counts IPv4 addresses', () => {
    expect(parseCidr('192.0.2.0/24')?.size).toBe('256 addresses');
    expect(parseCidr('10.0.0.0/16')?.size).toBe('65,536 addresses');
    expect(parseCidr('192.0.2.7/32')?.size).toBe('1 address');
    expect(parseCidr('192.0.2.7')?.prefix).toBe(32);
    expect(parseCidr('0.0.0.0/0')?.size).toBe('4,294,967,296 addresses');
  });
  it('words the impact', () => {
    expect(blockImpact(parseCidr('10.0.0.0/16')!)).toBe('this blocks 65,536 addresses');
    expect(blockImpact(parseCidr('192.0.2.1/32')!)).toBe('this blocks 1 address');
  });
  it('shows IPv6 sizes as powers of two', () => {
    expect(parseCidr('2001:db8::/32')?.size).toBe('2^96 addresses');
    expect(parseCidr('2001:db8::/64')?.size).toBe('2^64 addresses');
    expect(parseCidr('2001:db8::/120')?.size).toBe('256 addresses');
    expect(parseCidr('2001:db8::1/128')?.size).toBe('1 address');
  });
  it('flags huge ranges', () => {
    expect(parseCidr('10.0.0.0/8')?.huge).toBe(true);
    expect(parseCidr('10.0.0.0/16')?.huge).toBe(false);
    expect(parseCidr('2001:db8::/32')?.huge).toBe(true);
  });
  it.each(['', 'abc', '192.0.2.0/33', '256.0.0.1', '1.2.3', '1.2.3.4/', '1.2.3.4/8/8', '2001:db8::/129', '2001:::1', '1:2:3:4:5:6:7:8:9', '12345::1', '2001:db8::zz'])(
    'rejects %j',
    (s) => expect(parseCidr(s)).toBeNull(),
  );
  it.each(['::/0', '::1', '2001:db8::1/64', '1:2:3:4:5:6:7:8', '::ffff:192.0.2.1'])('accepts %s', (s) => expect(parseCidr(s)).not.toBeNull());
});

describe('format', () => {
  it('parses a TTL', () => {
    expect(parseTtl('10m')).toBe(600);
    expect(parseTtl('90s')).toBe(90);
    expect(parseTtl('24h')).toBe(86400);
    expect(parseTtl('0m')).toBeNull();
    expect(parseTtl('10')).toBeNull();
    expect(parseTtl('1x')).toBeNull();
  });
  it('formats durations', () => {
    expect(fmtDuration(45)).toBe('45s');
    expect(fmtDuration(90)).toBe('1m 30s');
    expect(fmtDuration(3700)).toBe('1h 01m');
    expect(fmtDuration(90000)).toBe('1d 1h');
  });
});
