import { describe, expect, it } from 'vitest';
import { parse, rates, seriesKey } from './prom';

// RFC 0021 case 17
describe('prometheus text', () => {
  const text = [
    '# HELP dvarapala_requests_total Requests by verdict.',
    '# TYPE dvarapala_requests_total counter',
    'dvarapala_requests_total{verdict="allow"} 10',
    'dvarapala_route_requests_total{route="a \\"b\\" \\\\c",verdict="drop"} 3 1767225600000',
    'dvarapala_ml_score NaN',
    'dvarapala_waf_inspect_seconds_bucket{le="+Inf"} 7',
    'dvarapala_upstream_healthy{upstream="http://192.0.2.1:80"} 0',
    '',
  ].join('\n');

  it('parses values and labels exactly', () => {
    const s = parse(text);
    expect(s).toHaveLength(5);
    expect(s[0]).toEqual({ name: 'dvarapala_requests_total', labels: { verdict: 'allow' }, value: 10 });
    expect(s[1]?.labels).toEqual({ route: 'a "b" \\c', verdict: 'drop' });
    expect(s[1]?.value).toBe(3);
    expect(Number.isNaN(s[2]?.value)).toBe(true);
    expect(s[3]?.labels.le).toBe('+Inf');
    expect(s[3]?.value).toBe(7);
    expect(s[4]?.labels.upstream).toBe('http://192.0.2.1:80');
  });

  it('computes rates and never a negative one after a reset', () => {
    const a = parse('dvarapala_requests_total{verdict="allow"} 100\ndvarapala_blocks 4');
    const b = parse('dvarapala_requests_total{verdict="allow"} 120\ndvarapala_blocks 1');
    const c = parse('dvarapala_requests_total{verdict="allow"} 5');
    const k = seriesKey(b[0]!);
    expect(rates(a, b, 2).get(k)).toBe(10);
    expect(rates(a, b, 2).has('dvarapala_blocks{}')).toBe(false);
    expect(rates(b, c, 5).get(k)).toBe(1);
  });
});
