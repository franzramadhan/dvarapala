import { queryOptions } from '@tanstack/solid-query';
import { ApiError, getMetricsText } from './api';
import { parse, rates, seriesKey, type Series } from './prom';

export type Scrape = { at: number; series: Series[]; rates: Map<string, number> };

// ponytail: rates over the last poll only, no 15 minute history; charts can keep one when they need it
let prev: { at: number; series: Series[] } | null = null;

export async function scrape(now = Date.now()): Promise<Scrape> {
  const series = parse(await getMetricsText());
  const r = prev ? rates(prev.series, series, (now - prev.at) / 1000) : new Map<string, number>();
  prev = { at: now, series };
  return { at: now, series, rates: r };
}

export function resetScrape(): void {
  prev = null;
}

const retry = (n: number, e: unknown) => !(e instanceof ApiError && e.status < 500) && n < 2;
export const metricsQuery = () => queryOptions({ queryKey: ['metrics'], queryFn: () => scrape(), refetchInterval: 5000, retry });

export type Health = 'ok' | 'degraded' | 'failing';
export type HealthPage = {
  id: string;
  label: string;
  rfc: string;
  /** Series that make the page exist; a page shows every series with these prefixes. */
  prefixes: string[];
  /** When set, only this series makes the page exist. */
  marker?: string;
  health?: (m: Scrape) => Health;
};

const values = (m: Scrape, name: string) => m.series.filter((s) => s.name === name);

/** Seconds until the served certificate expires, the soonest one. */
export function certSecs(m: Scrape): number | null {
  const v = values(m, 'dvarapala_tls_cert_expiry_timestamp_seconds').map((s) => s.value);
  return v.length ? Math.min(...v) - m.at / 1000 : null;
}
export const CERT_WARN_SECS = 14 * 86400;

export const storeDown = (m: Scrape | undefined) => !!m && values(m, 'dvarapala_store_up').some((s) => s.value === 0);

export const HEALTH: HealthPage[] = [
  {
    id: 'upstreams',
    label: 'Upstreams',
    rfc: '0015',
    prefixes: ['dvarapala_upstream_'],
    marker: 'dvarapala_upstream_healthy',
    health: (m) => {
      const h = values(m, 'dvarapala_upstream_healthy');
      const down = h.filter((s) => s.value === 0).length;
      return down === 0 ? 'ok' : down === h.length ? 'failing' : 'degraded';
    },
  },
  { id: 'store', label: 'Store', rfc: '0010', prefixes: ['dvarapala_store_'], health: (m) => (storeDown(m) ? 'failing' : 'ok') },
  { id: 'routes', label: 'Routes', rfc: '0013', prefixes: ['dvarapala_route_'] },
  { id: 'detection', label: 'Detection', rfc: '0002', prefixes: ['dvarapala_detection_', 'dvarapala_ml_'] },
  {
    id: 'challenge',
    label: 'Challenge and JA4',
    rfc: '0012',
    prefixes: ['dvarapala_challenges_total', 'dvarapala_fingerprint_matches_total', 'dvarapala_tls_ja4_total'],
  },
  { id: 'xdp', label: 'XDP', rfc: '0011', prefixes: ['dvarapala_xdp_'] },
  {
    id: 'tls',
    label: 'TLS and QUIC',
    rfc: '0003',
    prefixes: ['dvarapala_tls_', 'dvarapala_quic_'],
    health: (m) => {
      const s = certSecs(m);
      return s === null || s > CERT_WARN_SECS ? 'ok' : s > 0 ? 'degraded' : 'failing';
    },
  },
  {
    id: 'tunnels',
    label: 'Tunnels',
    rfc: '0005',
    prefixes: ['dvarapala_tunnel', 'dvarapala_grpc_local_responses_total', 'dvarapala_http2_goaway_total'],
  },
  { id: 'egress', label: 'Egress', rfc: '0007', prefixes: ['dvarapala_egress_'] },
  { id: 'limiter', label: 'Limiter', rfc: '0001', prefixes: ['dvarapala_limiter_', 'dvarapala_blocks'] },
];

export const pageSeries = (p: HealthPage, m: Scrape) =>
  m.series.filter((s) => !s.name.endsWith('_bucket') && p.prefixes.some((x) => s.name.startsWith(x)));

export const present = (p: HealthPage, m: Scrape | undefined) =>
  !!m && (p.marker ? m.series.some((s) => s.name === p.marker) : pageSeries(p, m).length > 0);

export const rateOf = (m: Scrape, s: Series) => m.rates.get(seriesKey(s));
