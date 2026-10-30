import { describe, expect, it } from 'vitest';
import { fireEvent, screen, waitFor, within } from '@solidjs/testing-library';
import { attackStatus, mockApi, renderApp } from './test/helpers';
import type { Switch, Waf } from './api';

const config = {
  keys: [
    { key: 'admin.mode_switch', value: true, reload: false, default: false },
    { key: 'admin.token', value: '<redacted>', reload: false, default: false },
    { key: 'listen', value: '0.0.0.0:8080', reload: false, default: true },
    { key: 'rate_limit.burst', value: 200, reload: true, default: true },
    { key: 'rate_limit.rate', value: 50, reload: true, default: false },
  ],
};

const switched: Switch = { layer: 'waf', mode: 'observe', file_mode: 'enforce', actor: 'alice', at: Math.floor(Date.now() / 1000) - 720 };

const waf: Waf = {
  settings: { enabled: true, mode: 'enforce', endpoint: '127.0.0.1:9000', app: 'default', timeout: '50ms', on_error: 'allow', max_body: 65536, body_limit_action: 'allow' },
  mode: 'observe',
  switch: switched,
  rules: [
    { rule: 942100, count: 5, last_seen: 1767225600, method: 'GET', path: '/a', anomaly_score: 5 },
    { rule: 942200, count: 2, last_seen: 1767225600, method: 'GET', path: '/b', anomaly_score: 5 },
    { rule: 941100, count: 1, last_seen: 1767225600, method: 'POST', path: '/c', anomaly_score: null },
    { rule: 100001, count: 1, last_seen: 1767225600, method: 'GET', path: '/d', anomaly_score: null },
  ],
  other: 0,
  files: [{ path: '/etc/coraza/coraza.yaml', size: 40, modified: 1767225600, content: 'SecRuleRemoveById 920350' }],
};

// RFC 0021 case 18
describe('Config and WAF', () => {
  it('lists non-default keys first and filters', async () => {
    mockApi({ 'GET /config': () => ({ body: config }) });
    renderApp('/ui/config');
    const rows = await screen.findAllByTestId(/^key-rate_limit/);
    expect(rows.map((r) => r.dataset.testid)).toEqual(['key-rate_limit.rate', 'key-rate_limit.burst']);
    expect(screen.getByTestId('key-admin.token').textContent).toContain('<redacted>');
    fireEvent.input(screen.getByLabelText('Filter keys'), { target: { value: 'burst' } });
    await waitFor(() => expect(screen.queryByTestId('key-rate_limit.rate')).toBeNull());
    expect(screen.getByTestId('key-rate_limit.burst')).toBeTruthy();
  });

  it('groups rules by CRS family, shows the switch banner and switches back', async () => {
    const { calls } = mockApi({
      'GET /config': () => ({ body: config }),
      'GET /waf': () => ({ body: waf }),
      'GET /status': () => ({ body: { ...attackStatus, waf: 'observe', switches: [switched] } }),
      'POST /mode': () => ({ body: { layer: 'waf', mode: 'enforce', previous: 'observe', switch: null } }),
    });
    renderApp('/ui/waf');
    const sqli = await screen.findByTestId('family-SQL injection');
    expect(within(sqli).getByText('942100')).toBeTruthy();
    expect(within(sqli).getByText('942200')).toBeTruthy();
    expect(within(screen.getByTestId('family-XSS')).getByText('941100')).toBeTruthy();
    expect(within(screen.getByTestId('family-Custom')).getByText('100001')).toBeTruthy();

    const banner = await screen.findByTestId('switch-waf');
    expect(banner.textContent).toContain('WAF switched to observe by alice 12m');
    expect(banner.textContent).toContain('the file says enforce');

    fireEvent.click(await screen.findByRole('button', { name: 'Switch to enforce' }));
    const dialog = await screen.findByRole('dialog', { name: 'WAF to enforce?' });
    expect(dialog.textContent).toContain("WAF to enforce: the agent's verdicts block requests again.");
    fireEvent.click(within(dialog).getByRole('button', { name: 'Switch to enforce' }));
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
    const post = calls.find((c) => c.method === 'POST' && c.url.startsWith('/mode'));
    expect(post?.url).toBe('/mode?layer=waf&mode=enforce');
    expect(post?.headers['X-Dvarapala-Csrf']).toBe('abc123');
  });

  // regression: the 5 s refetch rebuilt every <details> and closed the one the user opened
  it('keeps a details element as the user left it across a refetch', async () => {
    const { calls } = mockApi({
      'GET /config': () => ({ body: config }),
      'GET /waf': () => ({ body: waf }),
    });
    const { client } = renderApp('/ui/waf');
    const file = (await screen.findByText('/etc/coraza/coraza.yaml')).closest('details')!;
    file.open = true;
    const before = calls.filter((c) => c.url === '/waf').length;
    await client.refetchQueries({ queryKey: ['waf'] });
    await waitFor(() => expect(calls.filter((c) => c.url === '/waf').length).toBeGreaterThan(before));
    expect((await screen.findByText('/etc/coraza/coraza.yaml')).closest('details')!.open).toBe(true);
  });

  it('keeps a config section closed across a refetch', async () => {
    mockApi({ 'GET /config': () => ({ body: config }) });
    const { client } = renderApp('/ui/config');
    const admin = (await screen.findByText('admin', { exact: false, selector: 'summary' })).closest('details')!;
    expect(admin.open).toBe(true);
    admin.open = false;
    await client.refetchQueries({ queryKey: ['config'] });
    expect((await screen.findByText('admin', { exact: false, selector: 'summary' })).closest('details')!.open).toBe(false);
  });
});

const expiry = Math.floor(Date.now() / 1000) + 5 * 86400;
const degraded = [
  'dvarapala_store_up 0',
  'dvarapala_store_replicas 2',
  'dvarapala_upstream_healthy{upstream="http://192.0.2.1:80"} 1',
  'dvarapala_upstream_healthy{upstream="http://192.0.2.2:80"} 0',
  `dvarapala_tls_cert_expiry_timestamp_seconds ${expiry}`,
  'dvarapala_egress_queue{destination="api.example.com"} 3',
].join('\n');

// RFC 0021 case 19
describe('health pages', () => {
  it('shows the store banner, the ejected upstream, the TLS warning and Egress in forward mode', async () => {
    mockApi({
      'GET /metrics': () => ({ body: degraded }),
      'GET /status': () => ({ body: { ...attackStatus, mode: 'forward' } }),
    });
    renderApp('/ui/');
    expect(await screen.findByTestId('store-banner')).toBeTruthy();
    await waitFor(() => expect(screen.getByTestId('health-upstreams').textContent).toContain('degraded'));
    const nav = screen.getByRole('navigation', { name: 'Main' });
    await waitFor(() => expect(within(nav).queryByText('Top talkers')).toBeNull());
    expect(within(nav).queryByText('Blocks')).toBeNull();
    expect(within(nav).getByText('Egress')).toBeTruthy();

    fireEvent.click(within(nav).getByText('Upstreams'));
    const ejected = await screen.findByText('ejected');
    expect(ejected.closest('tr')?.className).toContain('text-danger');
    expect(screen.getByTestId('store-banner')).toBeTruthy();

    fireEvent.click(within(nav).getByText('TLS and QUIC'));
    await waitFor(() => expect(screen.getAllByRole('alert').some((a) => a.textContent?.includes('expires in 4d'))).toBe(true));
  });

  // RFC 0021 case 20
  it('hides the pages of features that export no series', async () => {
    mockApi({ 'GET /metrics': () => ({ body: 'dvarapala_requests_total{verdict="allow"} 1\ndvarapala_upstream_errors_total 0\ndvarapala_limiter_clients 4\n' }) });
    renderApp('/ui/');
    const nav = await screen.findByRole('navigation', { name: 'Main' });
    await waitFor(() => expect(within(nav).getByText('Limiter')).toBeTruthy());
    for (const absent of ['XDP', 'Store', 'Upstreams', 'WAF']) expect(within(nav).queryByText(absent)).toBeNull();
    expect(within(nav).getByText('Top talkers')).toBeTruthy();
  });
});

// RFC 0022 cases 14 and 15
describe('traffic history', () => {
  const now = Date.now();
  const point = (t: number, allow: number) => ({ t, allow, throttle: 0, challenge: 0, drop: 0, error: 0, detection: 'normal' });

  it('draws the history before the first poll', async () => {
    mockApi({
      'GET /history': () => ({ body: { interval_ms: 5000, source: 'memory', samples: [point(now - 10_000, 5), point(now - 5_000, 7)] } }),
    });
    renderApp('/ui/');
    const chart = await screen.findByRole('img', { name: /Requests per second by verdict/ });
    await waitFor(() => expect(chart.querySelector('path')).toBeTruthy());
    expect(screen.queryByLabelText('Range')).toBeNull();
  });

  it('offers longer ranges when the store keeps the history', async () => {
    const { calls } = mockApi({
      'GET /history': (c) => ({
        body: {
          interval_ms: c.url.includes('range=24h') ? 60_000 : 5000,
          source: 'store',
          samples: [point(now - 3_600_000, 3), point(now - 60_000, 4)],
        },
      }),
    });
    renderApp('/ui/');
    const range = await screen.findByLabelText('Range');
    fireEvent.change(range, { target: { value: '24h' } });
    await waitFor(() => expect(calls.some((c) => c.url === '/history?range=24h')).toBe(true));
    expect(await screen.findByRole('img', { name: /over the last 24 hours/ })).toBeTruthy();
  });
});
