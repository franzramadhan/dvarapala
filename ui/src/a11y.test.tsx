import { describe, expect, it } from 'vitest';
import axe from 'axe-core';
import { fireEvent, screen, waitFor } from '@solidjs/testing-library';
import { mockApi, renderApp } from './test/helpers';

// jsdom cannot compute layout or painted colours, so color-contrast is the one
// rule disabled here. Token contrast is checked separately by ratio (all text
// tokens are at least 5.5:1 on their surfaces in both themes, see app.css).
async function scan(): Promise<string[]> {
  const r = await axe.run(document.documentElement, { rules: { 'color-contrast': { enabled: false } } });
  return r.violations.map((v) => `${v.id}: ${v.help} (${v.nodes.map((n) => n.target.join(' ')).join('; ')})`);
}

const WAF = {
  settings: { enabled: true, mode: 'enforce' },
  mode: 'enforce',
  switch: null,
  rules: [{ rule: 942100, count: 1, last_seen: 1767225600, method: 'GET', path: '/', anomaly_score: 5 }],
  other: 0,
  files: [{ path: '/etc/coraza/coraza.yaml', size: 3, content: 'abc' }],
};

const pages: [string, string, () => Promise<unknown>][] = [
  ['login', '/ui/login', () => screen.findByLabelText('Admin token')],
  ['overview', '/ui/', () => waitFor(() => expect(screen.getByTestId('detection').textContent).toBe('Under attack'))],
  ['top talkers', '/ui/top', () => screen.findByText('198.51.100.0/24')],
  ['blocks', '/ui/blocks', () => screen.findByText('192.0.2.0/24')],
  ['reload', '/ui/reload', () => screen.findByRole('button', { name: 'Reload configuration' })],
  ['config', '/ui/config', () => screen.findByTestId('key-rate_limit.rate')],
  ['waf', '/ui/waf', () => screen.findByText('942100')],
  ['health', '/ui/h/upstreams', () => screen.findByText('ejected')],
];

describe.each(['light', 'dark'])('axe, %s theme', (theme) => {
  it.each(pages)('%s has no violations', async (_name, path, ready) => {
    mockApi({
      'GET /config': () => ({ body: { keys: [{ key: 'rate_limit.rate', value: 50, reload: true, default: false }, { key: 'admin.mode_switch', value: true, reload: false, default: false }] } }),
      'GET /waf': () => ({ body: WAF }),
      'GET /metrics': () => ({ body: 'dvarapala_upstream_healthy{upstream="http://192.0.2.2:80"} 0\n' }),
      'GET /session': () => (path.endsWith('login') ? { status: 401, body: { error: 'no' } } : { body: { subject: 'token', method: 'token', expires_in: 100, csrf: 'c' } }),
    });
    renderApp(path);
    await ready();
    document.documentElement.setAttribute('data-theme', theme);
    expect(await scan()).toEqual([]);
  });

  it('the block dialog has no violations', async () => {
    mockApi();
    renderApp('/ui/top');
    fireEvent.click(await screen.findByRole('button', { name: 'Block 198.51.100.0/24' }));
    await screen.findByRole('dialog');
    document.documentElement.setAttribute('data-theme', theme);
    expect(await scan()).toEqual([]);
  });
});
