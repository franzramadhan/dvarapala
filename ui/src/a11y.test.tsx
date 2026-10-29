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

const pages: [string, string, () => Promise<unknown>][] = [
  ['login', '/ui/login', () => screen.findByLabelText('Admin token')],
  ['overview', '/ui/', () => waitFor(() => expect(screen.getByTestId('detection').textContent).toBe('Under attack'))],
  ['top talkers', '/ui/top', () => screen.findByText('198.51.100.0/24')],
  ['blocks', '/ui/blocks', () => screen.findByText('192.0.2.0/24')],
  ['reload', '/ui/reload', () => screen.findByRole('button', { name: 'Reload configuration' })],
];

describe.each(['light', 'dark'])('axe, %s theme', (theme) => {
  it.each(pages)('%s has no violations', async (_name, path, ready) => {
    mockApi({ 'GET /session': () => (path.endsWith('login') ? { status: 401, body: { error: 'no' } } : { body: { subject: 'token', method: 'token', expires_in: 100, csrf: 'c' } }) });
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
