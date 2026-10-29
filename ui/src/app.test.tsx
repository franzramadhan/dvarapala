import { describe, expect, it } from 'vitest';
import { fireEvent, screen, waitFor, within } from '@solidjs/testing-library';
import { mockApi, renderApp } from './test/helpers';

describe('Overview', () => {
  it('shows the attack state', async () => {
    mockApi();
    renderApp('/ui/');
    const state = await screen.findByTestId('detection');
    await waitFor(() => expect(state.textContent).toBe('Under attack'));
    expect(screen.getByRole('status', { name: '' }).textContent).toContain('Under attack');
    expect(screen.getByText('1,234')).toBeTruthy();
    expect(document.title).toContain('ATTACK');
  });

  it('shows calm normal state', async () => {
    mockApi({ 'GET /status': () => ({ body: { ...(JSON.parse('{"version":"0.12.0","mode":"forward","clients":0,"blocks":0,"last_reload":null,"requests":{"allow":0,"throttle":0,"challenge":0,"drop":0,"error":0}}')), detection: 'normal' } }) });
    renderApp('/ui/');
    await waitFor(() => expect(screen.getByTestId('detection').textContent).toBe('Normal'));
  });
});

describe('Top talkers', () => {
  it('confirms by name, sends the CSRF header and shows the block', async () => {
    const { calls } = mockApi();
    renderApp('/ui/top');
    fireEvent.click(await screen.findByRole('button', { name: 'Block 198.51.100.0/24' }));

    const dialog = await screen.findByRole('dialog', { name: 'Block 198.51.100.0/24?' });
    expect(within(dialog).getByText('this blocks 256 addresses.')).toBeTruthy();
    fireEvent.click(within(dialog).getByRole('button', { name: '10m' }));
    fireEvent.click(within(dialog).getByRole('button', { name: 'Block 198.51.100.0/24' }));

    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
    const post = calls.find((c) => c.method === 'POST' && c.url.startsWith('/blocks'));
    expect(post?.url).toBe('/blocks?cidr=198.51.100.0%2F24&ttl=10m');
    expect(post?.headers['X-Dvarapala-Csrf']).toBe('abc123');
    expect(await screen.findByText('Blocked')).toBeTruthy();
  });

  it('shows the empty state when the rate limiter is off', async () => {
    mockApi({ 'GET /top': () => ({ status: 503, body: { error: 'rate limiter is off' } }), 'GET /blocks': () => ({ status: 503, body: { error: 'rate limiter is off' } }) });
    renderApp('/ui/top');
    expect(await screen.findByText('Top talkers is not available')).toBeTruthy();
    expect(screen.getByText('rate limiter is off')).toBeTruthy();
  });

  it('filters and sorts', async () => {
    mockApi();
    renderApp('/ui/top');
    await screen.findByText('198.51.100.0/24');
    fireEvent.input(screen.getByLabelText('Filter by network'), { target: { value: '2001' } });
    await waitFor(() => expect(screen.queryByText('198.51.100.0/24')).toBeNull());
    expect(screen.getByText('2001:db8::/32')).toBeTruthy();
  });
});

describe('Blocks', () => {
  it('validates and sizes a CIDR before submit', async () => {
    mockApi();
    renderApp('/ui/blocks');
    const input = await screen.findByLabelText('Block a network');
    const submit = screen.getByRole('button', { name: 'Block...' }) as HTMLButtonElement;
    expect(submit.disabled).toBe(true);
    fireEvent.input(input, { target: { value: '10.0.0.0/16' } });
    expect(await screen.findByText('this blocks 65,536 addresses.')).toBeTruthy();
    expect(submit.disabled).toBe(false);
    fireEvent.input(input, { target: { value: '10.0.0.0/99' } });
    expect(await screen.findByText('Not a valid IPv4 or IPv6 network.')).toBeTruthy();
    expect(submit.disabled).toBe(true);
  });

  it('removes a block after confirmation naming it', async () => {
    const { calls } = mockApi();
    renderApp('/ui/blocks');
    fireEvent.click(await screen.findByRole('button', { name: 'Remove block 192.0.2.0/24' }));
    const dialog = await screen.findByRole('dialog', { name: 'Remove block 192.0.2.0/24?' });
    fireEvent.click(within(dialog).getByRole('button', { name: 'Remove 192.0.2.0/24' }));
    await waitFor(() => expect(screen.queryByText('192.0.2.0/24')).toBeNull());
    const del = calls.find((c) => c.method === 'DELETE' && c.url.startsWith('/blocks'));
    expect(del?.url).toBe('/blocks?cidr=192.0.2.0%2F24');
    expect(del?.headers['X-Dvarapala-Csrf']).toBe('abc123');
  });
});

describe('Reload', () => {
  it('shows the applied result and the restart list', async () => {
    mockApi();
    renderApp('/ui/reload');
    fireEvent.click(await screen.findByRole('button', { name: 'Reload configuration' }));
    expect(await screen.findByText('Applied in place')).toBeTruthy();
    expect(screen.getByText('listen')).toBeTruthy();
  });

  it('shows the error of a failed reload (422)', async () => {
    mockApi({ 'POST /reload': () => ({ status: 422, body: { at: 1767225600, result: 'failed', error: 'l7.rate_limit.window: must be positive' } }) });
    renderApp('/ui/reload');
    fireEvent.click(await screen.findByRole('button', { name: 'Reload configuration' }));
    const alert = await screen.findByRole('alert');
    expect(alert.textContent).toContain('l7.rate_limit.window: must be positive');
  });
});

describe('Session', () => {
  it('goes to login on a 401', async () => {
    mockApi({ 'GET /session': () => ({ status: 401, body: { error: 'no session' } }) });
    const { router } = renderApp('/ui/top');
    expect(await screen.findByRole('heading', { name: 'Sign in to the admin console' })).toBeTruthy();
    expect(router.state.location.pathname).toBe('/login');
  });

  it('goes to login when a call answers 401 mid-session', async () => {
    mockApi({ 'GET /top': () => ({ status: 401, body: { error: 'expired' } }) });
    const { router } = renderApp('/ui/top');
    await waitFor(() => expect(router.state.location.pathname).toBe('/login'));
  });

  it('shows the OIDC error from the redirect and both methods', async () => {
    mockApi({ 'GET /session': () => ({ status: 401, body: { error: 'no session' } }) });
    renderApp('/ui/login?error=access%20denied%20for%20user');
    expect((await screen.findByRole('alert')).textContent).toBe('access denied for user');
    const link = (await screen.findByRole('link', { name: 'Sign in with SSO' })) as HTMLAnchorElement;
    expect(link.getAttribute('href')).toBe('/session/oidc');
    expect(screen.getByLabelText('Admin token')).toBeTruthy();
  });

  it('signs in with a token and rejects a wrong one', async () => {
    let ok = false;
    const { calls } = mockApi({
      'GET /session': () => (ok ? { body: { subject: 'token', method: 'token', expires_in: 100, csrf: 'c' } } : { status: 401, body: { error: 'no session' } }),
      'POST /session': (c) => (c.headers.Authorization === 'Bearer good' ? ((ok = true), { status: 204 }) : { status: 401, body: { error: 'bad token' } }),
    });
    const { router } = renderApp('/ui/login');
    const field = await screen.findByLabelText('Admin token');
    fireEvent.input(field, { target: { value: 'bad' } });
    fireEvent.click(screen.getByRole('button', { name: 'Sign in with token' }));
    expect((await screen.findByRole('alert')).textContent).toBe('That token was not accepted.');
    expect(router.state.location.pathname).toBe('/login');

    fireEvent.input(field, { target: { value: 'good' } });
    fireEvent.click(screen.getByRole('button', { name: 'Sign in with token' }));
    await waitFor(() => expect(router.state.location.pathname).toBe('/'));
    expect(calls.filter((c) => c.method === 'POST' && c.url === '/session')).toHaveLength(2);
  });

  it('signs out', async () => {
    const { calls } = mockApi();
    const { router } = renderApp('/ui/');
    fireEvent.click(await screen.findByRole('button', { name: 'Sign out' }));
    await waitFor(() => expect(router.state.location.pathname).toBe('/login'));
    expect(calls.some((c) => c.method === 'DELETE' && c.url === '/session' && c.headers['X-Dvarapala-Csrf'] === 'abc123')).toBe(true);
  });
});

describe('Shortcuts and theme', () => {
  it('navigates with g then a letter and opens help with ?', async () => {
    mockApi();
    const { router } = renderApp('/ui/');
    await screen.findByTestId('detection');
    fireEvent.keyDown(document, { key: 'g' });
    fireEvent.keyDown(document, { key: 'b' });
    await waitFor(() => expect(router.state.location.pathname).toBe('/blocks'));
    fireEvent.keyDown(document, { key: '?' });
    expect(await screen.findByRole('dialog', { name: 'Keyboard shortcuts' })).toBeTruthy();
    fireEvent.keyDown(screen.getByRole('dialog'), { key: 'Escape' });
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
  });

  it('switches the theme on <html> and saves it', async () => {
    mockApi();
    renderApp('/ui/');
    fireEvent.click(await screen.findByRole('button', { name: 'Dark theme' }));
    expect(document.documentElement.getAttribute('data-theme')).toBe('dark');
    expect(localStorage.getItem('dvarapala-theme')).toBe('dark');
    fireEvent.click(screen.getByRole('button', { name: 'Light theme' }));
    expect(document.documentElement.getAttribute('data-theme')).toBe('light');
  });
});
