import { vi } from 'vitest';
import { render } from '@solidjs/testing-library';
import { createMemoryHistory } from '@tanstack/solid-router';
import { App, createQueryClient } from '../App';
import { createAppRouter } from '../router';
import type { Block, Status } from '../api';

export type Call = { method: string; url: string; headers: Record<string, string> };
type Reply = { status?: number; body?: unknown };
type Handler = (call: Call) => Reply;

export const attackStatus: Status = {
  version: '0.12.0',
  mode: 'reverse',
  detection: 'attack',
  clients: 1234,
  blocks: 1,
  last_reload: null,
  requests: { allow: 1000, throttle: 50, challenge: 20, drop: 400, error: 1 },
};

/** Mocked API. `overrides` replace a route; keys look like "GET /status". */
export function mockApi(overrides: Record<string, Handler> = {}) {
  const calls: Call[] = [];
  const blocks: Block[] = [{ cidr: '192.0.2.0/24', ttl_secs: 600 }];
  const routes: Record<string, Handler> = {
    'GET /session/methods': () => ({ body: { token: true, oidc: { label: 'SSO' } } }),
    'GET /session': () => ({ body: { subject: 'token', method: 'token', expires_in: 28800, csrf: 'abc123' } }),
    'POST /session': () => ({ status: 204 }),
    'DELETE /session': () => ({ status: 204 }),
    'GET /status': () => ({ body: attackStatus }),
    'GET /top': () => ({
      body: { top: [{ cidr: '198.51.100.0/24', count: 9000 }, { cidr: '203.0.113.0/24', count: 1000 }, { cidr: '2001:db8::/32', count: 500 }] },
    }),
    'GET /blocks': () => ({ body: { blocks } }),
    'POST /blocks': (c) => {
      const u = new URL(c.url, 'http://x');
      blocks.push({ cidr: u.searchParams.get('cidr') ?? '', ttl_secs: 3600 });
      return { body: { cidr: u.searchParams.get('cidr'), ttl_secs: 3600 } };
    },
    'DELETE /blocks': (c) => {
      const cidr = new URL(c.url, 'http://x').searchParams.get('cidr');
      const i = blocks.findIndex((b) => b.cidr === cidr);
      if (i < 0) return { status: 404, body: { error: 'not blocked' } };
      blocks.splice(i, 1);
      return { body: { cidr } };
    },
    'POST /reload': () => ({ body: { at: 1767225600, result: 'ok', restart: ['listen'] } }),
    ...overrides,
  };
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: string, init: RequestInit = {}) => {
      const call: Call = { method: init.method ?? 'GET', url, headers: (init.headers ?? {}) as Record<string, string> };
      calls.push(call);
      const path = url.split('?')[0];
      const h = routes[`${call.method} ${path}`];
      if (!h) return new Response(JSON.stringify({ error: 'no route' }), { status: 500 });
      const r = h(call);
      const status = r.status ?? 200;
      return new Response(status === 204 ? null : JSON.stringify(r.body ?? {}), { status, statusText: '' });
    }),
  );
  return { calls, blocks };
}

export function renderApp(path = '/ui/') {
  const client = createQueryClient(false);
  const router = createAppRouter(createMemoryHistory({ initialEntries: [path] }));
  const view = render(() => <App router={router} client={client} />);
  return { router, client, ...view };
}
