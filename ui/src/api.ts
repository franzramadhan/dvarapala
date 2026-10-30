import { queryOptions } from '@tanstack/solid-query';
import { recordStatus } from './history';

export type Detection = 'normal' | 'suspect' | 'attack' | 'cooldown' | null;
export type Verdict = 'allow' | 'throttle' | 'challenge' | 'drop' | 'error';
export const VERDICTS: Verdict[] = ['allow', 'throttle', 'challenge', 'drop', 'error'];

export type ReloadOk = { at: number; result: 'ok'; restart: string[] };
export type ReloadFailed = { at: number; result: 'failed'; error: string };
export type Status = {
  version: string;
  mode: 'reverse' | 'forward';
  detection: Detection;
  clients: number;
  blocks: number;
  last_reload: ReloadOk | ReloadFailed | null;
  requests: Record<Verdict, number>;
  /** The WAF's running mode, null when the WAF is off (RFC 0021). */
  waf?: Mode | null;
  switches?: Switch[];
};
export type Mode = 'observe' | 'enforce';
export type Layer = 'detection' | 'waf';
export type Switch = { layer: Layer; mode: Mode; file_mode: Mode; actor: string; at: number };
export type ConfigKey = { key: string; value: unknown; reload: boolean; default: boolean };
export type RuleMatch = { rule: number; count: number; last_seen: number; method: string; path: string; anomaly_score: number | null };
export type RulesFile = { path: string; size?: number; modified?: number | null; content?: string; error?: string };
export type Waf = {
  settings: Record<string, unknown>;
  mode: Mode;
  switch: Switch | null;
  rules: RuleMatch[];
  other: number;
  files: RulesFile[];
};
export type Session = { subject: string; method: 'token' | 'oidc'; expires_in: number; csrf: string };
export type Methods = { token: boolean; oidc: { label: string } | null };
export type Talker = { cidr: string; count: number };
export type Block = { cidr: string; ttl_secs: number };

export class ApiError extends Error {
  constructor(
    readonly status: number,
    message: string,
    readonly body?: unknown,
  ) {
    super(message);
    this.name = 'ApiError';
  }
}

let csrf = '';
let onUnauthorized: () => void = () => {};
export function setUnauthorizedHandler(fn: () => void): void {
  onUnauthorized = fn;
}

type Opts = { method?: string; headers?: Record<string, string>; auth?: boolean; text?: boolean };

async function request<T>(path: string, opts: Opts = {}): Promise<T> {
  const method = opts.method ?? 'GET';
  const headers: Record<string, string> = { Accept: 'application/json', ...opts.headers };
  if (method !== 'GET' && opts.auth !== false) headers['X-Dvarapala-Csrf'] = csrf;
  const res = await fetch(path, { method, headers, credentials: 'same-origin' });
  if (res.status === 204) return undefined as T;
  let body: unknown;
  try {
    body = opts.text && res.ok ? await res.text() : await res.json();
  } catch {
    body = undefined;
  }
  if (!res.ok) {
    const msg = (body as { error?: string } | undefined)?.error ?? `${res.status} ${res.statusText}`.trim();
    // A wrong token at login is a 401 too, but it is not a lost session.
    if (res.status === 401 && opts.auth !== false) onUnauthorized();
    throw new ApiError(res.status, msg, body);
  }
  return body as T;
}

export const getMethods = () => request<Methods>('/session/methods', { auth: false });
export const login = (token: string) =>
  request<void>('/session', { method: 'POST', auth: false, headers: { Authorization: `Bearer ${token}` } });
export const logout = () => request<void>('/session', { method: 'DELETE' });
export async function getSession(quiet = false): Promise<Session> {
  const s = await request<Session>('/session', { auth: !quiet });
  csrf = s.csrf;
  return s;
}
export const getStatus = async () => {
  const s = await request<Status>('/status');
  recordStatus(s);
  return s;
};
export const getTop = () => request<{ top: Talker[] }>('/top').then((r) => r.top);
export const getBlocks = () => request<{ blocks: Block[] }>('/blocks').then((r) => r.blocks);
export const addBlock = (cidr: string, ttl: string) =>
  request<Block>(`/blocks?cidr=${encodeURIComponent(cidr)}&ttl=${encodeURIComponent(ttl)}`, { method: 'POST' });
export const removeBlock = (cidr: string) =>
  request<{ cidr: string }>(`/blocks?cidr=${encodeURIComponent(cidr)}`, { method: 'DELETE' });

/** 200 and 422 both carry a ReloadOk or ReloadFailed body; only other statuses throw. */
export async function reload(): Promise<ReloadOk | ReloadFailed> {
  try {
    return await request<ReloadOk>('/reload', { method: 'POST' });
  } catch (e) {
    if (e instanceof ApiError && e.status === 422) {
      const b = e.body as Partial<ReloadFailed> | undefined;
      return { at: b?.at ?? Math.floor(Date.now() / 1000), result: 'failed', error: b?.error ?? e.message };
    }
    throw e;
  }
}

export const getConfig = () => request<{ keys: ConfigKey[] }>('/config').then((r) => r.keys);
export const getWaf = () => request<Waf>('/waf');
export const getMetricsText = () => request<string>('/metrics', { text: true, headers: { Accept: 'text/plain' } });
export const setMode = (layer: Layer, mode: Mode) =>
  request<{ layer: Layer; mode: Mode; previous: Mode; switch: Switch | null }>(`/mode?layer=${layer}&mode=${mode}`, { method: 'POST' });

// 4xx and 503 (feature off) are answers, not faults: do not retry them.
const retry = (n: number, e: unknown) => !(e instanceof ApiError && (e.status < 500 || e.status === 503)) && n < 2;

export const sessionQuery = () =>
  queryOptions({ queryKey: ['session'], queryFn: () => getSession(), retry: false, staleTime: 60_000, refetchInterval: 300_000 });
export const statusQuery = () =>
  queryOptions({ queryKey: ['status'], queryFn: getStatus, refetchInterval: 2000, retry });
export const topQuery = () => queryOptions({ queryKey: ['top'], queryFn: getTop, refetchInterval: 5000, retry });
export const blocksQuery = () => queryOptions({ queryKey: ['blocks'], queryFn: getBlocks, refetchInterval: 10_000, retry });

export const configQuery = () => queryOptions({ queryKey: ['config'], queryFn: getConfig, retry });
export const wafQuery = () => queryOptions({ queryKey: ['waf'], queryFn: getWaf, refetchInterval: 5000, retry });

export function errMsg(e: unknown): string {
  return e instanceof Error ? e.message : '';
}
