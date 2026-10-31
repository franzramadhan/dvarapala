/**
 * Settings by their CONFIG.md names, for example `{ 'rate_limit.rate': 20 }`.
 * `routes` and `forward.destinations` take a list of objects (RFC 0028).
 */
export type Config = Record<string, string | number | boolean | string[] | object[]>;

/** RFC 0028: a request's verdict with the routes applied. */
export interface RequestVerdict extends Verdict {
  /** The matched route's name. */
  route: string | null;
}

export interface RequestInfo {
  ip: string;
  xff?: string | null;
  method: string;
  host?: string | null;
  /** The raw path, without the query. */
  path: string;
  /** Lower-case names; only the ones route keys read are passed on. */
  headers?: Record<string, string | string[] | undefined>;
}

export interface Block {
  cidr: string;
  ttlMs: number;
}

/** `egress` rejects with this when the destination refuses. */
export class EgressRefused extends Error {
  retryAfterMs: number;
}

export interface Verdict {
  kind: 'allow' | 'throttle' | 'drop';
  /** With `throttle`. */
  retryAfterMs: number;
}

export interface Stats {
  allowed: number;
  throttled: number;
  dropped: number;
  clients: number;
  evictions: number;
  /** 0 normal, 1 suspect, 2 attack, 3 cooldown; 0 without detection. */
  detectionState: number;
  rateZscore: number;
  sourceEntropy: number;
}

export interface Conn {
  /** Frees the place; later calls are no-ops. */
  close(): void;
}

interface Request {
  method?: string;
  url?: string;
  headers: Record<string, string | string[] | undefined>;
  socket: { remoteAddress?: string };
}

interface Response {
  writeHead(status: number, headers: Record<string, string>): unknown;
  end(): unknown;
}

interface Server {
  prependListener(event: 'connection', f: (socket: any) => void): unknown;
}

/** Thread-safe guard; throws naming a bad key. */
export class Guard {
  constructor(config?: Config);
  /** The verdict for one request from peer `ip`, with the raw X-Forwarded-For value. */
  check(ip: string, xff?: string | null): Verdict;
  /** Throws on bad input: a field over 8 KiB, a newline in a header value, no method or path. */
  checkRequest(r: RequestInfo): RequestVerdict;
  /** Applies `config` in place; throws naming a key that only applies at creation. */
  reload(config?: Config): void;
  /** `ttlMs` 0 means `admin.max_block_ttl`. */
  block(cidr: string, ttlMs?: number): void;
  /** Throws when `cidr` is not blocked. */
  unblock(cidr: string): void;
  blocks(): Block[];
  /** Resolves when a call to `dest` may go; a wait is spent even if abandoned. */
  egress(dest: string): Promise<void>;
  /** A provider's `Retry-After`, capped by the destination's `max_pause`. */
  egressPause(dest: string, retryAfterMs: number): void;
  stats(): Stats;
  /** Throws with the reason (`blocked`, `total`, `per_client`, `rate`) over an l4 limit. */
  connOpen(ip: string): Conn;
  middleware(): (req: Request, res: Response, next: () => void) => void;
  attach<S extends Server>(server: S): S;
}
