/** Settings by their CONFIG.md names, for example `{ 'rate_limit.rate': 20 }`. */
export type Config = Record<string, string | number | boolean | string[]>;

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
  stats(): Stats;
  /** Throws with the reason (`total`, `per_client`, `rate`) over an l4 limit. */
  connOpen(ip: string): Conn;
  middleware(): (req: Request, res: Response, next: () => void) => void;
  attach<S extends Server>(server: S): S;
}
