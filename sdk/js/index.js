'use strict';
// The dvarapala engine in process (RFC 0008), over the N-API addon from
// crates/node. DVARAPALA_NODE overrides the addon path (RFC 0026).
const { locate } = require('./locate');

const addon = { exports: {} };
process.dlopen(addon, locate());
const native = addon.exports;

const KINDS = ['allow', 'throttle', 'drop'];
// RFC 0028: list-shaped keys take JSON
const JSON_KEYS = new Set(['routes', 'forward.destinations']);

function text(k, v) {
  if (JSON_KEYS.has(k) && typeof v !== 'string') return JSON.stringify(v);
  return Array.isArray(v) ? v.join(',') : String(v);
}

function settings(config) {
  return Object.fromEntries(Object.entries(config).map(([k, v]) => [k, text(k, v)]));
}

// A `wait` slot is spent once handed out; `egress` throws this when the
// destination refuses.
class EgressRefused extends Error {
  constructor(dest, retryAfterMs) {
    super(`egress to ${dest} refused, retry after ${retryAfterMs} ms`);
    this.retryAfterMs = retryAfterMs;
  }
}

class Guard {
  #g;
  #headers;

  constructor(config = {}) {
    this.#g = new native.Guard(settings(config));
    this.#headers = this.#names();
  }

  // RFC 0028: applies `config` in place, keeping counts, blocks and queues.
  reload(config = {}) {
    this.#g.reload(settings(config));
    this.#headers = this.#names();
  }

  #names() {
    return this.#g.routeHeaders().split(',').filter(Boolean);
  }

  // The verdict with the routes applied; `headers` maps lower-case names to
  // values. Throws on bad input.
  checkRequest({ ip, xff, method, host, path, headers = {} }) {
    const lines = this.#headers
      .filter((n) => headers[n] !== undefined)
      .map((n) => `${n}: ${[headers[n]].flat()[0]}\n`)
      .join('');
    const v = this.#g.checkRequest(ip, xff ?? undefined, method, host ?? undefined, path, lines || undefined);
    return { kind: KINDS[v.kind], retryAfterMs: v.retryAfterMs, route: v.route ?? null };
  }

  block(cidr, ttlMs = 0) {
    this.#g.block(cidr, ttlMs);
  }

  unblock(cidr) {
    this.#g.unblock(cidr);
  }

  blocks() {
    return JSON.parse(this.#g.blocks()).map((b) => ({ cidr: b.cidr, ttlMs: b.ttl_ms }));
  }

  // Resolves when a call to `dest` may go; rejects with EgressRefused.
  async egress(dest) {
    const s = this.#g.egress(dest);
    if (s.kind === 2) throw new EgressRefused(dest, s.ms);
    if (s.kind === 1) await new Promise((r) => setTimeout(r, s.ms));
  }

  egressPause(dest, retryAfterMs) {
    this.#g.egressPause(dest, retryAfterMs);
  }

  check(ip, xff) {
    const v = this.#g.check(ip, xff ?? undefined);
    return { kind: KINDS[v.kind], retryAfterMs: v.retryAfterMs };
  }

  stats() {
    return this.#g.stats();
  }

  connOpen(ip) {
    return this.#g.connOpen(ip);
  }

  // node:http or Express-style middleware with the routes applied: 429
  // with Retry-After (seconds, rounded up, at least 1) or 403 with
  // Connection: close, as the gateway. Bad input is a 400 that closes.
  // One guard per process: behind `cluster` or replicas, divide the rates.
  middleware() {
    return (req, res, next) => {
      const xff = req.headers['x-forwarded-for'];
      let v;
      try {
        v = this.checkRequest({
          ip: req.socket.remoteAddress ?? '',
          xff: Array.isArray(xff) ? xff.join(', ') : xff,
          method: req.method ?? '',
          host: req.headers[':authority'] ?? req.headers.host,
          path: (req.url ?? '').split('?')[0],
          headers: req.headers,
        });
      } catch {
        // fail closed: never let bad input through
        res.writeHead(400, { Connection: 'close' });
        res.end();
        return;
      }
      if (v.kind === 'throttle') {
        res.writeHead(429, { 'Retry-After': String(Math.max(Math.ceil(v.retryAfterMs / 1000), 1)) });
        res.end();
      } else if (v.kind === 'drop') {
        res.writeHead(403, { Connection: 'close' });
        res.end();
      } else {
        next();
      }
    };
  }

  // l4.* connection limits on a net or http server: a refused socket is
  // destroyed before the server reads it, 'close' frees the place.
  attach(server) {
    server.prependListener('connection', (socket) => {
      let conn;
      try {
        conn = this.connOpen(socket.remoteAddress ?? '');
      } catch {
        socket.destroy();
        return;
      }
      socket.once('close', () => conn.close());
    });
    return server;
  }
}

module.exports = { Guard, EgressRefused };
