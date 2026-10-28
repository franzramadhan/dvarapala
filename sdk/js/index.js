'use strict';
// The dvarapala engine in process (RFC 0008), over the N-API addon from
// crates/node. DVARAPALA_NODE overrides the addon path.
const path = require('node:path');

const addon = { exports: {} };
process.dlopen(addon, process.env.DVARAPALA_NODE || path.join(__dirname, 'dvarapala.node'));
const native = addon.exports;

const KINDS = ['allow', 'throttle', 'drop'];

function text(v) {
  return Array.isArray(v) ? v.join(',') : String(v);
}

class Guard {
  #g;

  constructor(config = {}) {
    this.#g = new native.Guard(
      Object.fromEntries(Object.entries(config).map(([k, v]) => [k, text(v)])),
    );
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

  // node:http or Express-style middleware: 429 with Retry-After (seconds,
  // rounded up, at least 1) or 403 with Connection: close, as the gateway.
  middleware() {
    return (req, res, next) => {
      const xff = req.headers['x-forwarded-for'];
      let v;
      try {
        v = this.check(req.socket.remoteAddress ?? '', Array.isArray(xff) ? xff.join(', ') : xff);
      } catch {
        // fail closed: no peer address or a bad one
        v = { kind: 'drop' };
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

module.exports = { Guard };
