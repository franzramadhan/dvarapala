'use strict';
const assert = require('node:assert/strict');
const http = require('node:http');
const net = require('node:net');
const { once } = require('node:events');
const { test } = require('node:test');
const { Guard } = require('..');

async function listen(server) {
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  return server.address().port;
}

test('bad config names the key', () => {
  assert.throws(() => new Guard({ 'rate_limit.rate': 'fast' }), /rate_limit\.rate/);
});

test('throttles over the burst', () => {
  const g = new Guard({ 'rate_limit.rate': 1, 'rate_limit.burst': 1 });
  assert.equal(g.check('192.0.2.1').kind, 'allow');
  const v = g.check('192.0.2.1');
  assert.equal(v.kind, 'throttle');
  assert.ok(v.retryAfterMs > 0 && v.retryAfterMs <= 1000);
});

// RFC 0008 case 12
test('http middleware', async (t) => {
  const mw = new Guard({ 'rate_limit.rate': 1, 'rate_limit.burst': 1 }).middleware();
  const server = http.createServer((req, res) => mw(req, res, () => res.end('ok')));
  const port = await listen(server);
  t.after(() => server.close());
  const first = await fetch(`http://127.0.0.1:${port}/`);
  assert.equal(first.status, 200);
  const second = await fetch(`http://127.0.0.1:${port}/`);
  assert.equal(second.status, 429);
  assert.equal(second.headers.get('retry-after'), '1');
});

// RFC 0008 case 18
test('attach caps connections per client', async (t) => {
  const g = new Guard({ 'l4.max_per_client': 1 });
  const server = g.attach(http.createServer({ keepAlive: true }, (req, res) => res.end('ok')));
  const port = await listen(server);
  t.after(() => server.close());

  const first = net.connect(port, '127.0.0.1');
  t.after(() => first.destroy());
  await once(first, 'connect');
  first.write('GET / HTTP/1.1\r\nHost: x\r\n\r\n');
  const [data] = await once(first, 'data');
  assert.match(data.toString(), /^HTTP\/1\.1 200/);

  const second = net.connect(port, '127.0.0.1');
  const got = [];
  second.on('data', (d) => got.push(d));
  second.on('error', () => {});
  await once(second, 'close');
  assert.equal(got.length, 0);
});
