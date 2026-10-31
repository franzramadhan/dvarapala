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

const LOGIN = [{ name: 'login', path: '=/login', methods: ['POST'], rate: 1, burst: 2 }];

// RFC 0028 cases 15 and 19
test('middleware applies routes and refuses bad input', async (t) => {
  const g = new Guard({ routes: LOGIN });
  let ran = 0;
  const mw = g.middleware();
  const server = http.createServer((req, res) => mw(req, res, () => res.end(String(++ran))));
  const port = await listen(server);
  t.after(() => server.close());
  const post = () => fetch(`http://127.0.0.1:${port}/login`, { method: 'POST' });
  const codes = [];
  for (let i = 0; i < 3; i++) codes.push((await post()).status);
  assert.deepEqual(codes, [200, 200, 429]);
  assert.equal((await post()).headers.get('retry-after'), '1');
  const long = await fetch(`http://127.0.0.1:${port}/${'a'.repeat(9000)}`);
  assert.equal(long.status, 400);
  assert.equal(ran, 2);
});

// RFC 0028: blocks, egress and reload through the wrapper
test('blocks, egress and reload', async () => {
  const stripe = { origin: 'https://api.example.com', name: 'stripe', rate: 10, burst: 1, max_queue: 1, max_wait: '1s' };
  const g = new Guard({ 'forward.destinations': [stripe], routes: LOGIN });
  g.block('192.0.2.0/24', 60_000);
  assert.equal(g.check('192.0.2.9').kind, 'drop');
  assert.equal(g.blocks()[0].cidr, '192.0.2.0/24');
  g.unblock('192.0.2.0/24');
  assert.throws(() => g.unblock('192.0.2.0/24'), /not blocked/);
  await g.egress('stripe');
  const start = Date.now();
  await g.egress('stripe');
  assert.ok(Date.now() - start >= 80);
  g.egressPause('stripe', 2000);
  await assert.rejects(g.egress('stripe'), (e) => e.retryAfterMs > 1000);
  assert.throws(() => g.reload({ 'rate_limit.max_clients': 10 }), /rate_limit\.max_clients/);
  g.reload({ routes: [{ name: 'api', path: '/', key: 'header:x-api-key', rate: 1 }] });
  const v = () => g.checkRequest({ ip: '192.0.2.1', method: 'GET', path: '/', headers: { 'x-api-key': 'a' } });
  assert.deepEqual([v().kind, v().kind, v().route], ['allow', 'throttle', 'api']);
});
