'use strict';
// A node:http server behind a dvarapala guard, with no other dependency.
//
//   node examples/server.js           # serve on 127.0.0.1:8080
//   node examples/server.js --demo    # serve on a free port, send five requests, exit
//
// The guard has a per-client limit, a deny route for scanners and a manual
// block. The demo prints the status of each request:
//
//   / 200
//   / 200
//   / 429 Retry-After: 1
//   /wp-admin/ 403
//   192.0.2.1 dropped: true
const http = require('node:http');
const { once } = require('node:events');
const { Guard } = require('..'); // in your app: require('dvarapala')

const guard = new Guard({
  'rate_limit.rate': 1,
  'rate_limit.burst': 2,
  // JavaScript takes routes as a list of objects
  routes: [{ name: 'probes', path: '/wp-admin', deny: true }],
});
const mw = guard.middleware();
const server = http.createServer((req, res) => mw(req, res, () => res.end('ok')));
// the l4 connection limits, before any request is read
guard.attach(server);

async function demo(port) {
  for (const path of ['/', '/', '/', '/wp-admin/']) {
    const res = await fetch(`http://127.0.0.1:${port}${path}`);
    const ra = res.headers.get('retry-after');
    console.log(path, res.status, ...(ra ? ['Retry-After:', ra] : []));
  }
  // every check drops a blocked client until the block expires
  guard.block('192.0.2.0/24', 3600 * 1000);
  console.log('192.0.2.1 dropped:', guard.check('192.0.2.1').kind === 'drop');
}

async function main() {
  const runDemo = process.argv.includes('--demo');
  server.listen(runDemo ? 0 : 8080, '127.0.0.1');
  await once(server, 'listening');
  if (!runDemo) return;
  await demo(server.address().port);
  server.closeAllConnections();
  server.close();
}

main();
