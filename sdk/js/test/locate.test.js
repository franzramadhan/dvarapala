'use strict';
const assert = require('node:assert/strict');
const path = require('node:path');
const { test } = require('node:test');
const { locate, platform } = require('../locate');

const pkg = (id) => `/n/${id}`;
const none = () => {
  throw new Error('not found');
};

// RFC 0026 case 5
test('lookup order: env, local file, platform package', { skip: 'rfc 0026' }, () => {
  const env = { DVARAPALA_NODE: '/env.node' };
  const local = path.join('/d', 'dvarapala.node');
  const opts = { dir: '/d', key: 'linux-x64-gnu', exists: () => true, resolve: pkg };
  assert.equal(locate({ ...opts, env }), '/env.node');
  assert.equal(locate({ ...opts, env: {} }), local);
  assert.equal(
    locate({ ...opts, env: {}, exists: () => false }),
    '/n/@dvarapala/linux-x64-gnu/dvarapala.node',
  );
});

test('missing platform package says how to fix it', { skip: 'rfc 0026' }, () => {
  const opts = { env: {}, dir: '/d', key: 'darwin-arm64', exists: () => false, resolve: none };
  assert.throws(() => locate(opts), /@dvarapala\/darwin-arm64 is not installed/);
});

// RFC 0026 case 6
test('musl and windows name the platform and the supported ones', { skip: 'rfc 0026' }, () => {
  assert.equal(platform('linux', 'x64', undefined), 'linux-x64-musl');
  assert.equal(platform('linux', 'arm64', '2.28'), 'linux-arm64-gnu');
  for (const key of [platform('linux', 'x64', undefined), platform('win32', 'x64')]) {
    const opts = { env: {}, dir: '/d', key, exists: () => false, resolve: pkg };
    assert.throws(
      () => locate(opts),
      new RegExp(`${key}; supported: linux-x64-gnu, linux-arm64-gnu, darwin-arm64, darwin-x64`),
    );
  }
});
