'use strict';
const assert = require('node:assert/strict');
const { execFileSync } = require('node:child_process');
const path = require('node:path');
const { test } = require('node:test');

test('examples/server.js --demo prints the documented statuses', () => {
  const out = execFileSync(process.execPath, [path.join(__dirname, '../examples/server.js'), '--demo'], {
    encoding: 'utf8',
    timeout: 30000,
  });
  assert.deepEqual(out.trim().split('\n'), [
    '/ 200',
    '/ 200',
    '/ 429 Retry-After: 1',
    '/wp-admin/ 403',
    '192.0.2.1 dropped: true',
  ]);
});
