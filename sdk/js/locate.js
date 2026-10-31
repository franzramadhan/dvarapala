'use strict';
// RFC 0026: where the N-API addon is. DVARAPALA_NODE, else dvarapala.node
// next to index.js (a checkout or the SDK tarball), else the platform
// package npm installed from optionalDependencies.
const fs = require('node:fs');
const path = require('node:path');

const SUPPORTED = ['linux-x64-gnu', 'linux-arm64-gnu', 'darwin-arm64', 'darwin-x64'];

function platform(os = process.platform, arch = process.arch, glibc = glibcRuntime()) {
  if (os !== 'linux') return `${os}-${arch}`;
  return `${os}-${arch}-${glibc ? 'gnu' : 'musl'}`;
}

function glibcRuntime() {
  if (process.platform !== 'linux') return undefined;
  return process.report?.getReport().header.glibcVersionRuntime;
}

function locate({
  env = process.env,
  dir = __dirname,
  key = platform(),
  exists = fs.existsSync,
  resolve = require.resolve,
} = {}) {
  if (env.DVARAPALA_NODE) return env.DVARAPALA_NODE;
  const local = path.join(dir, 'dvarapala.node');
  if (exists(local)) return local;
  if (!SUPPORTED.includes(key)) {
    throw new Error(
      `dvarapala: no prebuilt addon for ${key}; supported: ${SUPPORTED.join(', ')}. ` +
        'Set DVARAPALA_NODE to an addon built from crates/node.',
    );
  }
  try {
    return resolve(`@dvarapala/${key}/dvarapala.node`);
  } catch {
    throw new Error(
      `dvarapala: the package @dvarapala/${key} is not installed ` +
        '(optional dependencies skipped?); reinstall without --omit=optional or set DVARAPALA_NODE.',
    );
  }
}

module.exports = { locate, platform, SUPPORTED };
