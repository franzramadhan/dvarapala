// Size budget and stale-dist check. Run after typecheck and tests.
import { readFileSync, mkdtempSync, rmSync, statSync, existsSync, readdirSync } from 'node:fs';
import { gunzipSync } from 'node:zlib';
import { execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const BUDGET = 120 * 1024;
const files = ['index.html', 'app.js', 'app.css'];
let failed = false;

for (const f of files) {
  if (!existsSync(`dist/${f}.gz`)) {
    console.error(`dist/${f}.gz missing: run npm run build`);
    process.exit(1);
  }
}
const extra = readdirSync('dist').filter((f) => !files.map((x) => `${x}.gz`).includes(f));
if (extra.length) {
  console.error(`unexpected files in dist: ${extra.join(', ')}`);
  failed = true;
}

const total = files.reduce((n, f) => n + statSync(`dist/${f}.gz`).size, 0);
console.log(`bundle: ${total} bytes gzip (${(total / 1024).toFixed(1)} KiB of ${BUDGET / 1024} KiB)`);
if (total > BUDGET) {
  console.error(`size budget exceeded by ${total - BUDGET} bytes`);
  failed = true;
}

const tmp = mkdtempSync(join(tmpdir(), 'dvarapala-ui-'));
try {
  execFileSync('npx', ['vite', 'build', '--outDir', tmp, '--emptyOutDir', '--logLevel', 'error'], { stdio: 'inherit' });
  for (const f of files) {
    const fresh = readFileSync(join(tmp, f));
    const kept = gunzipSync(readFileSync(`dist/${f}.gz`));
    if (!fresh.equals(kept)) {
      console.error(`dist/${f}.gz is stale: run npm run build and commit ui/dist`);
      failed = true;
    }
  }
} finally {
  rmSync(tmp, { recursive: true, force: true });
}
if (failed) process.exit(1);
console.log('dist is up to date');
