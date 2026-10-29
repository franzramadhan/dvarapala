// Postbuild: gzip the three bundle files and remove the plain ones.
import { readFileSync, writeFileSync, rmSync, readdirSync } from 'node:fs';
import { gzipSync, constants } from 'node:zlib';
import { join } from 'node:path';

const dir = process.argv[2] ?? 'dist';
const files = ['index.html', 'app.js', 'app.css'];
const present = readdirSync(dir).sort();
const unexpected = present.filter((f) => !files.includes(f));
if (unexpected.length) {
  console.error(`unexpected build output in ${dir}: ${unexpected.join(', ')}`);
  process.exit(1);
}
for (const f of files) {
  const src = join(dir, f);
  // mtime 0 and no filename keep the gzip header stable.
  writeFileSync(`${src}.gz`, gzipSync(readFileSync(src), { level: 9, memLevel: 9, strategy: constants.Z_DEFAULT_STRATEGY }));
  rmSync(src);
}
