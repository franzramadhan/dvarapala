/** One sample of the Prometheus text format. */
export type Series = { name: string; labels: Record<string, string>; value: number };

const SPECIAL: Record<string, number> = { NaN: NaN, '+Inf': Infinity, Inf: Infinity, '-Inf': -Infinity };

/** The text exposition format: comments skipped, label escapes (`\"`, `\\`, `\n`) decoded. */
export function parse(text: string): Series[] {
  const out: Series[] = [];
  for (const raw of text.split('\n')) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const brace = line.indexOf('{');
    const space = line.search(/\s/);
    const labels: Record<string, string> = {};
    let name: string;
    let rest: string;
    if (brace >= 0 && (space < 0 || brace < space)) {
      name = line.slice(0, brace);
      let i = brace + 1;
      while (i < line.length && line[i] !== '}') {
        const eq = line.indexOf('=', i);
        if (eq < 0) break;
        const key = line.slice(i, eq).trim();
        let j = eq + 2;
        let v = '';
        while (j < line.length && line[j] !== '"') {
          if (line[j] === '\\') {
            const n = line[j + 1] ?? '';
            v += n === 'n' ? '\n' : n;
            j += 2;
          } else v += line[j++];
        }
        labels[key] = v;
        i = j + 1;
        while (line[i] === ',' || line[i] === ' ') i++;
      }
      rest = line.slice(i + 1);
    } else {
      if (space < 0) continue;
      name = line.slice(0, space);
      rest = line.slice(space);
    }
    const tok = rest.trim().split(/\s+/)[0] ?? '';
    out.push({ name, labels, value: tok in SPECIAL ? (SPECIAL[tok] as number) : Number(tok) });
  }
  return out;
}

/** A stable identity for a series: its name and sorted labels. */
export function seriesKey(s: Series): string {
  const l = Object.keys(s.labels)
    .sort()
    .map((k) => `${k}=${JSON.stringify(s.labels[k])}`)
    .join(',');
  return `${s.name}{${l}}`;
}

const COUNTER = /_(total|count|sum)$/;

/** Per second rates of the counters between two scrapes; a counter that went down restarted from zero. */
export function rates(prev: Series[], cur: Series[], dtSecs: number): Map<string, number> {
  const out = new Map<string, number>();
  if (dtSecs <= 0) return out;
  const before = new Map(prev.map((s) => [seriesKey(s), s.value]));
  for (const s of cur) {
    if (!COUNTER.test(s.name)) continue;
    const k = seriesKey(s);
    const p = before.get(k);
    if (p === undefined) continue;
    out.set(k, (s.value < p ? s.value : s.value - p) / dtSecs);
  }
  return out;
}
