import { For, Show, createMemo } from 'solid-js';
import { VERDICTS, type Verdict } from '../api';
import { WINDOW_SECS, type Sample } from '../history';

function path(points: [number, number][]): string {
  return points.map(([x, y], i) => `${i ? 'L' : 'M'}${x.toFixed(1)} ${y.toFixed(1)}`).join('');
}

/** Tiny line for a KPI card. Decorative: the number beside it carries the value. */
export function Sparkline(props: { values: number[]; verdict?: Verdict }) {
  const d = createMemo(() => {
    const v = props.values;
    if (v.length < 2) return '';
    const max = Math.max(...v, 1e-9);
    return path(v.map((y, i) => [(i / (v.length - 1)) * 100, 28 - (y / max) * 26]));
  });
  return (
    <svg viewBox="0 0 100 30" preserveAspectRatio="none" class="h-8 w-full" aria-hidden="true" data-v={props.verdict ?? 'challenge'}>
      <Show when={d()}>
        <path d={d()} fill="none" class="vstroke" stroke-width="1.5" vector-effect="non-scaling-stroke" />
      </Show>
    </svg>
  );
}

const W = 900;
const H = 180;

function niceMax(v: number): number {
  if (v <= 0) return 1;
  const p = 10 ** Math.floor(Math.log10(v));
  const f = v / p;
  return (f <= 1 ? 1 : f <= 2 ? 2 : f <= 5 ? 5 : 10) * p;
}

/** Requests per second by verdict, stacked, over the last 15 minutes. */
export function StackedArea(props: { samples: Sample[]; label: string }) {
  const model = createMemo(() => {
    const s = props.samples;
    const last = s[s.length - 1];
    if (s.length < 2 || !last) return null;
    const start = last.t - WINDOW_SECS * 1000;
    const totals = s.map((x) => VERDICTS.reduce((n, k) => n + Math.max(0, x[k]), 0));
    const max = niceMax(Math.max(...totals));
    const xs = s.map((x) => ((x.t - start) / (WINDOW_SECS * 1000)) * W);
    const y = (v: number) => H - (v / max) * (H - 4);
    const cum = s.map(() => 0);
    const layers = VERDICTS.map((k) => {
      const bottom = [...cum];
      s.forEach((x, i) => (cum[i] = (cum[i] as number) + Math.max(0, x[k])));
      const top = [...cum];
      const upper = top.map((v, i): [number, number] => [xs[i] as number, y(v)]);
      const lower = bottom.map((v, i): [number, number] => [xs[i] as number, y(v)]).reverse();
      return { k, d: `${path(upper)}L${path(lower).slice(1)}Z` };
    });
    return { max, layers };
  });

  return (
    <div class="relative">
      <Show
        when={model()}
        fallback={<div class="flex h-44 items-center justify-center text-sm text-muted">Collecting samples, one every 2 s.</div>}
      >
        {(m) => (
          <>
            <svg viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="none" class="h-44 w-full" role="img" aria-label={props.label}>
              <line x1="0" x2={W} y1={H} y2={H} class="gridline" />
              <line x1="0" x2={W} y1={H / 2} y2={H / 2} class="gridline" />
              <line x1="0" x2={W} y1="0" y2="0" class="gridline" />
              <For each={m().layers}>{(l) => <path d={l.d} class="vfill" data-v={l.k} />}</For>
            </svg>
            <span class="num pointer-events-none absolute left-1 top-1 rounded bg-surface px-1 text-xs text-muted">
              {m().max}/s
            </span>
          </>
        )}
      </Show>
      <div class="mt-1 flex justify-between text-xs text-muted">
        <span>15 min ago</span>
        <span>now</span>
      </div>
    </div>
  );
}
