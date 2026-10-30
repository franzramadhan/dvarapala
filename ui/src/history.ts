import { createSignal } from 'solid-js';
import type { Detection, Status, Verdict } from './api';

export const WINDOW_SECS = 15 * 60;
export type Sample = { t: number } & Record<Verdict, number>;

const KEYS: Verdict[] = ['allow', 'throttle', 'challenge', 'drop', 'error'];
const [samples, setSamples] = createSignal<Sample[]>([]);
const [since, setSince] = createSignal<{ state: Detection; at: number }>({ state: null, at: Date.now() });
let prev: { t: number; requests: Record<Verdict, number> } | null = null;

/** Rates per second by verdict over the window, oldest first. */
export const history = samples;
/** The detection state and when this browser first saw it. */
export const stateSince = since;

export function resetHistory(): void {
  prev = null;
  setSamples([]);
}

/** Forget everything, including the observed detection state (logout, tests). */
export function resetAll(): void {
  resetHistory();
  setSince({ state: null, at: Date.now() });
}

/** Put the gateway's own samples (`GET /history`) before the ones this tab recorded. */
export function seedHistory(older: Sample[]): void {
  setSamples((old) => {
    const first = old[0]?.t ?? Infinity;
    return [...older.filter((x) => x.t < first), ...old];
  });
}

/** Turn cumulative counters into per-second rates; a drop in any counter means a restart. */
export function recordStatus(s: Status, now = Date.now()): void {
  if (since().state !== s.detection) setSince({ state: s.detection, at: now });
  const cur = s.requests;
  if (prev && KEYS.some((k) => cur[k] < prev!.requests[k])) resetHistory();
  if (prev && now > prev.t) {
    const dt = (now - prev.t) / 1000;
    const p = prev;
    const sample = { t: now } as Sample;
    for (const k of KEYS) sample[k] = (cur[k] - p.requests[k]) / dt;
    const cutoff = now - WINDOW_SECS * 1000;
    setSamples((old) => [...old.filter((x) => x.t >= cutoff), sample]);
  }
  prev = { t: now, requests: { ...cur } };
}
