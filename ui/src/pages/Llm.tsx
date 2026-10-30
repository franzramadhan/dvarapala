import { For, Show, createSignal } from 'solid-js';
import { useMutation, useQuery, useQueryClient } from '@tanstack/solid-query';
import { configQuery, errMsg, llmQuery, setLlm } from '../api';
import { PageHeader } from '../components/Ui';
import { fmtClock, fmtDuration, fmtInt } from '../format';

const DURATIONS = ['15m', '30m', '1h', '4h', '24h'];
const SECS: Record<string, number> = { '15m': 900, '30m': 1800, '1h': 3600, '4h': 14_400, '24h': 86_400 };

/** `GET /llm/export` for whole UTC days, both ends optional (RFC 0024). */
export function exportHref(since: string, until: string): string {
  const q = new URLSearchParams();
  if (since) q.set('since', `${since}T00:00:00Z`);
  if (until) q.set('until', `${until}T23:59:59.999Z`);
  const s = q.toString();
  return s ? `/llm/export?${s}` : '/llm/export';
}

/** RFC 0023: the sampling switch, labels by trigger and the recent answers. */
export function LlmPage() {
  const qc = useQueryClient();
  const q = useQuery(() => llmQuery());
  const cfg = useQuery(() => configQuery());
  const allowed = () => cfg.data?.find((k) => k.key === 'admin.mode_switch')?.value === true;
  const [dur, setDur] = createSignal('30m');
  const [since, setSince] = createSignal('');
  const [until, setUntil] = createSignal('');
  const run = useMutation(() => ({
    mutationFn: (on: string | null) => setLlm(on),
    onSettled: () => {
      for (const k of ['llm', 'status']) void qc.invalidateQueries({ queryKey: [k] });
    },
  }));
  const choices = () => DURATIONS.filter((d) => (SECS[d] ?? 0) <= (q.data?.max_duration_secs ?? 86_400));
  const left = () => Math.max(0, Math.round(((q.data?.until ?? 0) - Date.now()) / 1000));

  return (
    <div class="space-y-4">
      <PageHeader title="LLM labels" />
      <Show when={q.isError}>
        <p role="alert" class="field-error">
          Cannot read the labels: {errMsg(q.error)}
        </p>
      </Show>
      <Show when={q.data}>
        {(l) => (
          <Show when={l().configured} fallback={<p class="empty">LLM labels are off (<code class="font-mono">ml.llm.endpoint</code> is unset).</p>}>
            <section class="card flex flex-wrap items-center justify-between gap-3 p-4" aria-labelledby="llm-switch">
              <div class="text-sm">
                <h2 id="llm-switch" class="label mb-1">
                  Sampling
                </h2>
                <p data-testid="llm-state">
                  <Show when={l().sampling} fallback="Off">
                    <Show when={l().until} fallback="On (ml.llm.enabled)">
                      On, {fmtDuration(left())} left
                    </Show>
                  </Show>
                </p>
                <p class="mt-1 text-muted">
                  <Show when={allowed()} fallback={<>Switching is off: set <code class="font-mono">admin.mode_switch = true</code> to allow it.</>}>
                    Labels never change a verdict. Sampling stops at the end, on reload and on restart.
                  </Show>
                </p>
                <Show when={run.error}>
                  <p role="alert" class="field-error">
                    {errMsg(run.error)}
                  </p>
                </Show>
              </div>
              <Show when={allowed()}>
                <div class="flex items-center gap-2">
                  <Show
                    when={l().sampling}
                    fallback={
                      <>
                        <label class="sr-only" for="llm-duration">
                          Duration
                        </label>
                        <select id="llm-duration" class="input" value={dur()} onChange={(e) => setDur(e.currentTarget.value)}>
                          <For each={choices()}>{(d) => <option value={d}>{d}</option>}</For>
                        </select>
                        <button type="button" class="btn" disabled={run.isPending} onClick={() => run.mutate(dur())}>
                          Start sampling
                        </button>
                      </>
                    }
                  >
                    <button type="button" class="btn" disabled={run.isPending} onClick={() => run.mutate(null)}>
                      Stop sampling
                    </button>
                  </Show>
                </div>
              </Show>
            </section>
            <section class="card overflow-x-auto" aria-labelledby="llm-counts">
              <h2 id="llm-counts" class="label p-3">
                {l().source === 'store' ? 'Labels, all replicas, last 24 h' : 'Labels, this replica since start'}
              </h2>
              <table class="w-full">
                <thead class="border-b border-line">
                  <tr>
                    <th scope="col" class="th">Label</th>
                    <th scope="col" class="th">Trigger</th>
                    <th scope="col" class="th text-right">Count</th>
                  </tr>
                </thead>
                <tbody>
                  <For each={l().counts} fallback={<tr><td class="td text-muted" colSpan={3}>No labels yet.</td></tr>}>
                    {(c) => (
                      <tr class="border-t border-line">
                        <td class="td font-mono">{c.label}</td>
                        <td class="td font-mono">{c.trigger}</td>
                        <td class="td num text-right">{fmtInt(c.count)}</td>
                      </tr>
                    )}
                  </For>
                </tbody>
              </table>
            </section>
            <section class="card overflow-x-auto" aria-labelledby="llm-recent">
              <h2 id="llm-recent" class="label p-3">
                Recent labels
              </h2>
              <table class="w-full">
                <thead class="border-b border-line">
                  <tr>
                    <th scope="col" class="th">Time</th>
                    <th scope="col" class="th">Trigger</th>
                    <th scope="col" class="th">Request</th>
                    <th scope="col" class="th">Label</th>
                    <th scope="col" class="th text-right">Confidence</th>
                    <th scope="col" class="th">Pattern</th>
                  </tr>
                </thead>
                <tbody>
                  <For each={l().recent}>
                    {(r) => (
                      <tr class="border-t border-line" data-testid="llm-row">
                        <td class="td num text-xs">{fmtClock(Math.floor(r.at / 1000))}</td>
                        <td class="td font-mono">
                          {r.trigger}
                          <Show when={r.route}> ({r.route})</Show>
                        </td>
                        <td class="td break-all font-mono">
                          {r.method} {r.path}
                        </td>
                        <td class="td font-mono">{r.label}</td>
                        <td class="td num text-right">{r.confidence.toFixed(2)}</td>
                        {/* model output: a text node, never markup */}
                        <td class="td break-all text-xs">{r.pattern}</td>
                      </tr>
                    )}
                  </For>
                </tbody>
              </table>
            </section>
            <Show when={l().source === 'store'}>
              <section class="card flex flex-wrap items-end gap-3 p-4" aria-labelledby="llm-export">
                <h2 id="llm-export" class="label w-full">
                  Export (JSON lines, UTC days)
                </h2>
                <label class="text-sm">
                  From <input type="date" class="input" value={since()} onInput={(e) => setSince(e.currentTarget.value)} />
                </label>
                <label class="text-sm">
                  To <input type="date" class="input" value={until()} onInput={(e) => setUntil(e.currentTarget.value)} />
                </label>
                <a class="btn" href={exportHref(since(), until())} download="llm-labels.jsonl">
                  Export
                </a>
              </section>
            </Show>
          </Show>
        )}
      </Show>
    </div>
  );
}
