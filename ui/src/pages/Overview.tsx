import { For, Show, createMemo, createSignal, onCleanup } from 'solid-js';
import { Link } from '@tanstack/solid-router';
import { useQuery } from '@tanstack/solid-query';
import { VERDICTS } from '../api';
import { errMsg, statusQuery } from '../api';
import { Sparkline, StackedArea } from '../components/Charts';
import { STATE_LABEL, stateKey } from '../components/Shell';
import { Num, PageHeader } from '../components/Ui';
import { fmtDuration, fmtRate } from '../format';
import { history, stateSince } from '../history';
import { HEALTH, metricsQuery, present } from '../metrics';

const STATE_NOTE: Record<string, string> = {
  normal: 'Traffic is within the learned baseline.',
  suspect: 'Traffic is above baseline. Watching.',
  attack: 'Attack mode is on. Stricter limits apply.',
  cooldown: 'Attack mode is winding down.',
  unknown: 'The gateway does not report a detection state (detection is off).',
};

function Kpi(props: { label: string; children: unknown; chart?: unknown }) {
  return (
    <div class="card flex flex-col gap-1 p-4">
      <span class="label">{props.label}</span>
      <span class="text-2xl font-semibold tracking-tight">{props.children as never}</span>
      {props.chart as never}
    </div>
  );
}

export function OverviewPage() {
  const q = useQuery(() => statusQuery());
  const m = useQuery(() => metricsQuery());
  const layers = () => HEALTH.filter((p) => present(p, m.data)).map((p) => ({ p, h: p.health?.(m.data!) ?? 'ok' }));
  const state = () => stateKey(q.data?.detection);

  const [now, setNow] = createSignal(Date.now());
  const tick = setInterval(() => setNow(Date.now()), 1000);
  onCleanup(() => clearInterval(tick));

  const last = () => history()[history().length - 1];
  const total = (s: ReturnType<typeof last>) => (s ? VERDICTS.reduce((n, k) => n + Math.max(0, s[k]), 0) : 0);
  const totals = createMemo(() => history().map((s) => total(s)));
  const drops = createMemo(() => history().map((s) => s.drop));
  const sentence = () =>
    VERDICTS.map((k) => `${k} ${fmtRate(last()?.[k] ?? 0)}`).join(', ');

  return (
    <div class="space-y-4">
      <PageHeader title="Overview" />
      <Show when={q.isError}>
        <p role="alert" class="field-error">
          Cannot read the gateway status: {errMsg(q.error)}
        </p>
      </Show>

      <section class="card p-5" classList={{ 'attack-card': state() === 'attack' }} aria-label="Detection state">
        <span class="label">Detection</span>
        <p class="state-text mt-1 text-3xl font-bold tracking-tight" data-state={state()} data-testid="detection">
          {STATE_LABEL[state()]}
        </p>
        <p class="mt-1 text-sm text-muted">{STATE_NOTE[state()]}</p>
        <Show when={q.data?.waf}>
          {(w) => (
            <p class="mt-1 text-sm">
              <Link to="/waf" class="hover:underline">
                WAF: {w()}
              </Link>
            </p>
          )}
        </Show>
        <Show when={q.data}>
          <p class="num mt-2 text-xs text-muted">
            In this state for {fmtDuration((now() - stateSince().at) / 1000)}, as observed by this browser.
          </p>
        </Show>
      </section>

      <div class="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <Kpi label="Clients">
          <Num value={q.data?.clients ?? 0} />
        </Kpi>
        <Kpi label="Blocks in force">
          <Link to="/blocks" class="hover:underline">
            <Num value={q.data?.blocks ?? 0} />
          </Link>
        </Kpi>
        <Kpi label="Requests/s" chart={<Sparkline values={totals()} />}>
          <span class="num">{fmtRate(total(last()))}</span>
        </Kpi>
        <Kpi label="Dropped/s" chart={<Sparkline values={drops()} verdict="drop" />}>
          <span class="num">{fmtRate(last()?.drop ?? 0)}</span>
        </Kpi>
      </div>

      <section class="card p-4" aria-labelledby="chart-title">
        <div class="mb-2 flex flex-wrap items-center justify-between gap-2">
          <h2 id="chart-title" class="text-sm font-semibold">
            Requests per second by verdict
          </h2>
          <ul class="flex flex-wrap gap-x-4 gap-y-1 text-xs">
            <For each={VERDICTS}>
              {(k) => (
                <li class="flex items-center gap-1.5" data-v={k}>
                  <span class="vbg inline-block h-2.5 w-2.5 rounded-sm" aria-hidden="true" />
                  <span>{k}</span>
                  <span class="num text-muted">{fmtRate(last()?.[k] ?? 0)}</span>
                </li>
              )}
            </For>
          </ul>
        </div>
        <StackedArea samples={history()} label={`Requests per second by verdict over the last 15 minutes. Now: ${sentence()}.`} />
      </section>

      <Show when={layers().length}>
        <section class="card p-4" aria-labelledby="health-title">
          <h2 id="health-title" class="label mb-2">
            Layers
          </h2>
          <ul class="grid grid-cols-2 gap-x-4 gap-y-1 text-sm sm:grid-cols-3">
            <For each={layers()}>
              {(l) => (
                <li data-testid={`health-${l.p.id}`}>
                  <Link to="/h/$page" params={{ page: l.p.id }} class="hover:underline">
                    {l.p.label}
                  </Link>
                  : <span classList={{ 'text-ok': l.h === 'ok', 'text-warn': l.h === 'degraded', 'text-danger': l.h === 'failing' }}>{l.h}</span>
                </li>
              )}
            </For>
          </ul>
        </section>
      </Show>

      <dl class="grid grid-cols-2 gap-3 text-sm sm:grid-cols-3">
        <div class="card p-3">
          <dt class="label">Version</dt>
          <dd class="num mt-0.5">{q.data?.version ?? '...'}</dd>
        </div>
        <div class="card p-3">
          <dt class="label">Mode</dt>
          <dd class="mt-0.5">{q.data?.mode ?? '...'}</dd>
        </div>
        <div class="card col-span-2 p-3 sm:col-span-1">
          <dt class="label">Last reload</dt>
          <dd class="mt-0.5">
            <Show when={q.data?.last_reload} fallback="Never since start">
              {(r) => (r().result === 'ok' ? 'Applied' : 'Refused')}
            </Show>
          </dd>
        </div>
      </dl>
    </div>
  );
}
