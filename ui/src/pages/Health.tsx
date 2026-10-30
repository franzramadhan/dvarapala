import { For, Show } from 'solid-js';
import { useParams } from '@tanstack/solid-router';
import { useQuery } from '@tanstack/solid-query';
import { configQuery, errMsg, statusQuery, type Mode } from '../api';
import { ModeSwitch } from '../components/ModeSwitch';
import { PageHeader } from '../components/Ui';
import { fmtDuration, fmtRate } from '../format';
import { CERT_WARN_SECS, HEALTH, certSecs, metricsQuery, pageSeries, rateOf } from '../metrics';

const labels = (l: Record<string, string>) =>
  Object.entries(l)
    .map(([k, v]) => `${k}=${v}`)
    .join(' ');

const fmtValue = (v: number) => (Number.isInteger(v) ? String(v) : v.toFixed(3));

/** One page per feature, from the series the gateway exports (RFC 0021). */
export function HealthPage() {
  const params = useParams({ strict: false });
  const page = () => HEALTH.find((p) => p.id === (params() as { page?: string }).page);
  const m = useQuery(() => metricsQuery());
  const cfg = useQuery(() => configQuery());
  const status = useQuery(() => statusQuery());
  const detectionMode = (): Mode =>
    status.data?.switches?.find((s) => s.layer === 'detection')?.mode ??
    ((cfg.data?.find((k) => k.key === 'detection.mode')?.value as Mode | undefined) ?? 'observe');
  const allowed = () => cfg.data?.find((k) => k.key === 'admin.mode_switch')?.value === true;
  const cert = () => (m.data ? certSecs(m.data) : null);

  return (
    <Show when={page()} fallback={<p class="empty">No such page.</p>}>
      {(p) => (
        <div class="space-y-4">
          <PageHeader title={p().label} />
          <p class="text-xs text-muted">RFC {p().rfc}. Values from this instance's metrics; rates over the last poll.</p>
          <Show when={m.isError}>
            <p role="alert" class="field-error">
              Cannot read the metrics: {errMsg(m.error)}
            </p>
          </Show>
          <Show when={p().id === 'detection'}>
            <ModeSwitch layer="detection" mode={detectionMode()} allowed={allowed()} />
          </Show>
          <Show when={p().id === 'tls' && cert() !== null && cert()! < CERT_WARN_SECS}>
            <p role="alert" class="field-error">
              The served certificate expires in {fmtDuration(Math.max(0, cert()!))}.
            </p>
          </Show>
          <div class="card overflow-x-auto">
            <table class="w-full">
              <caption class="sr-only">{p().label} series</caption>
              <thead class="border-b border-line">
                <tr>
                  <th scope="col" class="th">Series</th>
                  <th scope="col" class="th">Labels</th>
                  <th scope="col" class="th text-right">Value</th>
                  <th scope="col" class="th text-right">Per second</th>
                </tr>
              </thead>
              <tbody>
                <For each={m.data ? pageSeries(p(), m.data) : []} fallback={<tr><td colspan="4" class="td text-muted">{m.isPending ? 'Loading...' : 'No series yet.'}</td></tr>}>
                  {(s) => {
                    const ejected = s.name === 'dvarapala_upstream_healthy' && s.value === 0;
                    const r = rateOf(m.data!, s);
                    return (
                      <tr class="border-t border-line" classList={{ 'text-danger': ejected }}>
                        <td class="td font-mono text-xs">{s.name.replace(/^dvarapala_/, '')}</td>
                        <td class="td break-all font-mono text-xs">{labels(s.labels)}</td>
                        <td class="td num text-right">{ejected ? 'ejected' : fmtValue(s.value)}</td>
                        <td class="td num text-right">{r === undefined ? '' : fmtRate(r)}</td>
                      </tr>
                    );
                  }}
                </For>
              </tbody>
            </table>
          </div>
        </div>
      )}
    </Show>
  );
}
