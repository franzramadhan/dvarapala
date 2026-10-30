import { For, Show, createMemo } from 'solid-js';
import { useQuery } from '@tanstack/solid-query';
import { configQuery, errMsg, wafQuery, type RuleMatch } from '../api';
import { ModeSwitch } from '../components/ModeSwitch';
import { PageHeader } from '../components/Ui';
import { fmtClock, fmtInt, fmtRate } from '../format';
import { metricsQuery, rateOf } from '../metrics';

const FAMILY: Record<string, string> = {
  '911': 'Method enforcement',
  '913': 'Scanner detection',
  '920': 'Protocol enforcement',
  '921': 'Protocol attack',
  '922': 'Multipart attack',
  '930': 'Local file inclusion',
  '931': 'Remote file inclusion',
  '932': 'Remote code execution',
  '933': 'PHP injection',
  '934': 'Generic attack',
  '941': 'XSS',
  '942': 'SQL injection',
  '943': 'Session fixation',
  '944': 'Java attack',
  '949': 'Inbound anomaly score',
  '959': 'Outbound anomaly score',
};

/** The CRS family of a rule ID, "Custom" for IDs outside the CRS ranges. */
export function family(rule: number): string {
  const s = String(rule);
  return (s.length === 6 && FAMILY[s.slice(0, 3)]) || 'Custom';
}

export function WafPage() {
  const q = useQuery(() => wafQuery());
  const cfg = useQuery(() => configQuery());
  const m = useQuery(() => metricsQuery());
  const allowed = () => cfg.data?.find((k) => k.key === 'admin.mode_switch')?.value === true;
  const groups = createMemo(() => {
    const g = new Map<string, RuleMatch[]>();
    for (const r of q.data?.rules ?? []) g.set(family(r.rule), [...(g.get(family(r.rule)) ?? []), r]);
    return [...g.entries()].sort((a, b) => b[1].reduce((n, r) => n + r.count, 0) - a[1].reduce((n, r) => n + r.count, 0));
  });
  const verdicts = () => (m.data?.series ?? []).filter((s) => s.name === 'dvarapala_waf_requests_total');

  return (
    <div class="space-y-4">
      <PageHeader title="WAF" />
      <Show when={q.isError}>
        <p role="alert" class="field-error">
          Cannot read the WAF state: {errMsg(q.error)}
        </p>
      </Show>
      <Show when={q.data}>
        {(w) => (
          <>
            <Show when={w().settings.enabled} fallback={<p class="empty">The WAF is off (<code class="font-mono">waf.enabled = false</code>).</p>}>
              <ModeSwitch layer="waf" mode={w().mode} allowed={allowed()} />
            </Show>
            <section class="card p-4" aria-labelledby="waf-settings">
              <h2 id="waf-settings" class="label mb-2">
                Settings
              </h2>
              <dl class="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-sm">
                <For each={['enabled', 'mode', 'endpoint', 'app', 'timeout', 'on_error', 'max_body', 'body_limit_action']}>
                  {(k) => (
                    <>
                      <dt class="font-mono text-muted">{k}</dt>
                      <dd class="font-mono">{String(w().settings[k] ?? '')}</dd>
                    </>
                  )}
                </For>
              </dl>
            </section>
            <Show when={verdicts().length}>
              <section class="card p-4" aria-labelledby="waf-verdicts">
                <h2 id="waf-verdicts" class="label mb-2">
                  Verdicts per second
                </h2>
                <ul class="flex flex-wrap gap-x-4 text-sm">
                  <For each={verdicts()}>
                    {(s) => (
                      <li>
                        {s.labels.verdict}: <span class="num">{fmtRate(rateOf(m.data!, s) ?? 0)}</span>
                      </li>
                    )}
                  </For>
                </ul>
              </section>
            </Show>
            <section aria-labelledby="waf-rules" class="space-y-2">
              <h2 id="waf-rules" class="text-sm font-semibold">
                Matched rules
              </h2>
              <For each={groups()} fallback={<p class="text-sm text-muted">No rule matched since start.</p>}>
                {([name, rules]) => (
                  <div class="card overflow-x-auto" data-testid={`family-${name}`}>
                    <table class="w-full">
                      <caption class="p-2 text-left text-sm font-medium">{name}</caption>
                      <thead class="border-b border-line">
                        <tr>
                          <th scope="col" class="th">Rule</th>
                          <th scope="col" class="th text-right">Count</th>
                          <th scope="col" class="th">Last match</th>
                          <th scope="col" class="th">Last seen</th>
                          <th scope="col" class="th text-right">Score</th>
                        </tr>
                      </thead>
                      <tbody>
                        <For each={rules}>
                          {(r) => (
                            <tr class="border-t border-line">
                              <td class="td font-mono">{r.rule}</td>
                              <td class="td num text-right">{fmtInt(r.count)}</td>
                              <td class="td break-all font-mono">
                                {r.method} {r.path}
                              </td>
                              <td class="td num text-xs">{fmtClock(r.last_seen)}</td>
                              <td class="td num text-right">{r.anomaly_score ?? ''}</td>
                            </tr>
                          )}
                        </For>
                      </tbody>
                    </table>
                  </div>
                )}
              </For>
              <Show when={w().other}>
                <p class="text-sm text-muted">{fmtInt(w().other)} more matches of rules past the first 256 IDs.</p>
              </Show>
            </section>
            <Show when={w().files.length}>
              <section aria-labelledby="waf-files" class="space-y-2">
                <h2 id="waf-files" class="text-sm font-semibold">
                  Agent rule files (display only)
                </h2>
                <For each={w().files}>
                  {(f) => (
                    <details class="card">
                      <summary class="cursor-pointer p-3 font-mono text-sm">
                        {f.path}
                        <Show when={f.error} fallback={<span class="text-xs text-muted"> {fmtInt(f.size ?? 0)} bytes</span>}>
                          <span class="text-danger"> {f.error}</span>
                        </Show>
                      </summary>
                      <Show when={f.content !== undefined}>
                        <pre class="overflow-x-auto border-t border-line p-3 text-xs">{f.content}</pre>
                      </Show>
                    </details>
                  )}
                </For>
              </section>
            </Show>
          </>
        )}
      </Show>
    </div>
  );
}
