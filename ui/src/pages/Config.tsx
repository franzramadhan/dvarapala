import { For, Show, createMemo, createSignal } from 'solid-js';
import { useQuery } from '@tanstack/solid-query';
import { configQuery, errMsg, type ConfigKey } from '../api';
import { PageHeader } from '../components/Ui';

const show = (v: unknown) => (typeof v === 'string' ? v : JSON.stringify(v));

export function ConfigPage() {
  const q = useQuery(() => configQuery());
  const [filter, setFilter] = createSignal('');
  // keys whose value changed since the previous fetch, such as after a reload
  let seen: Map<string, string> | null = null;
  const changed = createMemo(() => {
    const keys = q.data ?? [];
    const now = new Map(keys.map((k) => [k.key, show(k.value)]));
    const out = new Set(seen ? keys.filter((k) => seen!.has(k.key) && seen!.get(k.key) !== now.get(k.key)).map((k) => k.key) : []);
    if (keys.length) seen = now;
    return out;
  });
  const sections = createMemo(() => {
    const f = filter().trim().toLowerCase();
    const groups = new Map<string, ConfigKey[]>();
    for (const k of q.data ?? []) {
      if (f && !k.key.toLowerCase().includes(f) && !show(k.value).toLowerCase().includes(f)) continue;
      const s = k.key.includes('.') ? (k.key.split('.')[0] as string) : '(top level)';
      groups.set(s, [...(groups.get(s) ?? []), k]);
    }
    for (const g of groups.values()) g.sort((a, b) => Number(a.default) - Number(b.default) || a.key.localeCompare(b.key));
    return [...groups.entries()];
  });

  return (
    <div class="space-y-4">
      <PageHeader title="Configuration">
        <label for="config-filter" class="sr-only">
          Filter keys
        </label>
        <input id="config-filter" type="search" class="input w-56 font-mono" placeholder="Filter keys" autocomplete="off" value={filter()} onInput={(e) => setFilter(e.currentTarget.value)} />
      </PageHeader>
      <p class="max-w-prose text-sm text-muted">
        The running configuration: file, environment and defaults merged. Secrets show as <code class="font-mono">&lt;redacted&gt;</code>. Keys marked restart show the value the process started with.
      </p>
      <Show when={q.isError}>
        <p role="alert" class="field-error">
          Cannot read the configuration: {errMsg(q.error)}
        </p>
      </Show>
      <For each={sections()} fallback={<p class="text-muted">{q.isPending ? 'Loading...' : 'No key matches the filter.'}</p>}>
        {([name, keys]) => (
          <details class="card" open={!!filter() || keys.some((k) => !k.default)}>
            <summary class="cursor-pointer p-3 font-medium">
              {name} <span class="text-xs text-muted">({keys.filter((k) => !k.default).length} set)</span>
            </summary>
            <table class="w-full">
              <caption class="sr-only">Keys of {name}</caption>
              <thead class="border-b border-line">
                <tr>
                  <th scope="col" class="th">Key</th>
                  <th scope="col" class="th">Value</th>
                  <th scope="col" class="th">Applies</th>
                </tr>
              </thead>
              <tbody>
                <For each={keys}>
                  {(k) => (
                    <tr class="border-t border-line" classList={{ flash: changed().has(k.key) }} data-testid={`key-${k.key}`}>
                      <td class="td font-mono">{k.key}</td>
                      <td class="td break-all font-mono" classList={{ 'text-muted': k.default }}>
                        {show(k.value)}
                        <Show when={k.default}>
                          <span class="sr-only"> (default)</span>
                        </Show>
                      </td>
                      <td class="td text-xs">{k.reload ? 'reload' : 'restart'}</td>
                    </tr>
                  )}
                </For>
              </tbody>
            </table>
          </details>
        )}
      </For>
    </div>
  );
}
