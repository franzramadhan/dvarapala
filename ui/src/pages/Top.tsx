import { For, Show, createEffect, createMemo, createSignal } from 'solid-js';
import { createStore, reconcile } from 'solid-js/store';
import { useQuery } from '@tanstack/solid-query';
import { ApiError, errMsg, blocksQuery, topQuery, type Talker } from '../api';
import { BlockDialog } from '../components/BlockDialog';
import { Num, PageHeader, Unavailable } from '../components/Ui';

type SortKey = 'cidr' | 'count';

export function TopPage() {
  const q = useQuery(() => topQuery());
  const blocks = useQuery(() => blocksQuery());
  const [rows, setRows] = createStore<Talker[]>([]);
  createEffect(() => q.data && setRows(reconcile(q.data, { key: 'cidr' })));

  const [filter, setFilter] = createSignal('');
  const [sort, setSort] = createSignal<{ key: SortKey; dir: 1 | -1 }>({ key: 'count', dir: -1 });
  const [target, setTarget] = createSignal<string | null>(null);

  const total = createMemo(() => rows.reduce((n, r) => n + r.count, 0));
  const blocked = createMemo(() => new Set((blocks.data ?? []).map((b) => b.cidr)));
  const view = createMemo(() => {
    const f = filter().trim().toLowerCase();
    const { key, dir } = sort();
    return rows
      .filter((r) => r.cidr.toLowerCase().includes(f))
      .sort((a, b) => dir * (key === 'count' ? a.count - b.count : a.cidr.localeCompare(b.cidr, 'en', { numeric: true })));
  });
  const toggle = (key: SortKey) =>
    setSort((s) => (s.key === key ? { key, dir: s.dir === 1 ? -1 : 1 } : { key, dir: key === 'count' ? -1 : 1 }));
  const ariaSort = (key: SortKey) => (sort().key === key ? (sort().dir === 1 ? 'ascending' : 'descending') : 'none');
  const unavailable = () => q.error instanceof ApiError && q.error.status === 503;

  const Head = (p: { k: SortKey; label: string; right?: boolean }) => (
    <th scope="col" class="th" classList={{ 'text-right': p.right }} aria-sort={ariaSort(p.k)}>
      <button type="button" class="inline-flex items-center gap-1 uppercase tracking-wide hover:text-fg" onClick={() => toggle(p.k)}>
        {p.label}
        <span aria-hidden="true">{sort().key === p.k ? (sort().dir === 1 ? '▲' : '▼') : ''}</span>
      </button>
    </th>
  );

  return (
    <div class="space-y-4">
      <PageHeader title="Top talkers">
        <div class="flex items-center gap-2">
          <label for="top-filter" class="sr-only">
            Filter by network
          </label>
          <input
            id="top-filter"
            type="search"
            class="input w-56 font-mono"
            placeholder="Filter  (press /)"
            autocomplete="off"
            value={filter()}
            onInput={(e) => setFilter(e.currentTarget.value)}
          />
        </div>
      </PageHeader>

      <Show when={!unavailable()} fallback={<Unavailable what="Top talkers" message={errMsg(q.error)} />}>
        <Show when={q.isError}>
          <p role="alert" class="field-error">
            Could not load top talkers: {errMsg(q.error)}
          </p>
        </Show>
        <div class="card overflow-x-auto">
          <table class="w-full">
            <caption class="sr-only">Heaviest networks in the last window, with their share of the listed traffic</caption>
            <thead class="border-b border-line">
              <tr>
                <Head k="cidr" label="Network" />
                <Head k="count" label="Requests" right />
                <th scope="col" class="th">Share</th>
                <th scope="col" class="th"><span class="sr-only">Actions</span></th>
              </tr>
            </thead>
            <tbody>
              <For
                each={view()}
                fallback={
                  <tr>
                    <td colspan="4" class="td text-muted">
                      {q.isPending ? 'Loading...' : filter() ? 'No network matches the filter.' : 'No traffic recorded in this window.'}
                    </td>
                  </tr>
                }
              >
                {(r) => {
                  const share = () => (total() ? (r.count / total()) * 100 : 0);
                  return (
                    <tr class="row-enter border-t border-line first:border-0">
                      <td class="td font-mono">{r.cidr}</td>
                      <td class="td text-right">
                        <Num value={r.count} />
                      </td>
                      <td class="td">
                        <div class="flex items-center gap-2">
                          <div class="h-1.5 w-20 overflow-hidden rounded-full bg-surface2" aria-hidden="true">
                            <div class="h-full bg-accent" style={{ width: `${share()}%` }} />
                          </div>
                          <span class="num w-12 text-right text-xs text-muted">{share().toFixed(1)}%</span>
                        </div>
                      </td>
                      <td class="td text-right">
                        <Show
                          when={!blocked().has(r.cidr)}
                          fallback={<span class="chip !text-ok">Blocked</span>}
                        >
                          <button type="button" class="btn btn-sm" aria-label={`Block ${r.cidr}`} onClick={() => setTarget(r.cidr)}>
                            Block
                          </button>
                        </Show>
                      </td>
                    </tr>
                  );
                }}
              </For>
            </tbody>
          </table>
        </div>
      </Show>

      <Show when={target()}>{(c) => <BlockDialog cidr={c()} onClose={() => setTarget(null)} />}</Show>
    </div>
  );
}
