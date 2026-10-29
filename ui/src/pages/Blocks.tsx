import { For, Show, createMemo, createSignal, onCleanup } from 'solid-js';
import { createStore, reconcile } from 'solid-js/store';
import { createEffect } from 'solid-js';
import { useQuery } from '@tanstack/solid-query';
import { ApiError, errMsg, blocksQuery, type Block } from '../api';
import { BlockDialog } from '../components/BlockDialog';
import { ConfirmDialog } from '../components/Dialog';
import { PageHeader, Unavailable } from '../components/Ui';
import { blockImpact, parseCidr } from '../cidr';
import { fmtDuration } from '../format';
import { useRemoveBlock } from '../mutations';

export function BlocksPage() {
  const q = useQuery(() => blocksQuery());
  const [rows, setRows] = createStore<Block[]>([]);
  createEffect(() => q.data && setRows(reconcile(q.data, { key: 'cidr' })));

  const [now, setNow] = createSignal(Date.now());
  const tick = setInterval(() => setNow(Date.now()), 1000);
  onCleanup(() => clearInterval(tick));
  const left = (b: Block) => Math.max(0, b.ttl_secs - (now() - q.dataUpdatedAt) / 1000);

  const [cidr, setCidr] = createSignal('');
  const info = createMemo(() => parseCidr(cidr()));
  const [adding, setAdding] = createSignal<string | null>(null);
  const [removing, setRemoving] = createSignal<string | null>(null);
  const remove = useRemoveBlock();

  const unavailable = () => q.error instanceof ApiError && q.error.status === 503;

  return (
    <div class="space-y-4">
      <PageHeader title="Blocks" />
      <Show when={!unavailable()} fallback={<Unavailable what="Blocks" message={errMsg(q.error)} />}>
        <form
          class="card space-y-2 p-4"
          onSubmit={(e) => {
            e.preventDefault();
            if (info()) setAdding(cidr().trim());
          }}
        >
          <label for="block-cidr" class="label">
            Block a network
          </label>
          <div class="flex flex-wrap gap-2">
            <input
              id="block-cidr"
              class="input max-w-xs flex-1 font-mono"
              placeholder="192.0.2.0/24 or 2001:db8::/32"
              autocomplete="off"
              spellcheck={false}
              aria-invalid={cidr() !== '' && !info()}
              aria-describedby="block-cidr-hint"
              value={cidr()}
              onInput={(e) => setCidr(e.currentTarget.value)}
            />
            <button type="submit" class="btn btn-danger" disabled={!info()}>
              Block...
            </button>
          </div>
          <p id="block-cidr-hint" class="min-h-5 text-sm" aria-live="polite">
            <Show when={cidr().trim() !== ''}>
              <Show when={info()} fallback={<span class="field-error">Not a valid IPv4 or IPv6 network.</span>}>
                {(i) => (
                  <span classList={{ 'text-danger': i().huge, 'text-muted': !i().huge }}>
                    {blockImpact(i())}
                    {i().huge ? ', a very large range' : ''}.
                  </span>
                )}
              </Show>
            </Show>
          </p>
        </form>

        <Show when={q.isError && !unavailable()}>
          <p role="alert" class="field-error">
            Could not load blocks: {errMsg(q.error)}
          </p>
        </Show>

        <div class="card overflow-x-auto">
          <table class="w-full">
            <caption class="sr-only">Manual blocks in force</caption>
            <thead class="border-b border-line">
              <tr>
                <th scope="col" class="th">Network</th>
                <th scope="col" class="th text-right">Expires in</th>
                <th scope="col" class="th"><span class="sr-only">Actions</span></th>
              </tr>
            </thead>
            <tbody>
              <For
                each={rows}
                fallback={
                  <tr>
                    <td colspan="3" class="td text-muted">
                      {q.isPending ? 'Loading...' : 'No manual blocks in force.'}
                    </td>
                  </tr>
                }
              >
                {(b) => (
                  <tr class="row-enter border-t border-line first:border-0">
                    <td class="td font-mono">{b.cidr}</td>
                    <td class="td num text-right">{fmtDuration(left(b))}</td>
                    <td class="td text-right">
                      <button type="button" class="btn btn-sm" aria-label={`Remove block ${b.cidr}`} onClick={() => setRemoving(b.cidr)}>
                        Remove
                      </button>
                    </td>
                  </tr>
                )}
              </For>
            </tbody>
          </table>
        </div>
      </Show>

      <Show when={adding()}>
        {(c) => (
          <BlockDialog
            cidr={c()}
            onClose={() => {
              setAdding(null);
              setCidr('');
            }}
          />
        )}
      </Show>
      <Show when={removing()}>
        {(c) => (
          <ConfirmDialog
            title={`Remove block ${c()}?`}
            confirmLabel={`Remove ${c()}`}
            danger
            busy={remove.isPending}
            error={remove.error?.message}
            onCancel={() => {
              remove.reset();
              setRemoving(null);
            }}
            onConfirm={() => remove.mutate(c(), { onSuccess: () => setRemoving(null) })}
          >
            <p>
              Traffic from <strong class="font-mono">{c()}</strong> is no longer dropped by this block.
            </p>
          </ConfirmDialog>
        )}
      </Show>
    </div>
  );
}
