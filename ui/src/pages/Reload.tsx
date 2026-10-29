import { For, Show } from 'solid-js';
import { useMutation, useQuery, useQueryClient } from '@tanstack/solid-query';
import { reload, statusQuery, type ReloadFailed, type ReloadOk } from '../api';
import { PageHeader } from '../components/Ui';
import { fmtClock } from '../format';

function Result(props: { r: ReloadOk | ReloadFailed; title: string }) {
  return (
    <section class="card p-4" aria-label={props.title}>
      <h2 class="label mb-2">{props.title}</h2>
      <p class="num mb-3 text-xs text-muted">{fmtClock(props.r.at)}</p>
      {props.r.result === 'ok' ? (
        <div class="space-y-3 text-sm">
          <p class="font-medium text-ok">Applied in place</p>
          <Show when={props.r.restart.length > 0} fallback={<p class="text-muted">Nothing waits for a restart.</p>}>
            <div>
              <p class="mb-1">These keys changed and wait for a restart:</p>
              <ul class="flex flex-wrap gap-1.5">
                <For each={(props.r as ReloadOk).restart}>{(k) => <li class="chip font-mono">{k}</li>}</For>
              </ul>
            </div>
          </Show>
        </div>
      ) : (
        <div role="alert" class="space-y-1 text-sm">
          <p class="font-medium text-danger">Reload refused, the running configuration is unchanged</p>
          <p class="font-mono">{(props.r as ReloadFailed).error}</p>
        </div>
      )}
    </section>
  );
}

export function ReloadPage() {
  const qc = useQueryClient();
  const status = useQuery(() => statusQuery());
  const run = useMutation(() => ({
    mutationFn: reload,
    onSettled: () => void qc.invalidateQueries({ queryKey: ['status'] }),
  }));

  return (
    <div class="space-y-4">
      <PageHeader title="Reload" />
      <div class="card flex flex-wrap items-center justify-between gap-3 p-4">
        <p class="max-w-prose text-sm text-muted">
          Re-read the configuration file. Keys that can change at runtime apply at once; the rest are listed and wait for a restart. A file that does not validate is refused.
        </p>
        <button type="button" class="btn btn-primary" disabled={run.isPending} onClick={() => run.mutate()}>
          {run.isPending ? 'Reloading...' : 'Reload configuration'}
        </button>
      </div>
      <Show when={run.error}>
        <p role="alert" class="field-error">
          Reload request failed: {run.error?.message}
        </p>
      </Show>
      <Show when={run.data}>{(r) => <Result r={r()} title="Result" />}</Show>
      <Show when={!run.data && status.data?.last_reload}>{(r) => <Result r={r()} title="Last reload" />}</Show>
    </div>
  );
}
