import { Show, createSignal } from 'solid-js';
import { ConfirmDialog } from './Dialog';
import { blockImpact, parseCidr } from '../cidr';
import { parseTtl } from '../format';
import { useAddBlock } from '../mutations';

const PRESETS = ['10m', '1h', '24h'];

/** Confirmation that names the network, with a TTL from presets or typed. */
export function BlockDialog(props: { cidr: string; onClose: () => void }) {
  const [ttl, setTtl] = createSignal('1h');
  const add = useAddBlock();
  const info = () => parseCidr(props.cidr);
  const ttlOk = () => parseTtl(ttl()) !== null;

  const submit = () =>
    add.mutate({ cidr: props.cidr, ttl: ttl().trim() }, { onSuccess: () => props.onClose() });

  return (
    <ConfirmDialog
      title={`Block ${props.cidr}?`}
      confirmLabel={`Block ${props.cidr}`}
      danger
      busy={add.isPending}
      disabled={!ttlOk()}
      error={add.error?.message}
      onConfirm={submit}
      onCancel={props.onClose}
    >
      <p>
        Traffic from <strong class="font-mono">{props.cidr}</strong> is dropped until the block expires.
      </p>
      <Show when={info()}>{(i) => <p class="text-muted">{blockImpact(i())}.</p>}</Show>
      <div>
        <span class="label" id="ttl-label">
          Block for
        </span>
        <div class="mt-1 flex flex-wrap items-center gap-2" role="group" aria-labelledby="ttl-label">
          {PRESETS.map((p) => (
            <button type="button" class="btn btn-sm" aria-pressed={ttl() === p} classList={{ 'btn-primary': ttl() === p }} onClick={() => setTtl(p)}>
              {p}
            </button>
          ))}
          <input
            class="input !w-28"
            aria-label="Custom TTL"
            aria-invalid={!ttlOk()}
            placeholder="90s, 30m, 2h"
            value={ttl()}
            onInput={(e) => setTtl(e.currentTarget.value)}
          />
        </div>
        <Show when={!ttlOk()}>
          <p class="field-error mt-1">Use a number and a unit: s, m, h or d.</p>
        </Show>
      </div>
    </ConfirmDialog>
  );
}
