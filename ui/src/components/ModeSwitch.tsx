import { Show, createSignal } from 'solid-js';
import { useMutation, useQueryClient } from '@tanstack/solid-query';
import { errMsg, setMode, type Layer, type Mode } from '../api';
import { ConfirmDialog } from './Dialog';

export const LAYER_LABEL: Record<Layer, string> = { detection: 'Detection', waf: 'WAF' };

const EFFECT: Record<Layer, Record<Mode, string>> = {
  waf: {
    observe: "the agent's verdicts are logged and no longer block.",
    enforce: "the agent's verdicts block requests again.",
  },
  detection: {
    observe: 'attack mode is logged and the stricter limits no longer apply.',
    enforce: 'attack mode applies the stricter limits again.',
  },
};

/** The running mode of a layer and the button that switches it (RFC 0021). */
export function ModeSwitch(props: { layer: Layer; mode: Mode; allowed: boolean }) {
  const qc = useQueryClient();
  const [open, setOpen] = createSignal(false);
  const target = (): Mode => (props.mode === 'enforce' ? 'observe' : 'enforce');
  const run = useMutation(() => ({
    mutationFn: () => setMode(props.layer, target()),
    onSuccess: () => setOpen(false),
    onSettled: () => {
      for (const k of ['status', 'waf', 'config']) void qc.invalidateQueries({ queryKey: [k] });
    },
  }));
  const title = () => `${LAYER_LABEL[props.layer]} to ${target()}?`;

  return (
    <div class="card flex flex-wrap items-center justify-between gap-3 p-4">
      <div class="text-sm">
        <p>
          Running mode: <span class="chip font-mono">{props.mode}</span>
        </p>
        <p class="mt-1 text-muted">
          <Show when={props.allowed} fallback={<>Switching is off: set <code class="font-mono">admin.mode_switch = true</code> to allow it.</>}>
            A switch applies to this instance only and lasts until the next reload.
          </Show>
        </p>
      </div>
      <Show when={props.allowed}>
        <button type="button" class="btn" onClick={() => setOpen(true)}>
          Switch to {target()}
        </button>
      </Show>
      <Show when={open()}>
        <ConfirmDialog
          title={title()}
          confirmLabel={`Switch to ${target()}`}
          danger={target() === 'observe'}
          busy={run.isPending}
          error={run.error ? errMsg(run.error) : null}
          onConfirm={() => run.mutate()}
          onCancel={() => setOpen(false)}
        >
          <p>
            {LAYER_LABEL[props.layer]} to {target()}: {EFFECT[props.layer][target()]}
          </p>
          <p class="text-muted">Only this instance switches; other replicas keep their mode. A reload reverts to the file.</p>
        </ConfirmDialog>
      </Show>
    </div>
  );
}
