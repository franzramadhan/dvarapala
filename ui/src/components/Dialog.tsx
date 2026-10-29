import { createUniqueId, onCleanup, onMount, Show, type JSX } from 'solid-js';

const FOCUSABLE = 'button:not(:disabled), [href], input:not(:disabled), select:not(:disabled), [tabindex]:not([tabindex="-1"])';

export function Dialog(props: { title: string; onClose: () => void; children: JSX.Element; wide?: boolean }) {
  const titleId = createUniqueId();
  let box!: HTMLDivElement;
  const opener = document.activeElement as HTMLElement | null;

  const onKey = (e: KeyboardEvent) => {
    if (e.key === 'Escape') {
      e.stopPropagation();
      props.onClose();
    } else if (e.key === 'Tab') {
      const items = [...box.querySelectorAll<HTMLElement>(FOCUSABLE)];
      const first = items[0];
      const last = items[items.length - 1];
      if (!first || !last) return;
      if (e.shiftKey && document.activeElement === first) {
        e.preventDefault();
        last.focus();
      } else if (!e.shiftKey && document.activeElement === last) {
        e.preventDefault();
        first.focus();
      }
    }
  };

  onMount(() => {
    const target = box.querySelector<HTMLElement>('[data-autofocus]') ?? box.querySelector<HTMLElement>(FOCUSABLE) ?? box;
    target.focus();
  });
  onCleanup(() => opener?.focus?.());

  return (
    <div class="backdrop" onMouseDown={(e) => e.target === e.currentTarget && props.onClose()}>
      <div
        ref={box}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        tabindex="-1"
        onKeyDown={onKey}
        class="card w-full p-5 shadow-2xl"
        classList={{ 'max-w-md': !props.wide, 'max-w-lg': props.wide }}
      >
        <h2 id={titleId} class="mb-3 text-base font-semibold">
          {props.title}
        </h2>
        {props.children}
      </div>
    </div>
  );
}

export function ConfirmDialog(props: {
  title: string;
  confirmLabel: string;
  danger?: boolean;
  busy?: boolean;
  error?: string | null;
  disabled?: boolean;
  onConfirm: () => void;
  onCancel: () => void;
  children?: JSX.Element;
}) {
  return (
    <Dialog title={props.title} onClose={props.onCancel}>
      <div class="space-y-3 text-sm">{props.children}</div>
      <Show when={props.error}>
        <p role="alert" class="field-error mt-3">
          {props.error}
        </p>
      </Show>
      <div class="mt-5 flex justify-end gap-2">
        <button type="button" class="btn" onClick={props.onCancel}>
          Cancel
        </button>
        <button
          type="button"
          data-autofocus
          class="btn"
          classList={{ 'btn-danger': props.danger, 'btn-primary': !props.danger }}
          disabled={props.busy || props.disabled}
          onClick={props.onConfirm}
        >
          {props.busy ? 'Working...' : props.confirmLabel}
        </button>
      </div>
    </Dialog>
  );
}
