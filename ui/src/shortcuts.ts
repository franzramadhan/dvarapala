import { onCleanup, onMount } from 'solid-js';

export const SHORTCUTS: [string, string][] = [
  ['g o', 'Go to Overview'],
  ['g t', 'Go to Top talkers'],
  ['g b', 'Go to Blocks'],
  ['g r', 'Go to Reload'],
  ['/', 'Filter top talkers'],
  ['?', 'Show this list'],
  ['Esc', 'Close a dialog'],
];

type Handlers = { go: (to: '/' | '/top' | '/blocks' | '/reload') => void; filter: () => void; help: () => void };

function typing(t: EventTarget | null): boolean {
  const el = t as HTMLElement | null;
  return !!el && (['INPUT', 'TEXTAREA', 'SELECT'].includes(el.tagName) || el.isContentEditable);
}

/** `g` then a letter navigates; `/` filters; `?` helps. Ignored while typing or in a dialog. */
export function useShortcuts(h: Handlers): void {
  let pendingG = 0;
  const onKey = (e: KeyboardEvent) => {
    if (e.ctrlKey || e.metaKey || e.altKey || typing(e.target) || document.querySelector('[role="dialog"]')) return;
    const gWaiting = Date.now() < pendingG;
    pendingG = 0;
    if (gWaiting) {
      const to = ({ o: '/', t: '/top', b: '/blocks', r: '/reload' } as const)[e.key as 'o'];
      if (to) {
        e.preventDefault();
        h.go(to);
      }
      return;
    }
    if (e.key === 'g') pendingG = Date.now() + 1200;
    else if (e.key === '/') {
      e.preventDefault();
      h.filter();
    } else if (e.key === '?') h.help();
  };
  onMount(() => document.addEventListener('keydown', onKey));
  onCleanup(() => document.removeEventListener('keydown', onKey));
}
