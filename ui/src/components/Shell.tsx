import { For, Show, createEffect, createSignal } from 'solid-js';
import { Link, Outlet, useNavigate } from '@tanstack/solid-router';
import { useMutation, useQuery, useQueryClient } from '@tanstack/solid-query';
import { logout, reload, sessionQuery, statusQuery } from '../api';
import { HEALTH, metricsQuery, present, storeDown } from '../metrics';
import { LAYER_LABEL } from './ModeSwitch';
import { Dialog } from './Dialog';
import { SHORTCUTS, useShortcuts } from '../shortcuts';
import { themePref, setThemePref, type ThemePref } from '../theme';
import { resetAll } from '../history';
import { resetScrape } from '../metrics';
import { fmtDuration } from '../format';

export const STATE_LABEL: Record<string, string> = {
  normal: 'Normal',
  suspect: 'Suspect',
  attack: 'Under attack',
  cooldown: 'Cooldown',
  unknown: 'Not reported',
};

const NAV = [
  { to: '/', label: 'Overview', exact: true },
  { to: '/top', label: 'Top talkers', reverse: true },
  { to: '/blocks', label: 'Blocks', reverse: true },
  { to: '/waf', label: 'WAF', waf: true },
  { to: '/config', label: 'Config' },
  { to: '/reload', label: 'Reload' },
] as const;

const ICONS: Record<ThemePref, string> = {
  system: 'M3 5h18v11H3zM8 20h8M12 16v4',
  light: 'M12 8a4 4 0 100 8 4 4 0 000-8zM12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4',
  dark: 'M20 14.5A8 8 0 019.5 4 8 8 0 1020 14.5z',
};

function Icon(props: { d: string }) {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
      <path d={props.d} />
    </svg>
  );
}

export function stateKey(d: string | null | undefined): string {
  return d ?? 'unknown';
}

export function Shell() {
  const navigate = useNavigate();
  const qc = useQueryClient();
  const session = useQuery(() => sessionQuery());
  const status = useQuery(() => statusQuery());
  const metrics = useQuery(() => metricsQuery());
  const revert = useMutation(() => ({ mutationFn: reload, onSettled: () => void qc.invalidateQueries() }));
  const [help, setHelp] = createSignal(false);
  const nav = () =>
    NAV.filter((n) => !('reverse' in n && status.data?.mode === 'forward') && !('waf' in n && status.data?.waf == null));
  const health = () => HEALTH.filter((p) => present(p, metrics.data));
  const state = () => stateKey(status.data?.detection);

  useShortcuts({
    go: (to) => void navigate({ to }),
    filter: () => {
      void navigate({ to: '/top' }).then(() => requestAnimationFrame(() => document.getElementById('top-filter')?.focus()));
    },
    help: () => setHelp(true),
  });

  createEffect(() => {
    document.title = state() === 'attack' ? 'ATTACK | Dvarapala' : 'Dvarapala';
  });

  const signOut = async () => {
    try {
      await logout();
    } catch {
      // the session may be gone already; either way go to login
    }
    resetAll();
    resetScrape();
    qc.removeQueries();
    void navigate({ to: '/login' });
  };

  return (
    <>
      <a href="#main" class="sr-only focus:not-sr-only focus:absolute focus:z-50 focus:bg-surface focus:p-2">
        Skip to content
      </a>
      <div class="band" data-state={state()} aria-hidden="true" />
      <header class="border-b border-line bg-surface">
        <div class="mx-auto flex max-w-6xl flex-wrap items-center gap-x-3 gap-y-2 px-4 py-2">
          <span class="flex items-center gap-2 font-semibold tracking-tight">
            <svg width="20" height="20" viewBox="0 0 32 32" aria-hidden="true">
              <rect width="32" height="32" rx="7" fill="var(--accent)" />
              <path d="M16 5 7 9v6c0 5.5 3.8 9.6 9 12 5.2-2.4 9-6.5 9-12V9z" fill="none" stroke="var(--accent-fg)" stroke-width="2.2" stroke-linejoin="round" />
            </svg>
            Dvarapala
          </span>
          <span class="pill" data-state={state()} role="status">
            {STATE_LABEL[state()]}
          </span>
          <div class="ml-auto flex items-center gap-2">
            <Show when={session.data}>
              {(s) => (
                <span class="chip max-w-40 truncate sm:max-w-64" title={`${s().method} login`}>
                  {s().subject}
                </span>
              )}
            </Show>
            <div class="flex rounded-md border border-edge" role="group" aria-label="Theme">
              <For each={['system', 'light', 'dark'] as ThemePref[]}>
                {(t) => (
                  <button
                    type="button"
                    class="btn !min-h-8 !rounded-none !border-0 !px-2 first:!rounded-l-md last:!rounded-r-md"
                    classList={{ 'btn-primary': themePref() === t }}
                    aria-pressed={themePref() === t}
                    aria-label={`${t[0]?.toUpperCase()}${t.slice(1)} theme`}
                    title={`${t[0]?.toUpperCase()}${t.slice(1)} theme`}
                    onClick={() => setThemePref(t)}
                  >
                    <Icon d={ICONS[t]} />
                  </button>
                )}
              </For>
            </div>
            <button type="button" class="btn btn-sm" onClick={() => setHelp(true)} aria-label="Keyboard shortcuts" title="Keyboard shortcuts (?)">
              ?
            </button>
            <button type="button" class="btn btn-sm" onClick={signOut}>
              Sign out
            </button>
          </div>
        </div>
        <nav aria-label="Main" class="mx-auto flex max-w-6xl gap-1 overflow-x-auto px-4 pb-2">
          <For each={nav()}>
            {(n) => (
              <Link to={n.to} class="nav-link" activeOptions={{ exact: 'exact' in n }}>
                {n.label}
              </Link>
            )}
          </For>
          <For each={health()}>
            {(p) => (
              <Link to="/h/$page" params={{ page: p.id }} class="nav-link">
                {p.label}
              </Link>
            )}
          </For>
        </nav>
      </header>
      <div class="mx-auto max-w-6xl space-y-2 px-4 pt-3 empty:hidden">
        <Show when={storeDown(metrics.data)}>
          <p role="alert" class="field-error" data-testid="store-banner">
            The shared store is unreachable: each instance limits on its own (fail open) until it is back.
          </p>
        </Show>
        <For each={status.data?.switches ?? []}>
          {(w) => (
            <div role="status" class="card flex flex-wrap items-center justify-between gap-2 p-3 text-sm" data-testid={`switch-${w.layer}`}>
              <span>
                {LAYER_LABEL[w.layer]} switched to {w.mode} by {w.actor} {fmtDuration(Date.now() / 1000 - w.at)} ago; the file says {w.file_mode}; a reload reverts it.
              </span>
              <button type="button" class="btn btn-sm" disabled={revert.isPending} onClick={() => revert.mutate()}>
                Revert to file
              </button>
            </div>
          )}
        </For>
      </div>
      <main id="main" tabindex="-1" class="mx-auto max-w-6xl px-4 py-5">
        <Show when={session.data} fallback={<p class="text-muted" role="status">Loading...</p>}>
          <Outlet />
        </Show>
      </main>
      <footer class="mx-auto max-w-6xl px-4 pb-6 text-xs text-muted">
        <Show when={status.data}>{(s) => <span class="num">v{s().version} / {s().mode} / </span>}</Show>
        <Show when={session.data}>{(s) => <span class="num">session ends in about {fmtDuration(s().expires_in)}</span>}</Show>
      </footer>
      <Show when={help()}>
        <Dialog title="Keyboard shortcuts" onClose={() => setHelp(false)}>
          <dl class="grid grid-cols-[auto_1fr] items-center gap-x-4 gap-y-2 text-sm">
            <For each={SHORTCUTS}>
              {([k, d]) => (
                <>
                  <dt>
                    <kbd class="kbd">{k}</kbd>
                  </dt>
                  <dd>{d}</dd>
                </>
              )}
            </For>
          </dl>
          <div class="mt-5 flex justify-end">
            <button type="button" class="btn" data-autofocus onClick={() => setHelp(false)}>
              Close
            </button>
          </div>
        </Dialog>
      </Show>
    </>
  );
}
