import { Show, createSignal } from 'solid-js';
import { useNavigate, useSearch } from '@tanstack/solid-router';
import { useMutation, useQuery, useQueryClient } from '@tanstack/solid-query';
import { ApiError, getMethods, getSession, login } from '../api';

export function LoginPage() {
  const navigate = useNavigate();
  const qc = useQueryClient();
  const search = useSearch({ strict: false }) as () => { error?: string };
  const methods = useQuery(() => ({ queryKey: ['methods'], queryFn: getMethods, retry: 1, staleTime: 0 }));
  const [token, setToken] = createSignal('');

  document.title = 'Sign in | Dvarapala';

  // Already signed in (for example after the OIDC redirect): skip the form.
  void getSession(true).then(
    () => navigate({ to: '/' }),
    () => {},
  );

  const signIn = useMutation(() => ({
    mutationFn: (t: string) => login(t),
    onSuccess: async () => {
      setToken('');
      await qc.invalidateQueries({ queryKey: ['session'] });
      void navigate({ to: '/' });
    },
  }));

  const errorText = () => {
    const e = signIn.error;
    if (e instanceof ApiError) return e.status === 401 ? 'That token was not accepted.' : e.message;
    return e ? 'Could not reach the gateway.' : (search().error ?? null);
  };

  return (
    <main class="mx-auto flex min-h-screen max-w-sm flex-col justify-center px-4 py-10">
      <div class="mb-6 flex items-center gap-2 text-lg font-semibold tracking-tight">
        <svg width="24" height="24" viewBox="0 0 32 32" aria-hidden="true">
          <rect width="32" height="32" rx="7" fill="var(--accent)" />
          <path d="M16 5 7 9v6c0 5.5 3.8 9.6 9 12 5.2-2.4 9-6.5 9-12V9z" fill="none" stroke="var(--accent-fg)" stroke-width="2.2" stroke-linejoin="round" />
        </svg>
        Dvarapala
      </div>
      <section class="card space-y-4 p-5" aria-labelledby="login-title">
        <h1 id="login-title" class="text-base font-semibold">Sign in to the admin console</h1>
        <Show when={errorText()}>
          <p role="alert" class="field-error">
            {errorText()}
          </p>
        </Show>
        <Show when={methods.isError}>
          <p role="alert" class="field-error">
            Cannot load the login methods from the gateway.
          </p>
        </Show>
        <Show when={methods.data?.oidc}>
          {(o) => (
            <a href="/session/oidc" class="btn btn-primary w-full">
              Sign in with {o().label}
            </a>
          )}
        </Show>
        <Show when={methods.data?.oidc && methods.data.token}>
          <div class="flex items-center gap-3 text-xs text-muted" aria-hidden="true">
            <span class="h-px flex-1 bg-line" />
            or
            <span class="h-px flex-1 bg-line" />
          </div>
        </Show>
        <Show when={methods.data?.token}>
          <form
            class="space-y-3"
            onSubmit={(e) => {
              e.preventDefault();
              if (token()) signIn.mutate(token());
            }}
          >
            <div>
              <label for="token" class="label">
                Admin token
              </label>
              <input
                id="token"
                type="password"
                class="input mt-1 font-mono"
                autocomplete="off"
                spellcheck={false}
                value={token()}
                onInput={(e) => setToken(e.currentTarget.value)}
              />
            </div>
            <button type="submit" class="btn btn-primary w-full" disabled={!token() || signIn.isPending}>
              {signIn.isPending ? 'Signing in...' : 'Sign in with token'}
            </button>
          </form>
        </Show>
      </section>
    </main>
  );
}
