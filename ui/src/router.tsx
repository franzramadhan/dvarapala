import { Outlet, createRootRoute, createRoute, createRouter, type RouterHistory } from '@tanstack/solid-router';
import { Shell } from './components/Shell';
import { LoginPage } from './pages/Login';
import { OverviewPage } from './pages/Overview';
import { TopPage } from './pages/Top';
import { BlocksPage } from './pages/Blocks';
import { ReloadPage } from './pages/Reload';
import { ConfigPage } from './pages/Config';
import { WafPage } from './pages/Waf';
import { HealthPage } from './pages/Health';

function RouteError(props: { error: Error }) {
  return (
    <div role="alert" class="m-4 rounded-lg border border-danger p-4 text-sm">
      <p class="font-semibold text-danger">Something went wrong</p>
      <p class="font-mono">{props.error.message}</p>
    </div>
  );
}

export function createAppRouter(history?: RouterHistory) {
  const root = createRootRoute({ component: Outlet });
  const login = createRoute({
    getParentRoute: () => root,
    path: '/login',
    validateSearch: (s: Record<string, unknown>): { error?: string } => (typeof s.error === 'string' ? { error: s.error } : {}),
    component: LoginPage,
  });
  const app = createRoute({ getParentRoute: () => root, id: 'app', component: Shell });
  const pages = [
    createRoute({ getParentRoute: () => app, path: '/', component: OverviewPage }),
    createRoute({ getParentRoute: () => app, path: '/top', component: TopPage }),
    createRoute({ getParentRoute: () => app, path: '/blocks', component: BlocksPage }),
    createRoute({ getParentRoute: () => app, path: '/reload', component: ReloadPage }),
    createRoute({ getParentRoute: () => app, path: '/config', component: ConfigPage }),
    createRoute({ getParentRoute: () => app, path: '/waf', component: WafPage }),
    createRoute({ getParentRoute: () => app, path: '/h/$page', component: HealthPage }),
  ] as const;
  const tree = root.addChildren([login, app.addChildren(pages)]);
  return createRouter({ routeTree: tree, basepath: '/ui', history, defaultPreload: false, defaultErrorComponent: RouteError });
}

declare module '@tanstack/solid-router' {
  interface Register {
    router: ReturnType<typeof createAppRouter>;
  }
}
