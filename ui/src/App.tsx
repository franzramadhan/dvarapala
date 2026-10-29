import { QueryClient, QueryClientProvider } from '@tanstack/solid-query';
import { RouterProvider } from '@tanstack/solid-router';
import { setUnauthorizedHandler } from './api';
import type { createAppRouter } from './router';

export function createQueryClient(retry: boolean | number = 1): QueryClient {
  return new QueryClient({ defaultOptions: { queries: { retry, refetchOnWindowFocus: true }, mutations: { retry: false } } });
}

export function App(props: { router: ReturnType<typeof createAppRouter>; client: QueryClient }) {
  // Any 401 from the API means the session is gone: drop it and show the login.
  setUnauthorizedHandler(() => {
    props.client.removeQueries({ queryKey: ['session'] });
    if (!props.router.state.location.pathname.endsWith('/login')) void props.router.navigate({ to: '/login' });
  });
  return (
    <QueryClientProvider client={props.client}>
      <RouterProvider router={props.router} />
    </QueryClientProvider>
  );
}
