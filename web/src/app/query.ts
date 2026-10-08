import { MutationCache, QueryCache, QueryClient } from "@tanstack/react-query";
import type { AnyRouter } from "@tanstack/react-router";
import { isUnauthenticated } from "@/lib/errors";
import { clearCsrfToken } from "@/lib/rpc";
import { getAuthLifetime, synchronizeAuthLifetime } from "@/lib/auth-lifetime";

let router: AnyRouter | undefined;

export function bindRouter(next: AnyRouter): void {
  router = next;
}

function expire(error: unknown, generation: unknown): void {
  if (!isUnauthenticated(error)) return;
  if (typeof generation === "number" && generation !== getAuthLifetime()?.generation) return;
  synchronizeAuthLifetime(null);
  clearCsrfToken();
  queryClient.clear();
  void router?.navigate({ to: "/" });
}

export const queryClient = new QueryClient({
  queryCache: new QueryCache({
    onError: (error, query) => expire(error, query.meta?.authGeneration),
  }),
  mutationCache: new MutationCache({
    onError: (error, _variables, _context, mutation) =>
      expire(error, mutation.meta?.authGeneration),
  }),
  defaultOptions: {
    queries: {
      retry: (failureCount, error) => !isUnauthenticated(error) && failureCount < 1,
    },
    mutations: { retry: false },
  },
});
