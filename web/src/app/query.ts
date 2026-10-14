// SPDX-License-Identifier: Apache-2.0

import { Code } from "@connectrpc/connect";
import { MutationCache, QueryCache, QueryClient } from "@tanstack/react-query";
import type { AnyRouter } from "@tanstack/react-router";
import { isUnauthenticated, toRpcFailure } from "@/lib/errors";
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
  // Sign in again, then return to where the session ended.
  void router?.navigate({ to: "/", search: { next: router.state.location.href } });
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
      // Refusals and absent targets are answers, not transient failures: retrying
      // only delays "You don't have access" by the retry backoff.
      retry: (failureCount, error) => {
        const failure = toRpcFailure(error);
        return (
          !failure.unauthenticated &&
          !failure.denied &&
          failure.code !== Code.NotFound &&
          failureCount < 1
        );
      },
    },
    mutations: { retry: false },
  },
});
