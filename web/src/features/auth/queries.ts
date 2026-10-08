import { queryOptions, type QueryClient } from "@tanstack/react-query";
import { clearCsrfToken, setCsrfToken } from "@/lib/rpc";
import { getAuthLifetime, synchronizeAuthLifetime } from "@/lib/auth-lifetime";
import { fetchSession, postLogout, type SessionPrincipal } from "./session";

export const sessionQueryKey = ["session"] as const;

export function sessionIdentity(principal: SessionPrincipal): string {
  return `${principal.id}\u0000${principal.role}\u0000${principal.csrfToken}`;
}

export function sessionQueryOptions() {
  return queryOptions({
    queryKey: sessionQueryKey,
    queryFn: async ({ signal, client }): Promise<SessionPrincipal | null> => {
      const principal = await fetchSession(signal);
      signal.throwIfAborted();
      const changed = synchronizeAuthLifetime(
        principal === null ? null : sessionIdentity(principal),
      );
      if (changed) {
        const scoped = {
          predicate: (query: { queryKey: readonly unknown[] }) =>
            query.queryKey[0] !== sessionQueryKey[0],
        };
        await client.cancelQueries(scoped);
        client.removeQueries(scoped);
        client.getMutationCache().clear();
      }
      signal.throwIfAborted();
      if (principal === null) clearCsrfToken();
      else setCsrfToken(principal.csrfToken);
      return principal;
    },
    staleTime: 30_000,
    retry: false,
  });
}

export async function logout(queryClient: QueryClient, csrfToken: string): Promise<void> {
  const lifetime = getAuthLifetime();
  await postLogout(csrfToken);
  if (getAuthLifetime() !== lifetime) return;
  synchronizeAuthLifetime(null);
  clearCsrfToken();
  queryClient.clear();
}
