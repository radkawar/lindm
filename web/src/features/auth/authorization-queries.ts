import { queryOptions } from "@tanstack/react-query";
import type { AuthLifetime } from "@/lib/auth-lifetime";
import { adminClient } from "@/lib/rpc";

export function authorizationQueryOptions(lifetime: AuthLifetime) {
  return queryOptions({
    queryKey: ["authorization", lifetime.generation],
    meta: { authGeneration: lifetime.generation },
    queryFn: ({ signal }) =>
      adminClient.getAuthorization({}, { signal: AbortSignal.any([signal, lifetime.signal]) }),
    retry: false,
  });
}
