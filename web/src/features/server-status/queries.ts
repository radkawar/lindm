// SPDX-License-Identifier: Apache-2.0

import { queryOptions } from "@tanstack/react-query";
import type { AuthLifetime } from "@/lib/auth-lifetime";
import { adminClient } from "@/lib/rpc";

export function serverStatusQueryOptions(lifetime: AuthLifetime) {
  return queryOptions({
    queryKey: ["server-status", lifetime.generation] as const,
    meta: { authGeneration: lifetime.generation },
    queryFn: async ({ signal }) => {
      const result = await adminClient.getServerStatus(
        {},
        { signal: AbortSignal.any([signal, lifetime.signal]), timeoutMs: 30_000 },
      );
      lifetime.signal.throwIfAborted();
      return result;
    },
    refetchInterval: 60_000,
    retry: false,
  });
}
