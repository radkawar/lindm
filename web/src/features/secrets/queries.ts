// SPDX-License-Identifier: Apache-2.0

import { queryOptions } from "@tanstack/react-query";
import { adminClient } from "@/lib/rpc";
import type { AuthLifetime } from "@/lib/auth-lifetime";
import type { PageSize } from "@/lib/list-search";

// Metadata only. Revealed material never enters a query.
export function secretsQueryOptions(
  lifetime: AuthLifetime,
  pageSize: PageSize,
  pageToken: string,
  namePrefix = "",
) {
  return queryOptions({
    queryKey: ["secrets", lifetime.generation, pageSize, pageToken, namePrefix] as const,
    meta: { authGeneration: lifetime.generation },
    retry: false,
    staleTime: 0,
    queryFn: async ({ signal }) => {
      const response = await adminClient.listSecrets(
        { pageSize, pageToken, namePrefix },
        { signal: AbortSignal.any([signal, lifetime.signal]) },
      );
      lifetime.signal.throwIfAborted();
      return response;
    },
  });
}

export function secretQueryOptions(lifetime: AuthLifetime, secretId: string) {
  return queryOptions({
    queryKey: ["secret", lifetime.generation, secretId] as const,
    meta: { authGeneration: lifetime.generation },
    retry: false,
    staleTime: 0,
    queryFn: async ({ signal }) => {
      const response = await adminClient.getSecret(
        { secretId },
        { signal: AbortSignal.any([signal, lifetime.signal]) },
      );
      lifetime.signal.throwIfAborted();
      return response;
    },
  });
}

// Profiles and devices whose current settings reference the secret.
export function secretUsesQueryOptions(lifetime: AuthLifetime, secretId: string) {
  return queryOptions({
    queryKey: ["secret-uses", lifetime.generation, secretId] as const,
    meta: { authGeneration: lifetime.generation },
    retry: false,
    staleTime: 0,
    queryFn: async ({ signal }) => {
      const response = await adminClient.listSecretUses(
        { secretId },
        { signal: AbortSignal.any([signal, lifetime.signal]) },
      );
      lifetime.signal.throwIfAborted();
      return response;
    },
  });
}
