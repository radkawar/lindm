import { queryOptions } from "@tanstack/react-query";
import type { SuggestionField } from "../../gen/lindm/admin/v1/suggestions_pb";
import type { AuthLifetime } from "@/lib/auth-lifetime";
import { adminClient } from "@/lib/rpc";

// Narrowing accepted by SuggestValues: deviceId for device-derived fields,
// osId for OS_VERSION and manager for PACKAGE_NAME only.
export type SuggestionScope = {
  field: SuggestionField;
  deviceId?: string;
  osId?: string;
  manager?: string;
};

export const SUGGESTION_PAGE_SIZE = 50;

export function suggestionsQueryOptions(
  lifetime: AuthLifetime,
  scope: SuggestionScope,
  page: { prefix: string; after: string },
) {
  const request = {
    field: scope.field,
    deviceId: scope.deviceId ?? "",
    osId: scope.osId ?? "",
    manager: scope.manager ?? "",
    prefix: page.prefix,
    after: page.after,
    pageSize: SUGGESTION_PAGE_SIZE,
  };
  return queryOptions({
    queryKey: ["suggestions", lifetime.generation, request] as const,
    meta: { authGeneration: lifetime.generation },
    retry: false,
    staleTime: 30_000,
    queryFn: async ({ signal }) => {
      const response = await adminClient.suggestValues(request, {
        signal: AbortSignal.any([signal, lifetime.signal]),
      });
      lifetime.signal.throwIfAborted();
      return response;
    },
  });
}
