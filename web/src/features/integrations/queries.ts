import { queryOptions } from "@tanstack/react-query";
import type { AuthLifetime } from "@/lib/auth-lifetime";
import { adminClient } from "@/lib/rpc";
import { DeliveryStatus } from "../../../gen/lindm/integrations/v1/delivery_pb";

export function destinationsQueryOptions(lifetime: AuthLifetime, pageToken: string) {
  return queryOptions({
    queryKey: ["integrations", lifetime.generation, "destinations", pageToken],
    meta: { authGeneration: lifetime.generation },
    queryFn: ({ signal }) =>
      adminClient.listDestinations(
        { pageSize: 50, pageToken },
        { signal: AbortSignal.any([signal, lifetime.signal]) },
      ),
  });
}

export function deliveriesQueryOptions(
  lifetime: AuthLifetime,
  pageToken: string,
  deadLetters: boolean,
) {
  return queryOptions({
    queryKey: ["integrations", lifetime.generation, "deliveries", pageToken, deadLetters],
    meta: { authGeneration: lifetime.generation },
    queryFn: ({ signal }) =>
      adminClient.listDeliveries(
        {
          pageSize: 20,
          pageToken,
          status: deadLetters ? DeliveryStatus.DEAD_LETTER : DeliveryStatus.UNSPECIFIED,
        },
        { signal: AbortSignal.any([signal, lifetime.signal]) },
      ),
  });
}

export function reportSchedulesQueryOptions(lifetime: AuthLifetime, afterId: string) {
  return queryOptions({
    queryKey: ["integrations", lifetime.generation, "schedules", afterId],
    meta: { authGeneration: lifetime.generation },
    queryFn: ({ signal }) =>
      adminClient.listReportSchedules(
        { pageSize: 50, afterId },
        { signal: AbortSignal.any([signal, lifetime.signal]) },
      ),
  });
}

export function reportArtifactsQueryOptions(lifetime: AuthLifetime, afterId: string) {
  return queryOptions({
    queryKey: ["integrations", lifetime.generation, "artifacts", afterId],
    meta: { authGeneration: lifetime.generation },
    queryFn: ({ signal }) =>
      adminClient.listReportArtifacts(
        { pageSize: 50, afterId },
        { signal: AbortSignal.any([signal, lifetime.signal]) },
      ),
  });
}
