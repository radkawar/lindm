// SPDX-License-Identifier: Apache-2.0

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

/** Dead letters and deliveries retrying after a failed attempt, newest first. */
export function failedDeliveriesQueryOptions(lifetime: AuthLifetime, pageToken: string) {
  return queryOptions({
    queryKey: ["integrations", lifetime.generation, "deliveries", "failures", pageToken],
    meta: { authGeneration: lifetime.generation },
    queryFn: ({ signal }) =>
      adminClient.listDeliveries(
        { pageSize: 20, pageToken, failuresOnly: true },
        { signal: AbortSignal.any([signal, lifetime.signal]) },
      ),
  });
}

export function deliveredQueryOptions(
  lifetime: AuthLifetime,
  destinationId: string,
  pageToken: string,
) {
  return queryOptions({
    queryKey: ["integrations", lifetime.generation, "deliveries", destinationId, pageToken],
    meta: { authGeneration: lifetime.generation },
    queryFn: ({ signal }) =>
      adminClient.listDeliveries(
        { pageSize: 20, pageToken, destinationId, status: DeliveryStatus.DELIVERED },
        { signal: AbortSignal.any([signal, lifetime.signal]) },
      ),
  });
}

export function deliverySummaryQueryOptions(lifetime: AuthLifetime) {
  return queryOptions({
    queryKey: ["integrations", lifetime.generation, "delivery-summary"],
    meta: { authGeneration: lifetime.generation },
    queryFn: ({ signal }) =>
      adminClient.summarizeDeliveries({}, { signal: AbortSignal.any([signal, lifetime.signal]) }),
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
        { pageSize: 10, afterId },
        { signal: AbortSignal.any([signal, lifetime.signal]) },
      ),
  });
}
