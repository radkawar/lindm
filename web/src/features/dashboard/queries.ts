import { create } from "@bufbuild/protobuf";
import { TimestampSchema, type Timestamp } from "@bufbuild/protobuf/wkt";
import { queryOptions } from "@tanstack/react-query";
import type { AuthLifetime } from "@/lib/auth-lifetime";
import { adminClient } from "@/lib/rpc";

export function fleetSummaryQueryOptions(lifetime: AuthLifetime) {
  return queryOptions({
    queryKey: ["fleet-summary", lifetime.generation] as const,
    meta: { authGeneration: lifetime.generation },
    retry: false,
    staleTime: 0,
    queryFn: async ({ signal }) => {
      const response = await adminClient.getFleetSummary(
        // The server maximum, so grouping by kind covers as much history as one snapshot allows.
        { recentActionLimit: 20 },
        { signal: AbortSignal.any([signal, lifetime.signal]) },
      );
      lifetime.signal.throwIfAborted();
      return response;
    },
  });
}

// PostgreSQL contact timestamps have microsecond precision. ListDevices uses an
// inclusive upper bound, so subtract one microsecond to preserve the summary's
// strictly-older-than threshold without including its exact boundary.
export function staleContactUntil(observedAt: Timestamp, staleAfterSeconds: number): Timestamp {
  const nanos = observedAt.nanos - 1000;
  return create(TimestampSchema, {
    seconds: observedAt.seconds - BigInt(staleAfterSeconds) - (nanos < 0 ? 1n : 0n),
    nanos: nanos < 0 ? nanos + 1_000_000_000 : nanos,
  });
}

export function staleDevicesQueryOptions(lifetime: AuthLifetime, lastSeenUntil: Timestamp) {
  return queryOptions({
    queryKey: [
      "devices",
      lifetime.generation,
      "dashboard-stale",
      lastSeenUntil.seconds.toString(),
      lastSeenUntil.nanos,
    ] as const,
    meta: { authGeneration: lifetime.generation },
    retry: false,
    staleTime: 0,
    queryFn: async ({ signal }) => {
      const response = await adminClient.listDevices(
        { pageSize: 5, pageToken: "", filter: { lastSeenUntil } },
        { signal: AbortSignal.any([signal, lifetime.signal]) },
      );
      lifetime.signal.throwIfAborted();
      return response;
    },
  });
}
