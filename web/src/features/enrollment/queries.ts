import { queryOptions } from "@tanstack/react-query";
import type { EnrollmentGrantView } from "../../../gen/lindm/admin/v1/enrollment_grants_pb";
import type { AuthLifetime } from "@/lib/auth-lifetime";
import { adminClient } from "@/lib/rpc";

export function provisioningTokensQueryOptions(lifetime: AuthLifetime, pageToken: string) {
  return queryOptions({
    queryKey: ["provisioning-tokens", lifetime.generation, pageToken] as const,
    meta: { authGeneration: lifetime.generation },
    queryFn: async ({ signal }) => {
      const result = await adminClient.listProvisioningTokens(
        { pageSize: 50, pageToken },
        { signal: AbortSignal.any([signal, lifetime.signal]), timeoutMs: 30_000 },
      );
      lifetime.signal.throwIfAborted();
      return result;
    },
    retry: false,
  });
}

export function pendingEnrollmentsQueryOptions(lifetime: AuthLifetime, pageToken: string) {
  return queryOptions({
    queryKey: ["pending-enrollments", lifetime.generation, pageToken] as const,
    meta: { authGeneration: lifetime.generation },
    queryFn: async ({ signal }) => {
      const result = await adminClient.getPendingEnrollments(
        { pageSize: 50, pageToken },
        { signal: AbortSignal.any([signal, lifetime.signal]), timeoutMs: 30_000 },
      );
      lifetime.signal.throwIfAborted();
      return result;
    },
    retry: false,
  });
}

export function enrollmentGrantsQueryOptions(
  lifetime: AuthLifetime,
  view: EnrollmentGrantView,
  pageToken: string,
) {
  return queryOptions({
    queryKey: ["enrollment-grants", lifetime.generation, view, pageToken] as const,
    meta: { authGeneration: lifetime.generation },
    queryFn: async ({ signal }) => {
      const result = await adminClient.listEnrollmentGrants(
        { pageSize: 50, pageToken, view },
        { signal: AbortSignal.any([signal, lifetime.signal]), timeoutMs: 30_000 },
      );
      lifetime.signal.throwIfAborted();
      return result;
    },
    retry: false,
  });
}

export function enrollmentInstructionsQueryOptions(lifetime: AuthLifetime) {
  return queryOptions({
    queryKey: ["enrollment-instructions", lifetime.generation] as const,
    meta: { authGeneration: lifetime.generation },
    queryFn: async ({ signal }) => {
      const result = await adminClient.getEnrollmentInstructions(
        {},
        { signal: AbortSignal.any([signal, lifetime.signal]), timeoutMs: 30_000 },
      );
      lifetime.signal.throwIfAborted();
      return result;
    },
    retry: false,
  });
}

// OS ID/version groups across authorized devices, largest first; used only to
// preselect the install command's operating system.
export function fleetOperatingSystemsQueryOptions(lifetime: AuthLifetime) {
  return queryOptions({
    queryKey: ["enrollment-fleet-os", lifetime.generation] as const,
    meta: { authGeneration: lifetime.generation },
    queryFn: async ({ signal }) => {
      const result = await adminClient.getFleetSummary(
        { recentActionLimit: 1 },
        { signal: AbortSignal.any([signal, lifetime.signal]), timeoutMs: 30_000 },
      );
      lifetime.signal.throwIfAborted();
      return result.operatingSystems?.groups ?? [];
    },
    retry: false,
  });
}
