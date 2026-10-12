import { queryOptions } from "@tanstack/react-query";
import { adminClient } from "@/lib/rpc";
import type { AuthLifetime } from "@/lib/auth-lifetime";

export function profilesQueryOptions(lifetime: AuthLifetime, pageSize: number, pageToken: string) {
  return queryOptions({
    queryKey: ["profiles", lifetime.generation, pageSize, pageToken] as const,
    meta: { authGeneration: lifetime.generation },
    queryFn: async ({ signal }) => {
      const response = await adminClient.listProfiles(
        { pageSize, pageToken },
        { signal: AbortSignal.any([signal, lifetime.signal]) },
      );
      lifetime.signal.throwIfAborted();
      return { profiles: response.profiles, nextPageToken: response.nextPageToken };
    },
  });
}

export function profileRevisionQueryOptions(
  lifetime: AuthLifetime,
  profileId: string,
  revisionId: string,
) {
  return queryOptions({
    queryKey: ["profile-revision", lifetime.generation, profileId, revisionId] as const,
    meta: { authGeneration: lifetime.generation },
    // A catalog head used as a compare-and-swap target must not stay pinned.
    staleTime: 0,
    queryFn: async ({ signal }) => {
      const response = await adminClient.getProfileRevision(
        revisionId === "" ? { profileId } : { profileId, revisionId },
        { signal: AbortSignal.any([signal, lifetime.signal]) },
      );
      lifetime.signal.throwIfAborted();
      if (!response.revision?.spec || response.revision.revisionId === "") {
        throw new Error("Couldn't load this profile version.");
      }
      return response.revision;
    },
  });
}

export function profileRevisionsQueryOptions(
  lifetime: AuthLifetime,
  profileId: string,
  pageToken: string,
) {
  return queryOptions({
    queryKey: ["profile-revisions", lifetime.generation, profileId, pageToken] as const,
    meta: { authGeneration: lifetime.generation },
    enabled: !!profileId,
    retry: false,
    queryFn: async ({ signal }) => {
      const response = await adminClient.listProfileRevisions(
        { profileId, pageSize: 100, pageToken },
        { signal: AbortSignal.any([signal, lifetime.signal]) },
      );
      lifetime.signal.throwIfAborted();
      return response;
    },
  });
}

// Setting kinds the server dispatches to devices, with their qualified
// ownership operations. Server configuration, so it is cached for the session.
export function qualifiedKindsQueryOptions(lifetime: AuthLifetime) {
  return queryOptions({
    queryKey: ["qualified-resource-kinds", lifetime.generation] as const,
    meta: { authGeneration: lifetime.generation },
    staleTime: Infinity,
    queryFn: async ({ signal }) => {
      const response = await adminClient.listQualifiedResourceKinds(
        {},
        { signal: AbortSignal.any([signal, lifetime.signal]) },
      );
      lifetime.signal.throwIfAborted();
      return response.kinds;
    },
  });
}
