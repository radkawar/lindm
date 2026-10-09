import { queryOptions } from "@tanstack/react-query";
import { adminClient } from "@/lib/rpc";
import type { AuthLifetime } from "@/lib/auth-lifetime";

export function profilesQueryOptions(lifetime: AuthLifetime, pageSize: number, pageToken: string) {
  return queryOptions({
    queryKey: ["profiles", lifetime.generation, pageSize, pageToken] as const,
    meta: { authGeneration: lifetime.generation },
    queryFn: async ({ signal }) => {
      const response = await adminClient.listServiceProfiles(
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
      const response = await adminClient.getServiceProfileRevision(
        revisionId === "" ? { profileId } : { profileId, revisionId },
        { signal: AbortSignal.any([signal, lifetime.signal]) },
      );
      lifetime.signal.throwIfAborted();
      if (!response.revision?.spec || response.revision.revisionId === "") {
        throw new Error("The server did not return a profile revision.");
      }
      return response.revision;
    },
  });
}
