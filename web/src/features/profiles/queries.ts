import { queryOptions } from "@tanstack/react-query";
import type { ApprovedReferenceKind } from "../../../gen/lindm/admin/v1/approved_references_pb";
import { adminClient } from "@/lib/rpc";
import type { AuthLifetime } from "@/lib/auth-lifetime";

// nameSearch is a case-insensitive substring of the profile name; the server
// binds pageToken to it, so the key carries both.
export function profilesQueryOptions(
  lifetime: AuthLifetime,
  pageSize: number,
  pageToken: string,
  nameSearch = "",
) {
  return queryOptions({
    queryKey: ["profiles", lifetime.generation, pageSize, pageToken, nameSearch] as const,
    meta: { authGeneration: lifetime.generation },
    queryFn: async ({ signal }) => {
      const response = await adminClient.listProfiles(
        { pageSize, pageToken, nameSearch },
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

// Approved home roots or package sources devices report, by name prefix.
export function approvedReferencesQueryOptions(
  lifetime: AuthLifetime,
  kind: ApprovedReferenceKind,
  prefix: string,
  after: { name: string; referenceId: string },
) {
  return queryOptions({
    queryKey: ["approved-references", lifetime.generation, kind, prefix, after] as const,
    meta: { authGeneration: lifetime.generation },
    retry: false,
    staleTime: 30_000,
    queryFn: async ({ signal }) => {
      const response = await adminClient.listApprovedReferences(
        { kind, prefix, pageSize: 50, afterName: after.name, afterReferenceId: after.referenceId },
        { signal: AbortSignal.any([signal, lifetime.signal]) },
      );
      lifetime.signal.throwIfAborted();
      return response;
    },
  });
}
