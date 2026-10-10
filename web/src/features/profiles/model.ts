import {
  create,
  createRegistry,
  fromJsonString,
  getOption,
  toJsonString,
  type DescField,
} from "@bufbuild/protobuf";
import { createValidator } from "@bufbuild/protovalidate";
import { field as validationRules } from "@bufbuild/protovalidate/gen/buf/validate/validate_pb.js";
import { Code, ConnectError } from "@connectrpc/connect";
import {
  PublishProfileRevisionRequestSchema,
  type PublishProfileRevisionRequest,
} from "../../../gen/lindm/admin/v1/profiles_pb";
import {
  ProfileResourceSchema,
  ResourceProfileSchema,
  type ResourceProfile,
} from "../../../gen/lindm/policy/v1/profile_pb";
import { audit_reason } from "../../../gen/lindm/validation/v1/string_rules_pb";
import { canonicalUuid, newRequestId } from "@/lib/ids";
import { toRpcFailure, type RpcFailure } from "@/lib/errors";

export const NIL_UUID = "00000000-0000-0000-0000-000000000000";
export const MAX_RESOURCES = editorBound(ResourceProfileSchema.field.resources);
export const NAME_MAX = editorBound(ResourceProfileSchema.field.name);
export const DESCRIPTION_MAX = editorBound(ResourceProfileSchema.field.description);
const validator = createValidator({ registry: createRegistry(audit_reason) });

function editorBound(field: DescField): number {
  const rule = getOption(field, validationRules).type;
  const bound =
    rule.case === "string"
      ? rule.value.maxLen
      : rule.case === "repeated"
        ? rule.value.maxItems
        : undefined;
  if (bound === undefined || bound < 1n || bound > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new Error(`Missing bounded editor constraint for ${field.name}`);
  }
  return Number(bound);
}

export const CATALOG_SEMANTICS =
  "Publishing records an immutable catalog revision and can move the catalog head. It does not assign the profile, deploy it, or prove native compliance.";

// The row identity is independent of the editable protobuf resource ID.
export type DraftResource = { resourceId: string; document: string };
export type DraftSpec = { name: string; description: string; resources: DraftResource[] };
export type PublishPayload = PublishProfileRevisionRequest & { spec: ResourceProfile };

export function usableUuid(value: string): string | null {
  const canonical = canonicalUuid(value);
  return canonical === null || canonical === NIL_UUID ? null : canonical;
}

export function newResource(): DraftResource {
  const resourceId = newRequestId();
  return {
    resourceId,
    document: toJsonString(ProfileResourceSchema, create(ProfileResourceSchema, { resourceId }), {
      prettySpaces: 2,
    }),
  };
}

export function emptyDraft(): DraftSpec {
  return { name: "", description: "", resources: [newResource()] };
}

export function draftFromSpec(spec: ResourceProfile): DraftSpec {
  return {
    name: spec.name,
    description: spec.description,
    resources: spec.resources.map((resource) => ({
      resourceId: resource.resourceId,
      document: toJsonString(ProfileResourceSchema, resource, { prettySpaces: 2 }),
    })),
  };
}

export function draftFromPayload(payload: PublishPayload): DraftSpec {
  return draftFromSpec(payload.spec);
}

export function removeResource(draft: DraftSpec, resourceId: string): DraftSpec {
  return {
    ...draft,
    resources: draft.resources.filter((resource) => resource.resourceId !== resourceId),
  };
}

export function publishErrors(payload: PublishPayload): string[] {
  const result = validator.validate(PublishProfileRevisionRequestSchema, payload);
  if (result.kind === "invalid") return result.violations.map((violation) => violation.toString());
  if (result.kind === "error") return [`Profile validation failed: ${result.error.message}`];
  // Canonical resource identity, dependency cycles and ownership claims are checked by the server.
  return [];
}

export function capturePayload(input: {
  requestId: string;
  profileId: string;
  expectedRevisionId?: string;
  reason: string;
  draft: DraftSpec;
}): PublishPayload {
  const spec = create(ResourceProfileSchema, {
    name: input.draft.name,
    description: input.draft.description,
    resources: input.draft.resources.map((resource, index) => {
      try {
        return fromJsonString(ProfileResourceSchema, resource.document);
      } catch (error) {
        throw new Error(
          `Resource ${index + 1}: ${error instanceof Error ? error.message : "Invalid protobuf JSON"}`,
          { cause: error },
        );
      }
    }),
  });
  return {
    ...create(PublishProfileRevisionRequestSchema, {
      requestId: input.requestId,
      profileId: input.profileId,
      expectedRevisionId: input.expectedRevisionId,
      reason: input.reason.trim(),
      spec,
    }),
    spec,
  };
}

export function classifyPublishError(error: unknown): { failure: RpcFailure; conflict: boolean } {
  const failure = toRpcFailure(error);
  const connectError = ConnectError.from(error);
  const reason =
    connectError.metadata.get("lindm-reason") ?? connectError.metadata.get("Lindm-Reason") ?? "";
  const conflict =
    reason === "profile_revision_conflict" ||
    failure.message === "profile_revision_conflict" ||
    connectError.rawMessage === "profile_revision_conflict";
  return { conflict, failure: conflict ? { ...failure, ambiguous: false } : failure };
}

export function publishFailureTitle(failure: RpcFailure, conflict: boolean): string {
  if (conflict) return "Catalog head conflict";
  if (failure.denied) return "Not authorized";
  if (failure.unauthenticated) return "Sign-in required";
  if (failure.message === "profile_revision_not_found") return "Profile revision not found";
  if (failure.message === "profile_recovery_hold") return "Profile catalog recovery hold";
  if (failure.message === "profile_revision_capacity") return "Profile revision capacity exhausted";
  if (failure.message === "invalid_profile_request") return "Profile request rejected";
  if (failure.code === Code.Aborted || failure.ambiguous) return "Publish result unknown";
  return "Publish failed";
}

export function formatSha256(bytes: Uint8Array): string {
  if (bytes.length !== 32) return "Digest unavailable";
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

export function formatRevisionNumber(value: bigint): string {
  return value > 0n ? value.toString() : "Not recorded";
}
