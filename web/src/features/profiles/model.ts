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
import { ConnectError } from "@connectrpc/connect";
import {
  PublishProfileRevisionRequestSchema,
  type PublishProfileRevisionRequest,
} from "../../../gen/lindm/admin/v1/profiles_pb";
import {
  ProfileResourceSchema,
  ResourceProfileSchema,
  type ResourceProfile,
} from "../../../gen/lindm/policy/v1/profile_pb";
import { SSHServerDesiredSchema } from "../../../gen/lindm/resource/v1/accounts_pb";
import { audit_reason } from "../../../gen/lindm/validation/v1/string_rules_pb";
import { canonicalUuid, newRequestId } from "@/lib/ids";
import { toRpcFailure, type RpcFailure } from "@/lib/errors";
import { initialState, object, replaceReference, withDerivedRef } from "./resource-draft";

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
  "Publishing saves the profile. To apply it to devices, assign it in Rollouts.";

// Preserve the complete protobuf document while typed controls edit individual fields.
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
    document: JSON.stringify(
      withDerivedRef({
        resourceId,
        desired: { systemdService: initialState("systemdService") },
        ownership: {
          mode: "OWNERSHIP_MODE_CREATE_ONLY",
          release: "RELEASE_BEHAVIOR_RESTORE_OWNED",
        },
        verification: { maxAgeSeconds: 300, checks: ["HEALTH_CHECK_NATIVE_STATE"] },
      }),
      null,
      2,
    ),
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

export function updateResource(draft: DraftSpec, next: DraftResource): DraftSpec {
  const previous = draft.resources.find((item) => item.resourceId === next.resourceId);
  if (!previous) return draft;
  const previousRef = object(
    object(withDerivedRef(object(JSON.parse(previous.document))).desired).ref,
  );
  const nextRef = object(object(withDerivedRef(object(JSON.parse(next.document))).desired).ref);
  return {
    ...draft,
    resources: draft.resources.map((item) => {
      const document = object(
        JSON.parse(item.resourceId === next.resourceId ? next.document : item.document),
      );
      return {
        ...item,
        document: JSON.stringify(replaceReference(document, previousRef, nextRef), null, 2),
      };
    }),
  };
}

export function publishErrors(payload: PublishPayload): string[] {
  const result = validator.validate(PublishProfileRevisionRequestSchema, payload);
  if (result.kind === "invalid") {
    return result.violations.flatMap((violation) => {
      if (violation.field.at(-1) !== SSHServerDesiredSchema.field.bannerText)
        return [violation.toString()];
      const entry = violation.field.find((part) => part.kind === "list_sub");
      const prefix = entry === undefined ? "" : `Setting ${entry.index + 1}: `;
      if (violation.ruleId === "string.min_len")
        return [`${prefix}Enter the notice shown before SSH sign-in.`];
      if (violation.ruleId === "string.pattern") {
        // The schema can report both required text and character rules for an
        // empty notice. Present the actionable required-text error only.
        if (
          result.violations.some(
            (other) =>
              other.ruleId === "string.min_len" &&
              other.field.length === violation.field.length &&
              other.field.every((part, offset) => part === violation.field[offset]),
          )
        )
          return [];
        return [
          `${prefix}Use plain text in the SSH login notice, without terminal control characters.`,
        ];
      }
      return [`${prefix}SSH login notice: ${violation.message}`];
    });
  }
  if (result.kind === "error") return [`Couldn't check the profile: ${result.error.message}`];
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
        return fromJsonString(
          ProfileResourceSchema,
          JSON.stringify(withDerivedRef(object(JSON.parse(resource.document)))),
        );
      } catch (error) {
        throw new Error(
          `Setting ${index + 1}: ${error instanceof Error ? error.message : "Invalid JSON"}`,
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

export function formatSha256(bytes: Uint8Array): string {
  if (bytes.length !== 32) return "Digest unavailable";
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

export function formatRevisionNumber(value: bigint): string {
  return value > 0n ? value.toString() : "Unknown";
}
