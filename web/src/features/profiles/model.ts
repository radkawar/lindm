import {
  create,
  createRegistry,
  fromJsonString,
  getOption,
  toJsonString,
  type DescField,
} from "@bufbuild/protobuf";
import { createValidator, pathFromViolationProto, Violation } from "@bufbuild/protovalidate";
import {
  field as validationRules,
  ViolationsSchema,
} from "@bufbuild/protovalidate/gen/buf/validate/validate_pb.js";
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
import { SSHServerDesiredSchema } from "../../../gen/lindm/resource/v1/accounts_pb";
import { KernelModuleBlocklistSchema } from "../../../gen/lindm/resource/v1/host_pb";
import { Presence } from "../../../gen/lindm/resource/v1/identity_pb";
import { audit_reason } from "../../../gen/lindm/validation/v1/string_rules_pb";
import { canonicalUuid, newRequestId } from "@/lib/ids";
import { toRpcFailure, type RpcFailure } from "@/lib/errors";
import { describeViolation, violationText } from "@/lib/validation";
import { object, replaceReference, withDerivedRef } from "./resource-draft";
import { fieldLabel } from "./typed-fields";

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

// Preserve the complete protobuf document while typed controls edit individual fields.
export type DraftResource = { resourceId: string; document: string };
export type DraftSpec = { name: string; description: string; resources: DraftResource[] };
export type PublishPayload = PublishProfileRevisionRequest & { spec: ResourceProfile };

export function usableUuid(value: string): string | null {
  const canonical = canonicalUuid(value);
  return canonical === null || canonical === NIL_UUID ? null : canonical;
}

// A new setting has no type until the administrator chooses one; publishing
// refuses it until then. The ownership and verification defaults are adjusted
// to the chosen type's qualification when the type is picked.
export function newResource(): DraftResource {
  const resourceId = newRequestId();
  return {
    resourceId,
    document: JSON.stringify(
      {
        resourceId,
        desired: {},
        ownership: {
          mode: "OWNERSHIP_MODE_CREATE_ONLY",
          release: "RELEASE_BEHAVIOR_RESTORE_OWNED",
        },
        verification: { maxAgeSeconds: 300, checks: ["HEALTH_CHECK_NATIVE_STATE"] },
      },
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

// Errors on one setting are shown on that setting; the rest belong to the profile.
export type DraftErrors = { profile: string[]; settings: Record<number, string[]> };
export const NO_DRAFT_ERRORS: DraftErrors = { profile: [], settings: {} };

// The server refuses the same shape at publication (profile_setting_empty).
const EMPTY_SETTING_RULE = "profile_setting_empty";
const EMPTY_FIREWALL_ZONE =
  "Add an interface, source network or rule. Without one, this zone's default traffic rules apply to all traffic on the device.";

export function publishErrors(payload: PublishPayload): DraftErrors {
  const result = validator.validate(PublishProfileRevisionRequestSchema, payload);
  if (result.kind === "error") {
    return { profile: [`Couldn't check the profile: ${result.error.message}`], settings: {} };
  }
  const errors = draftErrors(result.kind === "invalid" ? result.violations : []);
  payload.spec.resources.forEach((resource, index) => {
    const state = resource.desired?.state;
    // Without a type, every other violation on the setting is noise.
    if (state?.case === undefined) {
      errors.settings[index] = ["Choose a setting type."];
      return;
    }
    if (
      state.case === "firewallZone" &&
      state.value.presence === Presence.PRESENT &&
      state.value.interfaces.length === 0 &&
      state.value.sourceNetworks.length === 0 &&
      state.value.rules.length === 0
    ) {
      errors.settings[index] = [...(errors.settings[index] ?? []), EMPTY_FIREWALL_ZONE];
    }
  });
  // Canonical resource identity, dependency cycles and ownership claims are checked by the server.
  return errors;
}

// A definitive server refusal that names settings, in the same violation shape
// as the schema check. Null when the refusal doesn't identify a setting.
export function publishRefusalErrors(error: unknown): DraftErrors | null {
  const connectError = ConnectError.from(error);
  if (connectError.code !== Code.InvalidArgument) return null;
  const violations = connectError.findDetails(ViolationsSchema).flatMap((detail) =>
    detail.violations.flatMap((violation) => {
      if (!violation.field) return [];
      try {
        const path = pathFromViolationProto(PublishProfileRevisionRequestSchema, violation.field);
        return [new Violation(violation.message, violation.ruleId, path, [], violation.forKey)];
      } catch {
        return [];
      }
    }),
  );
  const errors = draftErrors(violations);
  return Object.keys(errors.settings).length > 0 ? errors : null;
}

function draftErrors(violations: Violation[]): DraftErrors {
  const errors: DraftErrors = { profile: [], settings: {} };
  for (const violation of violations) {
    const entry = violation.field.find((part) => part.kind === "list_sub");
    if (entry === undefined) {
      errors.profile.push(describeViolation(violation).message);
      continue;
    }
    const message = settingMessage(violation, violations);
    if (message === null) continue;
    const existing = errors.settings[entry.index] ?? [];
    if (!existing.includes(message)) errors.settings[entry.index] = [...existing, message];
  }
  return errors;
}

function settingMessage(violation: Violation, all: Violation[]): string | null {
  const last = violation.field.at(-1);
  if (last === SSHServerDesiredSchema.field.bannerText) {
    if (violation.ruleId === "string.min_len") return "Enter the notice shown before SSH sign-in.";
    if (violation.ruleId === "string.pattern") {
      // The schema can report both required text and character rules for an
      // empty notice. Present the actionable required-text error only.
      const required = all.some(
        (other) =>
          other.ruleId === "string.min_len" &&
          other.field.length === violation.field.length &&
          other.field.every((part, offset) => part === violation.field[offset]),
      );
      return required
        ? null
        : "Use plain text in the SSH login notice, without terminal control characters.";
    }
    return violationText("SSH login notice", violation.ruleId, violation.message);
  }
  if (violation.ruleId === EMPTY_SETTING_RULE) {
    return last?.kind === "field" && last.localName === "firewallZone"
      ? EMPTY_FIREWALL_ZONE
      : "This setting doesn't manage anything yet. Fill in what it should change.";
  }
  if (/\.(managed_)?dimensions?$/.test(violation.ruleId)) {
    return "This setting doesn't manage anything yet. Choose at least one option to manage.";
  }
  const named = [...violation.field]
    .reverse()
    .find((part) => part.kind === "field" || part.kind === "oneof");
  const entry = last?.kind === "list_sub" ? ` (line ${last.index + 1})` : "";
  if (
    named === KernelModuleBlocklistSchema.field.modules &&
    violation.ruleId !== "repeated.min_items"
  ) {
    return `Modules to block${entry}: ${MODULE_NAME_RULE}`;
  }
  const label =
    named?.kind === "field"
      ? fieldLabel(named.jsonName)
      : named?.kind === "oneof"
        ? fieldLabel(named.localName)
        : "This setting";
  return violationText(`${label}${entry}`, violation.ruleId, violation.message);
}

export const MODULE_NAME_RULE =
  "use letters, digits and underscores, starting with a letter (usb_storage, not usb-storage).";

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

// Who published a version, by the account's current name; the actor ID stays
// in Details. A server-side publication has no actor.
export function publisherLabel(actorId: string, displayName: string, viewerId: string): string {
  if (!actorId.trim()) return "The system";
  const name = displayName.trim() || "An account without a name";
  return actorId === viewerId ? `${name} (you)` : name;
}
