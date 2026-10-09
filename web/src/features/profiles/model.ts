import { create, createRegistry, getOption, type DescField } from "@bufbuild/protobuf";
import { createValidator } from "@bufbuild/protovalidate";
import { field as validationRules } from "@bufbuild/protovalidate/gen/buf/validate/validate_pb.js";
import { PublishServiceProfileRevisionRequestSchema } from "../../../gen/lindm/admin/v1/profiles_pb";
import { Code, ConnectError } from "@connectrpc/connect";
import {
  ServiceEnablement,
  ServiceRuntimeState,
  ServiceDesiredStateSchema,
  type ServiceDesiredState,
} from "../../../gen/lindm/agent/v1/service_pb";
import {
  ServiceProfileSpecSchema,
  type ServiceProfileSpec,
} from "../../../gen/lindm/policy/v1/service_profile_pb";
import { audit_reason } from "../../../gen/lindm/validation/v1/string_rules_pb";
import { canonicalUuid, newRequestId } from "@/lib/ids";
import { toRpcFailure, type RpcFailure } from "@/lib/errors";

export const NIL_UUID = "00000000-0000-0000-0000-000000000000";
export const MAX_RESOURCES = editorBound(ServiceProfileSpecSchema.field.resources);
export const NAME_MAX = editorBound(ServiceProfileSpecSchema.field.name);
export const DESCRIPTION_MAX = editorBound(ServiceProfileSpecSchema.field.description);
export const UNIT_MAX = editorBound(ServiceDesiredStateSchema.field.unit);

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

export type DraftResource = {
  resourceId: string;
  unit: string;
  runtime: ServiceRuntimeState | "";
  enablement: ServiceEnablement | "";
  dependsOn: string[];
};

export type DraftSpec = {
  name: string;
  description: string;
  resources: DraftResource[];
};

export type PublishResource = {
  resourceId: string;
  desired: Pick<ServiceDesiredState, "unit" | "runtime" | "enablement">;
  dependsOn: string[];
};

export type PublishPayload = {
  requestId: string;
  profileId: string;
  expectedRevisionId?: string;
  spec: {
    name: string;
    description: string;
    resources: PublishResource[];
  };
  reason: string;
};

export const RUNTIME_OPTIONS = [
  { value: ServiceRuntimeState.UNMANAGED, label: "Unmanaged" },
  { value: ServiceRuntimeState.ACTIVE, label: "Active" },
  { value: ServiceRuntimeState.INACTIVE, label: "Inactive" },
] as const;

export const ENABLEMENT_OPTIONS = [
  { value: ServiceEnablement.UNMANAGED, label: "Unmanaged" },
  { value: ServiceEnablement.ENABLED, label: "Enabled" },
  { value: ServiceEnablement.DISABLED, label: "Disabled" },
] as const;

export function usableUuid(value: string): string | null {
  const canonical = canonicalUuid(value);
  if (canonical === null || canonical === NIL_UUID) return null;
  return canonical;
}

export function newResource(): DraftResource {
  return {
    resourceId: newRequestId(),
    unit: "",
    runtime: "",
    enablement: "",
    dependsOn: [],
  };
}

export function emptyDraft(): DraftSpec {
  return { name: "", description: "", resources: [newResource()] };
}

export function draftFromSpec(spec: ServiceProfileSpec): DraftSpec {
  return {
    name: spec.name,
    description: spec.description,
    resources: spec.resources.map((resource) => ({
      resourceId: usableUuid(resource.resourceId) ?? resource.resourceId,
      unit: resource.desired?.unit ?? "",
      runtime: definedRuntime(resource.desired?.runtime),
      enablement: definedEnablement(resource.desired?.enablement),
      dependsOn: resource.dependsOn.map((id) => usableUuid(id) ?? id),
    })),
  };
}

export function draftFromPayload(payload: PublishPayload): DraftSpec {
  return {
    name: payload.spec.name,
    description: payload.spec.description,
    resources: payload.spec.resources.map((resource) => ({
      resourceId: resource.resourceId,
      unit: resource.desired.unit,
      runtime: resource.desired.runtime,
      enablement: resource.desired.enablement,
      dependsOn: [...resource.dependsOn],
    })),
  };
}

export function removeResource(draft: DraftSpec, resourceId: string): DraftSpec {
  return {
    ...draft,
    resources: draft.resources
      .filter((resource) => resource.resourceId !== resourceId)
      .map((resource) => ({
        ...resource,
        dependsOn: resource.dependsOn.filter((id) => id !== resourceId),
      })),
  };
}

export function publishErrors(payload: PublishPayload): string[] {
  const result = validator.validate(
    PublishServiceProfileRevisionRequestSchema,
    create(PublishServiceProfileRevisionRequestSchema, payload),
  );
  if (result.kind === "invalid") return result.violations.map((violation) => violation.toString());
  if (result.kind === "error") return [`Profile validation failed: ${result.error.message}`];
  // Graph cycles are also checked by the server's resolver, outside the schema.
  return hasCycle(payload.spec.resources) ? ["Dependencies must not form a cycle."] : [];
}

export function capturePayload(input: {
  requestId: string;
  profileId: string;
  expectedRevisionId?: string;
  reason: string;
  draft: DraftSpec;
}): PublishPayload {
  const payload: PublishPayload = {
    requestId: input.requestId,
    profileId: input.profileId,
    spec: {
      name: input.draft.name,
      description: input.draft.description,
      resources: input.draft.resources.map((resource) => ({
        resourceId: resource.resourceId,
        desired: {
          unit: resource.unit,
          runtime: resource.runtime === "" ? ServiceRuntimeState.UNSPECIFIED : resource.runtime,
          enablement:
            resource.enablement === "" ? ServiceEnablement.UNSPECIFIED : resource.enablement,
        },
        dependsOn: [...resource.dependsOn].sort(),
      })),
    },
    reason: input.reason.trim(),
  };
  if (input.expectedRevisionId) payload.expectedRevisionId = input.expectedRevisionId;
  return payload;
}

// Shared toRpcFailure keeps Code.Aborted ambiguous. Only this explicit reason
// is a catalog conflict, and it never rebases by itself.
export function classifyPublishError(error: unknown): { failure: RpcFailure; conflict: boolean } {
  const failure = toRpcFailure(error);
  const connectError = ConnectError.from(error);
  const reason =
    connectError.metadata.get("lindm-reason") ?? connectError.metadata.get("Lindm-Reason") ?? "";
  const conflict =
    reason === "profile_revision_conflict" ||
    failure.message === "profile_revision_conflict" ||
    connectError.rawMessage === "profile_revision_conflict";
  return {
    conflict,
    failure: conflict ? { ...failure, ambiguous: false } : failure,
  };
}

export function publishFailureTitle(failure: RpcFailure, conflict: boolean): string {
  if (conflict) return "Catalog head conflict";
  if (failure.denied) return "Not authorized";
  if (failure.unauthenticated) return "Sign-in required";
  if (failure.message === "profile_revision_not_found") return "Profile revision not found";
  if (failure.message === "profile_recovery_hold") return "Profile catalog recovery hold";
  if (failure.message === "profile_revision_capacity") return "Profile revision capacity exhausted";
  if (failure.message === "invalid_profile_request") return "Profile request rejected";
  if (failure.code === Code.Aborted) return "Publish result unknown";
  if (failure.ambiguous) return "Publish result unknown";
  return "Publish failed";
}

export function formatSha256(bytes: Uint8Array): string {
  if (bytes.length !== 32) return "Digest unavailable";
  let hex = "";
  for (const byte of bytes) hex += byte.toString(16).padStart(2, "0");
  return hex;
}

export function formatRevisionNumber(value: bigint): string {
  return value > 0n ? value.toString() : "Not recorded";
}

export function runtimeLabel(value: ServiceRuntimeState | ""): string {
  return RUNTIME_OPTIONS.find((option) => option.value === value)?.label ?? "Not chosen";
}

export function enablementLabel(value: ServiceEnablement | ""): string {
  return ENABLEMENT_OPTIONS.find((option) => option.value === value)?.label ?? "Not chosen";
}

export function resourceLabel(resource: Pick<DraftResource, "resourceId" | "unit">): string {
  const unit = resource.unit.trim();
  return unit === ""
    ? `Unnamed resource ${resource.resourceId}`
    : `${unit} (${resource.resourceId})`;
}

function definedRuntime(value: ServiceRuntimeState | undefined): ServiceRuntimeState | "" {
  return value && isRuntime(value) ? value : "";
}

function definedEnablement(value: ServiceEnablement | undefined): ServiceEnablement | "" {
  return value && isEnablement(value) ? value : "";
}

function isRuntime(value: ServiceRuntimeState | ""): value is ServiceRuntimeState {
  return RUNTIME_OPTIONS.some((option) => option.value === value);
}

function isEnablement(value: ServiceEnablement | ""): value is ServiceEnablement {
  return ENABLEMENT_OPTIONS.some((option) => option.value === value);
}

function hasCycle(resources: Pick<DraftResource, "resourceId" | "dependsOn">[]): boolean {
  const ids = new Set(resources.map((resource) => resource.resourceId));
  const edges = new Map(
    resources.map((resource) => [
      resource.resourceId,
      resource.dependsOn.filter((id) => ids.has(id) && id !== resource.resourceId),
    ]),
  );
  const state = new Map<string, 0 | 1 | 2>();
  const visit = (id: string): boolean => {
    const mark = state.get(id) ?? 0;
    if (mark === 1) return true;
    if (mark === 2) return false;
    state.set(id, 1);
    for (const next of edges.get(id) ?? []) {
      if (visit(next)) return true;
    }
    state.set(id, 2);
    return false;
  };
  for (const id of edges.keys()) {
    if (visit(id)) return true;
  }
  return false;
}
