// SPDX-License-Identifier: Apache-2.0

import { type DescEnum, type JsonObject, type JsonValue } from "@bufbuild/protobuf";
import type { QualifiedResourceKind } from "../../../gen/lindm/admin/v1/profiles_pb";
import {
  OwnershipModeSchema,
  ReleaseBehaviorSchema,
} from "../../../gen/lindm/resource/v1/common_pb";
import { desiredField, object } from "./resource-draft";

// What the server reports it dispatches (ListQualifiedResourceKinds). Unknown
// while loading or after a failed read: never treated as qualified or refused.
export type Qualification =
  { status: "unknown" } | { status: "known"; kinds: readonly QualifiedResourceKind[] };

// ResourceRef.kind numbers follow the desired-state field numbers (see withDerivedRef).
function armResourceKind(arm: string): number | undefined {
  const field = desiredField(arm);
  return field ? field.number - 9 : undefined;
}

// The qualification entry for a desired-state arm; undefined when the server
// doesn't dispatch it, null when qualification is unknown.
export function kindQualification(
  qualification: Qualification,
  arm: string,
): QualifiedResourceKind | undefined | null {
  if (qualification.status === "unknown") return null;
  const kind = armResourceKind(arm);
  return qualification.kinds.find((entry) => entry.kind === kind);
}

function enumName(schema: DescEnum, value: JsonValue | undefined): string {
  return typeof value === "number"
    ? (schema.values.find((entry) => entry.number === value)?.name ?? "")
    : String(value ?? "");
}

// The ownership a newly chosen kind dispatches with: the draft's mode and
// release when the kind qualifies them, otherwise its first qualified ones.
export function qualifiedOwnership(
  ownership: JsonObject,
  entry: QualifiedResourceKind | undefined | null,
): JsonObject {
  if (!entry) return ownership;
  const pick = (schema: DescEnum, current: JsonValue | undefined, allowed: number[]) => {
    const names = allowed.map((value) => enumName(schema, value));
    const name = enumName(schema, current);
    return names.includes(name) ? name : (names[0] ?? name);
  };
  return {
    ...object(ownership),
    mode: pick(OwnershipModeSchema, ownership.mode, entry.ownershipModes),
    release: pick(ReleaseBehaviorSchema, ownership.release, entry.releaseBehaviors),
  };
}
