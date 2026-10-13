import { type DescEnum, type JsonObject } from "@bufbuild/protobuf";
import {
  OwnershipMode,
  OwnershipModeSchema,
  OwnershipPolicySchema,
  ReleaseBehavior,
  ReleaseBehaviorSchema,
} from "../../../gen/lindm/resource/v1/common_pb";
import type { QualifiedResourceKind } from "../../../gen/lindm/admin/v1/profiles_pb";
import { Label } from "@/components/ui/label";
import { SelectField } from "@/components/ui/select-field";
import { TypedFields, type ReferenceChoice } from "./typed-fields";

const MODE_LABELS: Record<number, string> = {
  [OwnershipMode.CREATE_ONLY]: "Create it only if it doesn't exist",
  [OwnershipMode.APPROVED_ADOPTION]: "Take over the existing one (needs an approved assignment)",
};
const RELEASE_LABELS: Record<number, string> = {
  [ReleaseBehavior.RESTORE_OWNED]: "Undo what lindm changed",
  [ReleaseBehavior.RETAIN]: "Leave it as it is",
};

function enumNumber(schema: DescEnum, value: unknown): number | undefined {
  return typeof value === "number"
    ? value
    : schema.values.find((entry) => entry.name === value)?.number;
}

// How lindm takes and gives back control of one setting. Only the operations the
// server dispatches for this setting type are offered (a kernel setting can
// only be taken over, a service is left as it is on removal); a stored
// combination outside them stays visible and is marked as never sent.
export function OwnershipFields({
  id,
  value,
  qualified,
  references,
  disabled,
  onChange,
}: {
  id: string;
  value: JsonObject;
  // undefined: this type isn't dispatched; null: qualification unknown.
  qualified: QualifiedResourceKind | undefined | null;
  references: ReferenceChoice[];
  disabled: boolean;
  onChange: (value: JsonObject) => void;
}) {
  const controls = [
    {
      field: "mode",
      label: "If the item already exists on the device",
      schema: OwnershipModeSchema,
      labels: MODE_LABELS,
      allowed: qualified?.ownershipModes,
    },
    {
      field: "release",
      label: "When you remove this setting",
      schema: ReleaseBehaviorSchema,
      labels: RELEASE_LABELS,
      allowed: qualified?.releaseBehaviors,
    },
  ] as const;
  return (
    <div className="grid min-w-0 gap-3">
      {controls.map((control) => {
        const current = enumNumber(control.schema, value[control.field]);
        const choices = (
          control.allowed ??
          control.schema.values.map((entry) => entry.number).filter((number) => number !== 0)
        ).filter((number) => control.labels[number] !== undefined);
        const unqualified =
          qualified !== null && current !== undefined && !choices.includes(current);
        const options = [
          ...choices.map((number) => ({ value: number, label: control.labels[number] })),
          ...(unqualified && current !== undefined
            ? [
                {
                  value: current,
                  label: `${control.labels[current] ?? "Other"} (devices won't apply this)`,
                },
              ]
            : []),
        ];
        return (
          <div key={control.field} className="grid gap-1.5">
            <Label htmlFor={`${id}-${control.field}`}>{control.label}</Label>
            <SelectField
              id={`${id}-${control.field}`}
              value={current ?? ""}
              disabled={disabled || (options.length === 1 && !unqualified)}
              options={options}
              onValueChange={(next) => {
                const number = Number(next);
                const name = control.schema.values.find((entry) => entry.number === number)?.name;
                if (name) onChange({ ...value, [control.field]: name });
              }}
            />
          </div>
        );
      })}
      <TypedFields
        schema={{
          ...OwnershipPolicySchema,
          fields: OwnershipPolicySchema.fields.filter(
            (entry) => entry.jsonName !== "mode" && entry.jsonName !== "release",
          ),
        }}
        value={value}
        id={`${id}-policy`}
        references={references}
        disabled={disabled}
        onChange={onChange}
      />
    </div>
  );
}
