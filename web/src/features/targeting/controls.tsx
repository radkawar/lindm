import { create } from "@bufbuild/protobuf";
import { timestampFromDate, timestampDate, type Timestamp } from "@bufbuild/protobuf/wkt";
import { useId, type ReactNode } from "react";
import { TargetRefSchema, type TargetRef } from "../../../gen/lindm/policy/v1/targeting_pb";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { DynamicGroupPicker, useTargetPickers } from "./pickers";

const targetKinds = [
  { value: "staticGroupId", label: "Device group" },
  { value: "dynamicGroupId", label: "Dynamic group" },
  { value: "deviceId", label: "One device" },
] as const;

// The kind is a visible segmented choice, so the Target picker lists only named
// groups or devices, never the kinds themselves. Each control has its own label:
// "<label> type" for the kind and "<label>" for the chosen group or device.
export function TargetControl({
  label,
  value,
  onChange,
  disabled,
}: {
  label: string;
  value?: TargetRef;
  onChange: (value: TargetRef) => void;
  disabled?: boolean;
}) {
  const { devicePicker: DevicePicker, groupPicker: GroupPicker } = useTargetPickers();
  const name = useId();
  const kind = value?.target.case ?? "staticGroupId";
  const Picker =
    kind === "deviceId"
      ? DevicePicker
      : kind === "dynamicGroupId"
        ? DynamicGroupPicker
        : GroupPicker;
  return (
    <div className="grid min-w-0 gap-3">
      <fieldset className="grid gap-1.5" disabled={disabled}>
        <legend className="mb-1.5 text-sm font-medium">{`${label} type`}</legend>
        <div className="flex flex-wrap gap-x-4 gap-y-2">
          {targetKinds.map((option) => (
            <label key={option.value} className="flex items-center gap-2 text-sm">
              <input
                type="radio"
                name={name}
                value={option.value}
                checked={kind === option.value}
                onChange={() =>
                  onChange(create(TargetRefSchema, { target: { case: option.value, value: "" } }))
                }
              />
              {option.label}
            </label>
          ))}
        </div>
      </fieldset>
      <Picker
        label={label}
        value={value?.target.value ?? ""}
        disabled={disabled}
        onChange={(next) =>
          onChange(create(TargetRefSchema, { target: { case: kind, value: next } }))
        }
      />
    </div>
  );
}

export function NumberControl({
  label,
  value,
  onChange,
  percent = false,
}: {
  label: string;
  value: number;
  onChange: (value: number) => void;
  percent?: boolean;
}) {
  return (
    <label className="grid gap-1.5 text-sm">
      {label}
      <Input
        type="number"
        data-freeform="numeric rollout threshold"
        required
        step={percent ? "0.01" : "1"}
        value={percent ? value / 100 : value}
        onChange={(event) =>
          onChange(
            percent ? Math.round(Number(event.target.value) * 100) : Number(event.target.value),
          )
        }
      />
    </label>
  );
}

export function TimeControl({
  label,
  value,
  onChange,
}: {
  label: string;
  value?: Timestamp;
  onChange: (value?: Timestamp) => void;
}) {
  const date = value ? timestampDate(value) : undefined;
  const local = date
    ? new Date(date.getTime() - date.getTimezoneOffset() * 60000).toISOString().slice(0, 19)
    : "";
  return (
    <label className="grid gap-1.5 text-sm">
      {label}
      <Input
        type="datetime-local"
        step="1"
        value={local}
        onChange={(event) =>
          onChange(event.target.value ? timestampFromDate(new Date(event.target.value)) : undefined)
        }
      />
    </label>
  );
}

export function ReasonControl({
  value,
  onChange,
  label = "Reason for this change",
}: {
  value: string;
  onChange: (value: string) => void;
  label?: string;
}) {
  return (
    <label className="grid gap-1.5 text-sm">
      {label}
      <Textarea
        required
        data-freeform="audit reason"
        value={value}
        onChange={(event) => onChange(event.target.value)}
      />
    </label>
  );
}

export function OptionalControls({ title, children }: { title: string; children: ReactNode }) {
  return (
    <details className="border p-3">
      <summary className="cursor-pointer text-sm font-medium">{title}</summary>
      <div className="mt-3 grid min-w-0 gap-4">{children}</div>
    </details>
  );
}
