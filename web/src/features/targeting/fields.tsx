import {
  ScalarType,
  type DescField,
  type DescMessage,
  type JsonObject,
  type JsonValue,
} from "@bufbuild/protobuf";
import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { SelectField } from "@/components/ui/select-field";
import type { TargetPickers } from "./pickers";

const names: Record<string, string> = {
  staticGroupId: "Device group",
  osId: "Operating system",
  osVersion: "Operating system version",
  namePrefix: "Hostname prefix",
  inventoryMaxAgeSeconds: "Maximum inventory age (seconds)",
  notIndex: "Negated node index",
  indices: "Child node indices",
  all: "All children",
  any: "Any children",
  predicate: "Inventory filter",
  nodes: "Conditions",
};
function labelFor(name: string) {
  const words = name.replace(/([A-Z])/g, " $1").toLowerCase();
  return names[name] ?? words.charAt(0).toUpperCase() + words.slice(1);
}
function object(value: JsonValue | undefined): JsonObject {
  return value && typeof value === "object" && !Array.isArray(value) ? value : {};
}
function defaultValue(field: DescField): JsonValue {
  if (field.fieldKind === "message" || field.fieldKind === "map") return {};
  if (field.fieldKind === "list") return [];
  if (field.fieldKind === "enum") return field.enum.values[0]?.name ?? 0;
  return field.scalar === ScalarType.BOOL
    ? false
    : field.scalar === ScalarType.STRING || field.scalar === ScalarType.BYTES
      ? ""
      : 0;
}

// Dynamic-group expression editing only. Assignment and rollout tasks use authored controls.
export function TargetFields({
  schema,
  value,
  onChange,
  pickers,
  disabled,
}: {
  schema: DescMessage;
  value: JsonObject;
  onChange: (value: JsonObject) => void;
  pickers: TargetPickers;
  disabled: boolean;
}) {
  function set(field: DescField, next: JsonValue | undefined) {
    const updated = { ...value };
    if (field.oneof) for (const sibling of field.oneof.fields) delete updated[sibling.jsonName];
    if (next === undefined) delete updated[field.jsonName];
    else updated[field.jsonName] = next;
    onChange(updated);
  }
  return (
    <div className="grid min-w-0 gap-3">
      {schema.oneofs.map((oneof) => (
        <label className="grid gap-1 text-sm" key={oneof.name}>
          {labelFor(oneof.name)}
          <SelectField
            aria-label={labelFor(oneof.name)}
            disabled={disabled}
            value={
              oneof.fields.find((field) => value[field.jsonName] !== undefined)?.jsonName ?? ""
            }
            options={[
              { value: "", label: "Choose a type" },
              ...oneof.fields.map((field) => ({
                value: field.jsonName,
                label: labelFor(field.jsonName),
              })),
            ]}
            onValueChange={(name) => {
              const field = oneof.fields.find((item) => item.jsonName === name);
              if (field) set(field, defaultValue(field));
            }}
          />
        </label>
      ))}
      {schema.fields.map((field) => {
        const name = field.jsonName;
        const current = value[name];
        if (["requestId", "expectedRevision", "revision", "groupId"].includes(name)) return null;
        if (field.oneof && current === undefined) return null;
        const label = labelFor(name);
        const Picker = name === "staticGroupId" ? pickers.groupPicker : undefined;
        if (Picker)
          return (
            <Picker
              key={name}
              label={label}
              value={typeof current === "string" ? current : ""}
              disabled={disabled}
              onChange={(next) => set(field, next || undefined)}
            />
          );
        if (field.fieldKind === "message" && field.message.typeName !== "google.protobuf.Timestamp")
          return (
            <fieldset key={name} className="grid gap-2 border p-3" disabled={disabled}>
              <legend className="text-sm font-medium">{label}</legend>
              <TargetFields
                schema={field.message}
                value={object(current)}
                onChange={(next) => set(field, next)}
                pickers={pickers}
                disabled={disabled}
              />
            </fieldset>
          );
        if (field.fieldKind === "list" && field.listKind === "message") {
          const values = Array.isArray(current) ? current : [];
          return (
            <fieldset key={name} className="grid gap-3 border p-3" disabled={disabled}>
              <legend className="text-sm font-medium">{label}</legend>
              {values.map((item, index) => (
                <div className="grid gap-2 border p-3" key={index}>
                  <TargetFields
                    schema={field.message}
                    value={object(item)}
                    onChange={(next) =>
                      set(
                        field,
                        values.map((entry, i) => (i === index ? next : entry)),
                      )
                    }
                    pickers={pickers}
                    disabled={disabled}
                  />
                  <Button
                    type="button"
                    variant="outline"
                    disabled={disabled}
                    onClick={() =>
                      set(
                        field,
                        values.filter((_, i) => i !== index),
                      )
                    }
                  >
                    Remove {label.toLowerCase()} {index + 1}
                  </Button>
                </div>
              ))}
              <Button
                type="button"
                variant="outline"
                disabled={disabled}
                onClick={() => set(field, [...values, {}])}
              >
                Add {label.toLowerCase()}
              </Button>
            </fieldset>
          );
        }
        if (field.fieldKind === "map" || field.fieldKind === "list")
          return (
            <JSONField
              key={name}
              label={label}
              value={current ?? defaultValue(field)}
              onChange={(next) => set(field, next)}
              disabled={disabled}
            />
          );
        if (field.fieldKind === "enum")
          return (
            <label key={name} className="grid gap-1 text-sm">
              {label}
              <SelectField
                aria-label={label}
                disabled={disabled}
                value={String(current ?? field.enum.values[0]?.name ?? "")}
                options={field.enum.values.map((item) => ({
                  value: item.name,
                  label: labelFor(item.localName.toLowerCase().replaceAll("_", " ")),
                }))}
                onValueChange={(next) => set(field, next)}
              />
            </label>
          );
        if (field.fieldKind === "scalar" && field.scalar === ScalarType.BOOL)
          return (
            <label key={name} className="flex gap-2 text-sm">
              <input
                type="checkbox"
                checked={current === true}
                disabled={disabled}
                onChange={(event) => set(field, event.target.checked)}
              />
              {label}
            </label>
          );
        const numeric =
          field.fieldKind === "scalar" &&
          field.scalar !== ScalarType.STRING &&
          field.scalar !== ScalarType.BYTES;
        return (
          <label key={name} className="grid gap-1 text-sm">
            {label}
            <Input
              disabled={disabled}
              type={numeric ? "number" : "text"}
              value={typeof current === "string" || typeof current === "number" ? current : ""}
              placeholder={field.fieldKind === "message" ? "2026-10-11T12:00:00Z" : undefined}
              onChange={(event) =>
                set(
                  field,
                  event.target.value === ""
                    ? undefined
                    : numeric
                      ? Number(event.target.value)
                      : event.target.value,
                )
              }
            />
          </label>
        );
      })}
    </div>
  );
}
function JSONField({
  label,
  value,
  onChange,
  disabled,
}: {
  label: string;
  value: JsonValue;
  onChange: (value: JsonValue) => void;
  disabled: boolean;
}) {
  const [text, setText] = useState(JSON.stringify(value, null, 2));
  const [error, setError] = useState("");
  return (
    <label className="grid gap-1 text-sm">
      {label} (JSON)
      <Textarea
        value={text}
        disabled={disabled}
        onChange={(event) => {
          setText(event.target.value);
          try {
            const parsed: JsonValue = JSON.parse(event.target.value);
            onChange(parsed);
            setError("");
            event.target.setCustomValidity("");
          } catch {
            setError("Enter valid JSON.");
            event.target.setCustomValidity("Enter valid JSON.");
          }
        }}
      />
      {error ? <span role="alert">{error}</span> : null}
    </label>
  );
}
