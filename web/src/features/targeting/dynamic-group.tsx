import { create } from "@bufbuild/protobuf";
import { Link } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { useState, type ReactNode } from "react";
import {
  AttributeType,
  AttributeValueSchema,
  DeviceFilterSchema,
  type AttributeValue,
  type DeviceFilter,
} from "../../../gen/lindm/admin/v1/inventory_management_pb";
import { SuggestionField } from "../../../gen/lindm/admin/v1/suggestions_pb";
import {
  PutDynamicGroupRequestSchema,
  TargetExpressionSchema,
  TargetNodeSchema,
  type PutDynamicGroupRequest,
  type TargetExpression,
  type TargetNode,
} from "../../../gen/lindm/admin/v1/targeting_pb";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { SelectField } from "@/components/ui/select-field";
import { SuggestionPicker } from "@/components/ui/suggestion-picker";
import { Textarea } from "@/components/ui/textarea";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
import { formatTimestamp } from "@/lib/time";
import { useTargetPickers, type NameSlot } from "./pickers";
import { attributeDefinitionsQueryOptions } from "./queries";

// The server accepts a bounded AST (TargetExpression). Administrators edit one
// flat list of conditions joined by "all" or "any", each optionally excluded;
// that covers every expression this editor writes. Other shapes stay intact and
// are shown read-only until the administrator replaces them.

type Kind = "os" | "label" | "hostname" | "attribute" | "group" | "other";
export type Condition = {
  key: number;
  kind: Kind;
  exclude: boolean;
  osId: string;
  osVersion: string;
  label: string;
  prefix: string;
  attributeKey: string;
  attributeValue?: AttributeValue;
  groupId: string;
  // Kept verbatim for filters this editor does not author (e.g. last-seen ranges).
  filter?: DeviceFilter;
};
export type Conditions = { match: "all" | "any"; conditions: Condition[] };

const MAX_CONDITIONS = 16; // TargetChildren.indices max_items
const kinds: { value: Kind; label: string }[] = [
  { value: "os", label: "Operating system" },
  { value: "label", label: "Device label" },
  { value: "hostname", label: "Hostname starts with" },
  { value: "attribute", label: "Custom attribute" },
  { value: "group", label: "Device group membership" },
];
export const freshnessChoices = [
  { seconds: 900, label: "15 minutes" },
  { seconds: 3600, label: "1 hour" },
  { seconds: 21600, label: "6 hours" },
  { seconds: 86400, label: "24 hours" },
];
export function freshnessLabel(seconds: number) {
  return (
    freshnessChoices.find((choice) => choice.seconds === seconds)?.label ??
    (seconds % 3600 === 0 ? `${seconds / 3600} hours` : `${Math.round(seconds / 60)} minutes`)
  );
}

let nextKey = 0;
function blank(kind: Kind): Condition {
  return {
    key: nextKey++,
    kind,
    exclude: false,
    osId: "",
    osVersion: "",
    label: "",
    prefix: "",
    attributeKey: "",
    groupId: "",
  };
}

function leaf(node: TargetNode | undefined): Condition | undefined {
  if (node?.node.case === "staticGroupId") return { ...blank("group"), groupId: node.node.value };
  if (node?.node.case !== "predicate") return undefined;
  const f = node.node.value;
  const attributes = Object.entries(f.attributes);
  const os = f.osId !== "" || f.osVersion !== "";
  const used = [
    os,
    f.labels.length > 0,
    attributes.length > 0,
    f.namePrefix !== "",
    !!f.lastSeenFrom || !!f.lastSeenUntil || f.agentRelease !== "",
  ].filter(Boolean).length;
  if (used === 1 && os) return { ...blank("os"), osId: f.osId, osVersion: f.osVersion };
  if (used === 1 && f.labels.length === 1) return { ...blank("label"), label: f.labels[0] };
  if (used === 1 && f.namePrefix) return { ...blank("hostname"), prefix: f.namePrefix };
  if (used === 1 && attributes.length === 1)
    return {
      ...blank("attribute"),
      attributeKey: attributes[0][0],
      attributeValue: attributes[0][1],
    };
  return { ...blank("other"), filter: f };
}

function withExclusion(nodes: TargetNode[], index: number): Condition | undefined {
  const node = nodes[index];
  if (node?.node.case === "notIndex") {
    const inner = leaf(nodes[node.node.value]);
    return inner ? { ...inner, exclude: true } : undefined;
  }
  return leaf(node);
}

// Returns undefined when the expression is not a flat list this editor can show.
export function parseExpression(expression: TargetExpression | undefined): Conditions | undefined {
  const nodes = expression?.nodes ?? [];
  if (nodes.length === 0) return { match: "all", conditions: [] };
  const root = nodes[nodes.length - 1];
  if (root.node.case === "all" || root.node.case === "any") {
    const conditions: Condition[] = [];
    for (const index of root.node.value.indices) {
      const condition = withExclusion(nodes, index);
      if (!condition) return undefined;
      conditions.push(condition);
    }
    return { match: root.node.case, conditions };
  }
  const single = withExclusion(nodes, nodes.length - 1);
  return single ? { match: "all", conditions: [single] } : undefined;
}

function leafNode(condition: Condition): TargetNode["node"] {
  if (condition.kind === "group") return { case: "staticGroupId", value: condition.groupId };
  const filter =
    condition.kind === "other"
      ? (condition.filter ?? create(DeviceFilterSchema))
      : create(DeviceFilterSchema, {
          osId: condition.kind === "os" ? condition.osId : "",
          osVersion: condition.kind === "os" ? condition.osVersion : "",
          labels: condition.kind === "label" && condition.label ? [condition.label] : [],
          namePrefix: condition.kind === "hostname" ? condition.prefix : "",
          attributes:
            condition.kind === "attribute" && condition.attributeKey && condition.attributeValue
              ? { [condition.attributeKey]: condition.attributeValue }
              : {},
        });
  return { case: "predicate", value: filter };
}

export function compileConditions({ match, conditions }: Conditions): TargetNode[] {
  if (conditions.length === 0) return [];
  const nodes: TargetNode[] = [];
  const roots: number[] = [];
  for (const condition of conditions) {
    nodes.push(create(TargetNodeSchema, { depth: 1, node: leafNode(condition) }));
    if (condition.exclude)
      nodes.push(
        create(TargetNodeSchema, { depth: 2, node: { case: "notIndex", value: nodes.length - 1 } }),
      );
    roots.push(nodes.length - 1);
  }
  const depth = conditions.some((condition) => condition.exclude) ? 3 : 2;
  nodes.push(create(TargetNodeSchema, { depth, node: { case: match, value: { indices: roots } } }));
  return nodes;
}

function incomplete(condition: Condition) {
  switch (condition.kind) {
    case "os":
      return !condition.osId && !condition.osVersion;
    case "label":
      return !condition.label;
    case "hostname":
      return !condition.prefix;
    case "attribute":
      return !condition.attributeKey || !condition.attributeValue;
    case "group":
      return !condition.groupId;
    case "other":
      return false;
  }
}

// Checks the administrator's intent before protobuf validation, in their words.
export function validateDynamicGroup(request: PutDynamicGroupRequest): string | undefined {
  if (!request.group?.name.trim()) return "Enter a group name.";
  const parsed = parseExpression(request.group.expression);
  if (parsed && parsed.conditions.length === 0)
    return "Add at least one condition. A dynamic group without conditions would include every device.";
  const index = parsed?.conditions.findIndex(incomplete) ?? -1;
  if (index >= 0) return `Complete or remove condition ${index + 1}.`;
  if (!request.reason.trim()) return "Enter a reason for this change.";
  return undefined;
}

function attributeText(value: AttributeValue | undefined) {
  switch (value?.value.case) {
    case "boolValue":
      return value.value.value ? "yes" : "no";
    case "intValue":
      return value.value.value.toString();
    case "stringValue":
    case "enumValue":
      return `“${value.value.value}”`;
    default:
      return "(no value)";
  }
}

function filterText(f: DeviceFilter) {
  const parts: string[] = [];
  if (f.osId) parts.push(`operating system is ${f.osId}`);
  if (f.osVersion) parts.push(`OS version is ${f.osVersion}`);
  for (const label of f.labels) parts.push(`has label “${label}”`);
  for (const [key, value] of Object.entries(f.attributes))
    parts.push(`${key} is ${attributeText(value)}`);
  if (f.namePrefix) parts.push(`hostname starts with “${f.namePrefix}”`);
  if (f.lastSeenFrom) parts.push(`last seen after ${formatTimestamp(f.lastSeenFrom).local}`);
  if (f.lastSeenUntil) parts.push(`last seen before ${formatTimestamp(f.lastSeenUntil).local}`);
  if (f.agentRelease) parts.push(`agent release is ${f.agentRelease}`);
  if (parts.length === 0) return "Any device with fresh inventory";
  const text = parts.join(" and ");
  return text.charAt(0).toUpperCase() + text.slice(1);
}

export function ConditionText({
  condition,
  groupName: GroupName,
}: {
  condition: Condition;
  groupName: NameSlot;
}) {
  const text: ReactNode =
    condition.kind === "group" ? (
      <>
        Member of <GroupName value={condition.groupId} />
      </>
    ) : (
      filterText(leafNode(condition).value as DeviceFilter)
    );
  return condition.exclude ? <>Not: {text}</> : <>{text}</>;
}

export function DynamicGroupFields({
  request,
  change,
  disabled,
  groupName,
}: {
  request: PutDynamicGroupRequest;
  change: (request: PutDynamicGroupRequest) => void;
  disabled: boolean;
  groupName: NameSlot;
}) {
  const group = request.group;
  const [state, setState] = useState(() => parseExpression(group?.expression));
  if (!group) return null;
  const id = `dynamic-group-${group.groupId}`;
  function update(next: {
    conditions?: Conditions;
    name?: string;
    seconds?: number;
    reason?: string;
  }) {
    if (!group) return;
    if (next.conditions) setState(next.conditions);
    const expression = group.expression;
    change(
      create(PutDynamicGroupRequestSchema, {
        ...request,
        reason: next.reason ?? request.reason,
        group: {
          ...group,
          name: next.name ?? group.name,
          expression: create(TargetExpressionSchema, {
            inventoryMaxAgeSeconds:
              next.seconds ?? expression?.inventoryMaxAgeSeconds ?? freshnessChoices[1].seconds,
            nodes: next.conditions ? compileConditions(next.conditions) : (expression?.nodes ?? []),
          }),
        },
      }),
    );
  }
  const seconds = group.expression?.inventoryMaxAgeSeconds ?? 0;
  return (
    <fieldset disabled={disabled} className="grid min-w-0 gap-4">
      <div className="grid gap-1.5">
        <Label htmlFor={`${id}-name`}>Group name</Label>
        <Input
          id={`${id}-name`}
          data-freeform="new or renamed dynamic group name"
          maxLength={128}
          value={group.name}
          onChange={(event) => update({ name: event.target.value })}
        />
      </div>
      {state ? (
        <ConditionList
          id={id}
          value={state}
          disabled={disabled}
          groupName={groupName}
          onChange={(conditions) => update({ conditions })}
        />
      ) : (
        <div className="grid gap-2 border bg-muted/30 p-3 text-sm">
          <p>
            These conditions are nested more deeply than this editor shows. They are kept as they
            are unless you replace them.
          </p>
          <Button
            type="button"
            variant="outline"
            className="w-fit"
            onClick={() => update({ conditions: { match: "all", conditions: [blank("os")] } })}
          >
            Replace with new conditions
          </Button>
        </div>
      )}
      <div className="grid gap-1.5">
        <Label htmlFor={`${id}-freshness`}>Inventory must be newer than</Label>
        <SelectField
          id={`${id}-freshness`}
          disabled={disabled}
          aria-describedby={`${id}-freshness-help`}
          value={seconds || ""}
          options={[
            ...(seconds && !freshnessChoices.some((choice) => choice.seconds === seconds)
              ? [{ value: seconds, label: freshnessLabel(seconds) }]
              : []),
            ...freshnessChoices.map((choice) => ({ value: choice.seconds, label: choice.label })),
          ]}
          onValueChange={(next) => update({ seconds: Number(next) })}
        />
        <p id={`${id}-freshness-help`} className="text-xs text-muted-foreground">
          Devices whose inventory is older count as unknown and are not included.
        </p>
      </div>
      <div className="grid gap-1.5">
        <Label htmlFor={`${id}-reason`}>Reason for this change</Label>
        <Textarea
          id={`${id}-reason`}
          data-freeform="audit reason"
          value={request.reason}
          onChange={(event) => update({ reason: event.target.value })}
        />
      </div>
    </fieldset>
  );
}

function ConditionList({
  id,
  value,
  onChange,
  disabled,
  groupName,
}: {
  id: string;
  value: Conditions;
  onChange: (value: Conditions) => void;
  disabled: boolean;
  groupName: NameSlot;
}) {
  const { conditions } = value;
  function set(index: number, next: Condition) {
    onChange({ ...value, conditions: conditions.map((item, i) => (i === index ? next : item)) });
  }
  return (
    <fieldset className="grid min-w-0 gap-3">
      <legend className="mb-2 text-sm font-medium">Conditions</legend>
      <div className="grid gap-1.5">
        <Label htmlFor={`${id}-match`}>Include devices that match</Label>
        <SelectField
          id={`${id}-match`}
          disabled={disabled}
          value={value.match}
          options={[
            { value: "all", label: "All conditions" },
            { value: "any", label: "Any condition" },
          ]}
          onValueChange={(next) => {
            if (next === "all" || next === "any") onChange({ ...value, match: next });
          }}
        />
      </div>
      {conditions.length === 0 ? (
        <p className="text-sm text-muted-foreground">
          No conditions yet. Add one to choose which devices belong to this group.
        </p>
      ) : null}
      <ol className="grid min-w-0 gap-3">
        {conditions.map((condition, index) => (
          <li key={condition.key} className="grid min-w-0 gap-3 border p-3">
            <ConditionFields
              id={`${id}-condition-${condition.key}`}
              number={index + 1}
              condition={condition}
              disabled={disabled}
              groupName={groupName}
              onChange={(next) => set(index, next)}
              onRemove={() =>
                onChange({ ...value, conditions: conditions.filter((_, i) => i !== index) })
              }
            />
          </li>
        ))}
      </ol>
      <div className="flex flex-wrap items-center gap-3">
        <Button
          type="button"
          variant="outline"
          className="w-fit"
          disabled={disabled || conditions.length >= MAX_CONDITIONS}
          onClick={() => onChange({ ...value, conditions: [...conditions, blank("os")] })}
        >
          Add condition
        </Button>
        {conditions.length >= MAX_CONDITIONS ? (
          <span className="text-xs text-muted-foreground">
            A group can have up to {MAX_CONDITIONS} conditions.
          </span>
        ) : null}
      </div>
    </fieldset>
  );
}

function ConditionFields({
  id,
  number,
  condition,
  onChange,
  onRemove,
  disabled,
  groupName,
}: {
  id: string;
  number: number;
  condition: Condition;
  onChange: (next: Condition) => void;
  onRemove: () => void;
  disabled: boolean;
  groupName: NameSlot;
}) {
  const { groupPicker: GroupPicker } = useTargetPickers();
  return (
    <>
      <div className="flex flex-wrap items-end gap-3">
        <div className="grid min-w-48 flex-1 gap-1.5">
          <Label htmlFor={`${id}-kind`}>Condition {number}</Label>
          {condition.kind === "other" ? (
            <p id={`${id}-kind`} className="text-sm">
              <ConditionText condition={condition} groupName={groupName} />
            </p>
          ) : (
            <SelectField
              id={`${id}-kind`}
              disabled={disabled}
              value={condition.kind}
              options={kinds}
              onValueChange={(next) => {
                const kind = kinds.find((entry) => entry.value === next)?.value;
                if (kind && kind !== condition.kind)
                  onChange({ ...blank(kind), key: condition.key, exclude: condition.exclude });
              }}
            />
          )}
        </div>
        <Button
          type="button"
          variant="outline"
          disabled={disabled}
          aria-label={`Remove condition ${number}`}
          onClick={onRemove}
        >
          Remove
        </Button>
      </div>
      {condition.kind === "os" ? (
        <div className="grid gap-3 sm:grid-cols-2">
          <SuggestionPicker
            label="Operating system"
            field={SuggestionField.OS_ID}
            allowTyped
            disabled={disabled}
            value={condition.osId}
            onChange={(osId) => onChange({ ...condition, osId, osVersion: "" })}
          />
          <SuggestionPicker
            label="Version (optional)"
            field={SuggestionField.OS_VERSION}
            osId={condition.osId || undefined}
            allowTyped
            disabled={disabled}
            value={condition.osVersion}
            onChange={(osVersion) => onChange({ ...condition, osVersion })}
          />
        </div>
      ) : condition.kind === "label" ? (
        <SuggestionPicker
          label="Label"
          field={SuggestionField.DEVICE_LABEL}
          allowTyped
          disabled={disabled}
          value={condition.label}
          onChange={(label) => onChange({ ...condition, label })}
        />
      ) : condition.kind === "hostname" ? (
        <div className="grid gap-1.5">
          <Label htmlFor={`${id}-prefix`}>Hostname starts with</Label>
          <Input
            id={`${id}-prefix`}
            data-freeform="hostname prefix pattern"
            spellCheck={false}
            aria-describedby={`${id}-prefix-help`}
            value={condition.prefix}
            onChange={(event) => onChange({ ...condition, prefix: event.target.value })}
          />
          <p id={`${id}-prefix-help`} className="text-xs text-muted-foreground">
            Case-sensitive. For example, “lab-” matches lab-01 and lab-02.
          </p>
        </div>
      ) : condition.kind === "attribute" ? (
        <AttributeCondition id={id} condition={condition} disabled={disabled} onChange={onChange} />
      ) : condition.kind === "group" ? (
        <GroupPicker
          label="Device group"
          disabled={disabled}
          value={condition.groupId}
          onChange={(groupId) => onChange({ ...condition, groupId })}
        />
      ) : null}
      <label className="flex items-center gap-2 text-sm">
        <input
          type="checkbox"
          checked={condition.exclude}
          disabled={disabled}
          onChange={(event) => onChange({ ...condition, exclude: event.target.checked })}
        />
        Exclude devices that match this condition
      </label>
    </>
  );
}

function AttributeCondition({
  id,
  condition,
  onChange,
  disabled,
}: {
  id: string;
  condition: Condition;
  onChange: (next: Condition) => void;
  disabled: boolean;
}) {
  const definitions = useQuery(attributeDefinitionsQueryOptions(useAuthLifetime()));
  const list = [...(definitions.data?.definitions ?? [])].sort((a, b) =>
    a.key.localeCompare(b.key),
  );
  const definition = list.find((entry) => entry.key === condition.attributeKey);
  const value = condition.attributeValue?.value;
  function setValue(next: AttributeValue["value"] | undefined) {
    onChange({
      ...condition,
      attributeValue: next ? create(AttributeValueSchema, { value: next }) : undefined,
    });
  }
  return (
    <div className="grid gap-3 sm:grid-cols-2">
      <div className="grid gap-1.5">
        <Label htmlFor={`${id}-attribute`}>Attribute</Label>
        <SelectField
          id={`${id}-attribute`}
          disabled={disabled || definitions.isPending}
          value={condition.attributeKey}
          options={[
            {
              value: "",
              label: definitions.isPending ? "Loading attributes…" : "Choose an attribute",
            },
            ...(condition.attributeKey && !definition
              ? [{ value: condition.attributeKey, label: condition.attributeKey }]
              : []),
            ...list.map((entry) => ({ value: entry.key, label: entry.key })),
          ]}
          onValueChange={(attributeKey) =>
            onChange({ ...condition, attributeKey, attributeValue: undefined })
          }
        />
        {definitions.error ? (
          <p role="alert" className="text-xs text-destructive">
            Couldn't load custom attributes. Reload the page to try again.
          </p>
        ) : !definitions.isPending && list.length === 0 ? (
          <p className="text-xs text-muted-foreground">
            No custom attributes are defined yet.{" "}
            <Link to="/settings" className="underline underline-offset-4">
              Define them in Settings
            </Link>
            .
          </p>
        ) : definitions.data?.nextAfterKey ? (
          <p className="text-xs text-muted-foreground">Showing the first 200 attributes.</p>
        ) : null}
      </div>
      {definition?.type === AttributeType.BOOL ? (
        <div className="grid gap-1.5">
          <Label htmlFor={`${id}-value`}>Value</Label>
          <SelectField
            id={`${id}-value`}
            disabled={disabled}
            value={value?.case === "boolValue" ? String(value.value) : ""}
            options={[
              { value: "", label: "Choose a value" },
              { value: "true", label: "Yes" },
              { value: "false", label: "No" },
            ]}
            onValueChange={(next) =>
              setValue(next ? { case: "boolValue", value: next === "true" } : undefined)
            }
          />
        </div>
      ) : definition?.type === AttributeType.ENUM ? (
        <div className="grid gap-1.5">
          <Label htmlFor={`${id}-value`}>Value</Label>
          <SelectField
            id={`${id}-value`}
            disabled={disabled}
            value={value?.case === "enumValue" ? value.value : ""}
            options={[
              { value: "", label: "Choose a value" },
              ...definition.enumValues.map((entry) => ({ value: entry, label: entry })),
            ]}
            onValueChange={(next) =>
              setValue(next ? { case: "enumValue", value: next } : undefined)
            }
          />
        </div>
      ) : definition?.type === AttributeType.INT ? (
        <div className="grid gap-1.5">
          <Label htmlFor={`${id}-value`}>Value</Label>
          <Input
            id={`${id}-value`}
            type="number"
            step="1"
            data-freeform="custom attribute value to compare"
            value={value?.case === "intValue" ? value.value.toString() : ""}
            onChange={(event) =>
              setValue(
                /^-?\d+$/.test(event.target.value)
                  ? { case: "intValue", value: BigInt(event.target.value) }
                  : undefined,
              )
            }
          />
        </div>
      ) : definition?.type === AttributeType.STRING ? (
        <div className="grid gap-1.5">
          <Label htmlFor={`${id}-value`}>Value</Label>
          <Input
            id={`${id}-value`}
            data-freeform="custom attribute value to compare"
            maxLength={1024}
            value={value?.case === "stringValue" ? value.value : ""}
            onChange={(event) =>
              setValue(
                event.target.value ? { case: "stringValue", value: event.target.value } : undefined,
              )
            }
          />
        </div>
      ) : null}
    </div>
  );
}
