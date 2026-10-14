// SPDX-License-Identifier: Apache-2.0

import { create, fromJsonString, toJsonString } from "@bufbuild/protobuf";
import { Link } from "@tanstack/react-router";
import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { Trash2Icon } from "lucide-react";
import { useEffect, useMemo, useState, type ReactNode } from "react";
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
import { RpcError } from "@/components/ui/rpc-error";
import { SelectField } from "@/components/ui/select-field";
import { SuggestionPicker } from "@/components/ui/suggestion-picker";
import { Textarea } from "@/components/ui/textarea";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
import { toRpcFailure } from "@/lib/errors";
import { suggestionsQueryOptions } from "@/lib/suggestions";
import { formatTimestamp } from "@/lib/time";
import { useTargetPickers, type NameSlot } from "./pickers";
import { attributeDefinitionsQueryOptions, dynamicGroupPreviewQueryOptions } from "./queries";

// The server accepts a bounded AST (TargetExpression). Administrators edit a list
// of conditions joined by "all" or "any"; a condition may itself be a group of
// conditions with its own all/any (one level deep). Each condition reads as a
// sentence and can be negated ("is not"). Shapes this editor does not write stay
// intact and are shown read-only until the administrator replaces them.

type Match = "all" | "any";
type Kind = "os" | "label" | "hostname" | "lastSeen" | "attribute" | "group" | "nested" | "other";
export type Condition = {
  key: number;
  kind: Kind;
  exclude: boolean;
  osId: string;
  osVersion: string;
  label: string;
  prefix: string;
  days: number;
  attributeKey: string;
  attributeValue?: AttributeValue;
  groupId: string;
  // Conditions inside a nested group (kind "nested").
  nested?: Conditions;
  // Kept verbatim for filters this editor does not author (e.g. absolute date ranges).
  filter?: DeviceFilter;
};
export type Conditions = { match: Match; conditions: Condition[] };

const MAX_CONDITIONS = 16; // TargetChildren.indices max_items
const MAX_NODES = 64; // TargetExpression.nodes max_items
const MAX_DAYS = 366; // DeviceFilter.last_seen_within_seconds lte 366 days
const DAY = 86_400;
const kinds: { value: Kind; label: string }[] = [
  { value: "os", label: "Operating system" },
  { value: "label", label: "Label" },
  { value: "hostname", label: "Hostname" },
  { value: "lastSeen", label: "Last seen" },
  { value: "attribute", label: "Custom attribute" },
  { value: "group", label: "Device group" },
];
// Each kind's "is" / "is not" wording, so a row reads as a sentence.
const verbs: Record<Kind, [string, string]> = {
  os: ["is", "is not"],
  label: ["is", "is not"],
  hostname: ["starts with", "does not start with"],
  lastSeen: ["within", "not within"],
  attribute: ["is", "is not"],
  group: ["includes the device", "does not include the device"],
  nested: ["match", "do not match"],
  other: ["matches", "does not match"],
};
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
    days: 7,
    attributeKey: "",
    groupId: "",
    nested: kind === "nested" ? { match: "any", conditions: [blank("os")] } : undefined,
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
    f.lastSeenWithinSeconds > 0,
    !!f.lastSeenFrom || !!f.lastSeenUntil || f.agentRelease !== "",
  ].filter(Boolean).length;
  if (used === 1 && os) return { ...blank("os"), osId: f.osId, osVersion: f.osVersion };
  if (used === 1 && f.labels.length === 1) return { ...blank("label"), label: f.labels[0] };
  if (used === 1 && f.namePrefix) return { ...blank("hostname"), prefix: f.namePrefix };
  if (used === 1 && f.lastSeenWithinSeconds > 0 && f.lastSeenWithinSeconds % DAY === 0)
    return { ...blank("lastSeen"), days: f.lastSeenWithinSeconds / DAY };
  if (used === 1 && attributes.length === 1)
    return {
      ...blank("attribute"),
      attributeKey: attributes[0][0],
      attributeValue: attributes[0][1],
    };
  return { ...blank("other"), filter: f };
}

function item(nodes: TargetNode[], index: number, nested: boolean): Condition | undefined {
  const node = nodes[index];
  if (node?.node.case === "notIndex") {
    const inner = item(nodes, node.node.value, nested);
    return inner && !inner.exclude ? { ...inner, exclude: true } : undefined;
  }
  if (node?.node.case === "all" || node?.node.case === "any") {
    if (!nested) return undefined;
    const children = list(nodes, node.node.case, node.node.value.indices, false);
    return children ? { ...blank("nested"), nested: children } : undefined;
  }
  return leaf(node);
}

function list(nodes: TargetNode[], match: Match, indices: number[], nested: boolean) {
  const conditions: Condition[] = [];
  for (const index of indices) {
    const condition = item(nodes, index, nested);
    if (!condition) return undefined;
    conditions.push(condition);
  }
  return { match, conditions };
}

// Returns undefined when the expression is deeper than this editor shows.
export function parseExpression(expression: TargetExpression | undefined): Conditions | undefined {
  const nodes = expression?.nodes ?? [];
  if (nodes.length === 0) return { match: "all", conditions: [] };
  const root = nodes[nodes.length - 1];
  if (root.node.case === "all" || root.node.case === "any")
    return list(nodes, root.node.case, root.node.value.indices, true);
  const single = item(nodes, nodes.length - 1, true);
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
          lastSeenWithinSeconds: condition.kind === "lastSeen" ? condition.days * DAY : 0,
          attributes:
            condition.kind === "attribute" && condition.attributeKey && condition.attributeValue
              ? { [condition.attributeKey]: condition.attributeValue }
              : {},
        });
  return { case: "predicate", value: filter };
}

// Emits a condition's nodes; the returned depth is the rank its parent must exceed.
function emit(nodes: TargetNode[], condition: Condition): { index: number; depth: number } {
  let result: { index: number; depth: number };
  if (condition.kind === "nested" && condition.nested) {
    result = emitList(nodes, condition.nested);
  } else {
    nodes.push(create(TargetNodeSchema, { depth: 1, node: leafNode(condition) }));
    result = { index: nodes.length - 1, depth: 1 };
  }
  if (!condition.exclude) return result;
  nodes.push(
    create(TargetNodeSchema, {
      depth: result.depth + 1,
      node: { case: "notIndex", value: result.index },
    }),
  );
  return { index: nodes.length - 1, depth: result.depth + 1 };
}

function emitList(nodes: TargetNode[], { match, conditions }: Conditions) {
  const children = conditions.map((condition) => emit(nodes, condition));
  const depth = Math.max(...children.map((child) => child.depth)) + 1;
  nodes.push(
    create(TargetNodeSchema, {
      depth,
      node: { case: match, value: { indices: children.map((child) => child.index) } },
    }),
  );
  return { index: nodes.length - 1, depth };
}

export function compileConditions(value: Conditions): TargetNode[] {
  if (value.conditions.length === 0) return [];
  const nodes: TargetNode[] = [];
  emitList(nodes, value);
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
    case "lastSeen":
      return !Number.isInteger(condition.days) || condition.days < 1 || condition.days > MAX_DAYS;
    case "attribute":
      return !condition.attributeKey || !condition.attributeValue;
    case "group":
      return !condition.groupId;
    case "nested":
      return false;
    case "other":
      return false;
  }
}

// The first condition that blocks saving or previewing, described in words.
export function conditionsProblem(value: Conditions | undefined): string | undefined {
  if (!value) return undefined;
  if (value.conditions.length === 0)
    return "Add at least one condition. A dynamic group without conditions would include every device.";
  for (const [index, condition] of value.conditions.entries()) {
    if (condition.kind === "lastSeen" && incomplete(condition))
      return `Condition ${index + 1}: enter a whole number of days from 1 to ${MAX_DAYS}.`;
    if (incomplete(condition)) return `Complete or remove condition ${index + 1}.`;
    if (condition.kind === "nested") {
      const inner = condition.nested?.conditions ?? [];
      if (inner.length === 0) return `Add a condition to group ${index + 1}, or remove it.`;
      const blocked = inner.findIndex(incomplete);
      if (blocked >= 0) return `Complete or remove condition ${blocked + 1} in group ${index + 1}.`;
    }
  }
  if (compileConditions(value).length > MAX_NODES)
    return "This group has too many conditions to save. Remove some conditions.";
  return undefined;
}

// Checks the administrator's intent before protobuf validation, in their words.
export function validateDynamicGroup(request: PutDynamicGroupRequest): string | undefined {
  if (!request.group?.name.trim()) return "Enter a group name.";
  const problem = conditionsProblem(parseExpression(request.group.expression));
  if (problem) return problem;
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
  for (const label of f.labels) parts.push(`label is ${label}`);
  for (const [key, value] of Object.entries(f.attributes))
    parts.push(`${key} is ${attributeText(value)}`);
  if (f.namePrefix) parts.push(`hostname starts with “${f.namePrefix}”`);
  if (f.lastSeenWithinSeconds)
    parts.push(`last seen within ${daysText(f.lastSeenWithinSeconds / DAY)}`);
  if (f.lastSeenFrom) parts.push(`last seen after ${formatTimestamp(f.lastSeenFrom).local}`);
  if (f.lastSeenUntil) parts.push(`last seen before ${formatTimestamp(f.lastSeenUntil).local}`);
  if (f.agentRelease) parts.push(`agent release is ${f.agentRelease}`);
  if (parts.length === 0) return "any device with fresh inventory";
  return parts.join(" and ");
}

function daysText(days: number) {
  return days === 1 ? "1 day" : `${Number.isInteger(days) ? days : days.toFixed(1)} days`;
}

// The platform registry's name for a recorded OS ID ("ubuntu" → "Ubuntu"), from
// the same recorded values the picker offers; the ID itself until it loads.
function OsName({ osId }: { osId: string }) {
  const suggestions = useQuery(
    suggestionsQueryOptions(
      useAuthLifetime(),
      { field: SuggestionField.OS_ID },
      { prefix: osId, after: "" },
    ),
  );
  return <>{suggestions.data?.suggestions.find((item) => item.value === osId)?.label || osId}</>;
}

// One condition as the sentence it means, for read views and summaries.
export function ConditionText({
  condition,
  groupName: GroupName,
}: {
  condition: Condition;
  groupName: NameSlot;
}) {
  const [is, isNot] = verbs[condition.kind];
  const verb = condition.exclude ? isNot : is;
  switch (condition.kind) {
    case "os":
      return (
        <>
          Operating system {verb}{" "}
          {condition.osId ? <OsName osId={condition.osId} /> : "any operating system"}
          {condition.osVersion ? ` ${condition.osVersion}` : ""}
        </>
      );
    case "label":
      return (
        <>
          Label {verb} {condition.label}
        </>
      );
    case "hostname":
      return (
        <>
          Hostname {verb} “{condition.prefix}”
        </>
      );
    case "lastSeen":
      return (
        <>
          Last seen {verb} {daysText(condition.days)}
        </>
      );
    case "attribute":
      return (
        <>
          {condition.attributeKey} {verb} {attributeText(condition.attributeValue)}
        </>
      );
    case "group":
      return (
        <>
          {condition.exclude ? "Not in device group " : "In device group "}
          <GroupName value={condition.groupId} />
        </>
      );
    case "nested":
      return (
        <>
          {condition.exclude ? "None of: " : ""}
          <ConditionsText value={condition.nested} groupName={GroupName} />
        </>
      );
    case "other": {
      const text = filterText(condition.filter ?? create(DeviceFilterSchema));
      return condition.exclude ? (
        <>Not: {text}</>
      ) : (
        <>{text.charAt(0).toUpperCase() + text.slice(1)}</>
      );
    }
  }
}

// A whole condition list as a lead-in sentence and one row per condition.
export function ConditionsText({
  value,
  groupName,
}: {
  value: Conditions | undefined;
  groupName: NameSlot;
}) {
  if (!value || value.conditions.length === 0) return <>No conditions</>;
  if (value.conditions.length === 1)
    return <ConditionText condition={value.conditions[0]} groupName={groupName} />;
  return (
    <span className="inline-grid gap-0.5">
      <span>{value.match === "all" ? "All of these conditions" : "Any of these conditions"}:</span>
      <ul className="grid list-disc gap-0.5 pl-5">
        {value.conditions.map((condition) => (
          <li key={condition.key} className="break-words">
            <ConditionText condition={condition} groupName={groupName} />
          </li>
        ))}
      </ul>
    </span>
  );
}

function deviceCount(count: number) {
  return count === 1 ? "1 device" : `${count.toLocaleString()} devices`;
}

// Live, server-evaluated membership for an expression: the same matcher as a
// saved group, debounced while editing. A failed or pending count is named,
// never shown as zero.
export function MembershipPreview({
  expression,
  ready,
  sampleSize = 5,
  live = false,
}: {
  expression: TargetExpression;
  // False while the conditions are incomplete; nothing is asked.
  ready: boolean;
  sampleSize?: number;
  live?: boolean;
}) {
  const lifetime = useAuthLifetime();
  // Debounce on the serialized expression: the editor rebuilds the message on
  // every render, so object identity says nothing about a change.
  const json = toJsonString(TargetExpressionSchema, expression);
  const [delayed, setDelayed] = useState(json);
  useEffect(() => {
    const timer = setTimeout(() => setDelayed(json), 400);
    return () => clearTimeout(timer);
  }, [json]);
  const settled = useMemo(
    () => fromJsonString(TargetExpressionSchema, live ? delayed : json),
    [live, delayed, json],
  );
  const query = useQuery({
    ...dynamicGroupPreviewQueryOptions(lifetime, settled, sampleSize),
    enabled: ready && settled.nodes.length > 0,
    placeholderData: live ? keepPreviousData : undefined,
  });
  const maxAge = freshnessLabel(expression.inventoryMaxAgeSeconds);
  let body: ReactNode;
  if (!ready) {
    body = (
      <p className="text-muted-foreground">Complete the conditions to see which devices match.</p>
    );
  } else if (query.error) {
    body = (
      <RpcError failure={toRpcFailure(query.error)} title="Matching devices unknown">
        <p>Couldn&apos;t count matching devices.</p>
        <Button type="button" variant="outline" size="sm" onClick={() => void query.refetch()}>
          Count again
        </Button>
      </RpcError>
    );
  } else if (!query.data) {
    body = <p className="text-muted-foreground">Counting matching devices…</p>;
  } else {
    const data = query.data;
    const named = data.matchedDevices.map((device) => device.hostname.trim() || "Unnamed device");
    const more = data.matchedCount - named.length;
    body = (
      <>
        <p>
          {data.matchedCount === 0 ? (
            "No devices match right now."
          ) : (
            <>
              <span className="font-medium">
                {deviceCount(data.matchedCount)} {data.matchedCount === 1 ? "matches" : "match"}
              </span>
              {": "}
              {named.join(", ")}
              {more > 0 ? ` and ${more.toLocaleString()} more` : ""}.
            </>
          )}
          {query.isFetching ? <span className="text-muted-foreground"> Updating…</span> : null}
        </p>
        {data.unknownCount > 0 ? (
          <p className="text-muted-foreground">
            The group excludes {deviceCount(data.unknownCount)}. Their inventory is older than{" "}
            {maxAge}, or they have never reported inventory.
          </p>
        ) : null}
        {!data.complete ? (
          <p className="text-muted-foreground">
            Counted the first {deviceCount(data.evaluatedDeviceCount)} only; the total may be
            higher.
          </p>
        ) : null}
      </>
    );
  }
  return (
    <div
      role="status"
      aria-live="polite"
      aria-label="Matching devices"
      className="grid gap-1 text-sm"
    >
      {body}
    </div>
  );
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
  const [state, setState] = useState(() => {
    const parsed = parseExpression(group?.expression);
    // A new group opens on its first condition row rather than an empty list.
    return parsed?.conditions.length === 0 ? { ...parsed, conditions: [blank("os")] } : parsed;
  });
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
  const expression = group.expression ?? create(TargetExpressionSchema);
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
            This editor cannot show the full depth of these conditions. It preserves the conditions
            unless you replace them.
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
      <div className="grid gap-1.5 border-l-2 pl-3">
        <span className="text-sm font-medium">Matching devices</span>
        <MembershipPreview expression={expression} ready={!conditionsProblem(state)} live />
      </div>
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
          The group excludes devices with older inventory because it cannot confirm their
          membership.
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
  nestedIn,
  negation,
}: {
  id: string;
  value: Conditions;
  onChange: (value: Conditions) => void;
  disabled: boolean;
  groupName: NameSlot;
  // The 1-based number of the condition group this list sits in, when nested.
  nestedIn?: number;
  // A nested group's "match / do not match" choice, read inline with all/any.
  negation?: ReactNode;
}) {
  const { conditions } = value;
  function set(index: number, next: Condition) {
    onChange({ ...value, conditions: conditions.map((item, i) => (i === index ? next : item)) });
  }
  const full = conditions.length >= MAX_CONDITIONS;
  return (
    <fieldset className={nestedIn ? "grid min-w-0 gap-2" : "grid min-w-0 gap-3"}>
      <legend className={nestedIn ? "sr-only" : "mb-2 text-sm font-medium"}>
        {nestedIn ? `Conditions in group ${nestedIn}` : "Conditions"}
      </legend>
      <div className="flex flex-wrap items-center gap-2 text-sm">
        {nestedIn ? (
          <>
            <span>Devices that</span>
            {negation}
          </>
        ) : (
          <span>Include devices that match</span>
        )}
        <SelectField
          id={`${id}-match`}
          className="w-auto"
          aria-label={nestedIn ? `Group ${nestedIn} matches` : "Include devices that match"}
          disabled={disabled}
          value={value.match}
          options={[
            { value: "all", label: "All of these conditions" },
            { value: "any", label: "Any of these conditions" },
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
      <ol className="grid min-w-0 gap-2">
        {conditions.map((condition, index) => {
          const number = nestedIn ? `${nestedIn}.${index + 1}` : `${index + 1}`;
          return (
            <li
              key={condition.key}
              className={
                condition.kind === "nested"
                  ? "grid min-w-0 gap-2 border bg-muted/20 p-3"
                  : "grid min-w-0 gap-2"
              }
            >
              <ConditionRow
                id={`${id}-condition-${condition.key}`}
                number={number}
                condition={condition}
                disabled={disabled}
                groupName={groupName}
                onChange={(next) => set(index, next)}
                onRemove={() =>
                  onChange({ ...value, conditions: conditions.filter((_, i) => i !== index) })
                }
              />
            </li>
          );
        })}
      </ol>
      <div className="flex flex-wrap items-center gap-2">
        <Button
          type="button"
          variant="outline"
          size="sm"
          className="w-fit"
          disabled={disabled || full}
          onClick={() => onChange({ ...value, conditions: [...conditions, blank("os")] })}
        >
          Add condition
        </Button>
        {nestedIn ? null : (
          <Button
            type="button"
            variant="outline"
            size="sm"
            className="w-fit"
            disabled={disabled || full}
            onClick={() => onChange({ ...value, conditions: [...conditions, blank("nested")] })}
          >
            Add condition group
          </Button>
        )}
        {full ? (
          <span className="text-xs text-muted-foreground">
            Up to {MAX_CONDITIONS} conditions here.
          </span>
        ) : null}
      </div>
    </fieldset>
  );
}

function ConditionRow({
  id,
  number,
  condition,
  onChange,
  onRemove,
  disabled,
  groupName,
}: {
  id: string;
  number: string;
  condition: Condition;
  onChange: (next: Condition) => void;
  onRemove: () => void;
  disabled: boolean;
  groupName: NameSlot;
}) {
  const remove = (
    <Button
      type="button"
      variant="ghost"
      size="icon-sm"
      disabled={disabled}
      aria-label={
        condition.kind === "nested"
          ? `Remove condition group ${number}`
          : `Remove condition ${number}`
      }
      onClick={onRemove}
    >
      <Trash2Icon aria-hidden="true" />
    </Button>
  );
  const [is, isNot] = verbs[condition.kind];
  const verb = (
    <SelectField
      className="w-auto"
      aria-label={`Condition ${number} comparison`}
      disabled={disabled}
      value={condition.exclude ? "not" : "is"}
      options={[
        { value: "is", label: is },
        { value: "not", label: isNot },
      ]}
      onValueChange={(next) => onChange({ ...condition, exclude: next === "not" })}
    />
  );
  if (condition.kind === "nested" && condition.nested) {
    return (
      <>
        <div className="flex flex-wrap items-center justify-between gap-2">
          <span className="text-sm font-medium">Condition group {number}</span>
          {remove}
        </div>
        <ConditionList
          id={id}
          value={condition.nested}
          disabled={disabled}
          groupName={groupName}
          nestedIn={Number(number)}
          negation={verb}
          onChange={(nested) => onChange({ ...condition, nested })}
        />
      </>
    );
  }
  return (
    <div className="flex min-w-0 flex-wrap items-start gap-2">
      {condition.kind === "other" ? (
        <p className="min-w-0 flex-1 self-center text-sm">
          <ConditionText condition={condition} groupName={groupName} />
        </p>
      ) : (
        <>
          <SelectField
            className="w-auto min-w-36"
            aria-label={`Condition ${number}`}
            disabled={disabled}
            value={condition.kind}
            options={kinds}
            onValueChange={(next) => {
              const kind = kinds.find((entry) => entry.value === next)?.value;
              if (kind && kind !== condition.kind)
                onChange({ ...blank(kind), key: condition.key, exclude: condition.exclude });
            }}
          />
          {verb}
          <div className="min-w-48 flex-1">
            <ConditionValue
              id={id}
              number={number}
              condition={condition}
              disabled={disabled}
              onChange={onChange}
            />
          </div>
        </>
      )}
      <div className="flex h-9 items-center">{remove}</div>
    </div>
  );
}

function ConditionValue({
  id,
  number,
  condition,
  onChange,
  disabled,
}: {
  id: string;
  number: string;
  condition: Condition;
  onChange: (next: Condition) => void;
  disabled: boolean;
}) {
  const { groupPicker: GroupPicker } = useTargetPickers();
  // Pickers keep their "Condition N …" name for assistive technology; the row's
  // own field and comparison already say it visually.
  const quiet = "min-w-0 [&_[id$='-label']]:sr-only";
  switch (condition.kind) {
    case "os":
      return (
        <div className="grid items-start gap-2 sm:grid-cols-2">
          <div className={quiet}>
            <SuggestionPicker
              label={`Condition ${number} operating system`}
              placeholder="Choose an operating system"
              field={SuggestionField.OS_ID}
              allowTyped
              disabled={disabled}
              value={condition.osId}
              onChange={(osId) => onChange({ ...condition, osId, osVersion: "" })}
            />
          </div>
          <div className={quiet}>
            <SuggestionPicker
              label={`Condition ${number} version`}
              placeholder="Any version"
              field={SuggestionField.OS_VERSION}
              osId={condition.osId || undefined}
              allowTyped
              disabled={disabled}
              value={condition.osVersion}
              onChange={(osVersion) => onChange({ ...condition, osVersion })}
            />
          </div>
        </div>
      );
    case "label":
      return (
        <div className={quiet}>
          <SuggestionPicker
            label={`Condition ${number} label`}
            field={SuggestionField.DEVICE_LABEL}
            allowTyped
            disabled={disabled}
            value={condition.label}
            onChange={(label) => onChange({ ...condition, label })}
          />
        </div>
      );
    case "hostname":
      return (
        <Input
          id={`${id}-prefix`}
          aria-label={`Condition ${number} hostname beginning (case-sensitive)`}
          data-freeform="hostname prefix pattern"
          spellCheck={false}
          placeholder="For example, lab- (case-sensitive)"
          value={condition.prefix}
          onChange={(event) => onChange({ ...condition, prefix: event.target.value })}
        />
      );
    case "lastSeen": {
      // The range is checked here and named under the field, not by the
      // browser's own number validation, which would block the form silently.
      const invalid = incomplete(condition);
      return (
        <div className="grid gap-1">
          <div className="flex items-center gap-2 text-sm">
            <Input
              id={`${id}-days`}
              aria-label={`Condition ${number} days`}
              aria-invalid={invalid || undefined}
              aria-describedby={invalid ? `${id}-days-error` : undefined}
              data-freeform="number of days"
              className="w-24"
              type="number"
              inputMode="numeric"
              value={Number.isNaN(condition.days) ? "" : condition.days}
              onChange={(event) => onChange({ ...condition, days: event.target.valueAsNumber })}
            />
            <span>days</span>
          </div>
          {invalid ? (
            <p id={`${id}-days-error`} className="text-xs text-destructive">
              Enter a whole number of days from 1 to {MAX_DAYS}.
            </p>
          ) : null}
        </div>
      );
    }
    case "attribute":
      return (
        <AttributeCondition
          id={id}
          number={number}
          condition={condition}
          disabled={disabled}
          onChange={onChange}
        />
      );
    case "group":
      return (
        <div className={quiet}>
          <GroupPicker
            label={`Condition ${number} device group`}
            disabled={disabled}
            value={condition.groupId}
            onChange={(groupId) => onChange({ ...condition, groupId })}
          />
        </div>
      );
    default:
      return null;
  }
}

function AttributeCondition({
  id,
  number,
  condition,
  onChange,
  disabled,
}: {
  id: string;
  number: string;
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
  const valueLabel = `Condition ${number} value`;
  return (
    <div className="grid gap-2 sm:grid-cols-2">
      <div className="grid gap-1">
        <SelectField
          id={`${id}-attribute`}
          aria-label={`Condition ${number} attribute`}
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
            Couldn&apos;t load custom attributes. Reload the page to try again.
          </p>
        ) : !definitions.isPending && list.length === 0 ? (
          <p className="text-xs text-muted-foreground">
            No custom attributes exist yet.{" "}
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
        <SelectField
          id={`${id}-value`}
          aria-label={valueLabel}
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
      ) : definition?.type === AttributeType.ENUM ? (
        <SelectField
          id={`${id}-value`}
          aria-label={valueLabel}
          disabled={disabled}
          value={value?.case === "enumValue" ? value.value : ""}
          options={[
            { value: "", label: "Choose a value" },
            ...definition.enumValues.map((entry) => ({ value: entry, label: entry })),
          ]}
          onValueChange={(next) => setValue(next ? { case: "enumValue", value: next } : undefined)}
        />
      ) : definition?.type === AttributeType.INT ? (
        <Input
          id={`${id}-value`}
          aria-label={valueLabel}
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
      ) : definition?.type === AttributeType.STRING ? (
        <Input
          id={`${id}-value`}
          aria-label={valueLabel}
          data-freeform="custom attribute value to compare"
          maxLength={1024}
          value={value?.case === "stringValue" ? value.value : ""}
          onChange={(event) =>
            setValue(
              event.target.value ? { case: "stringValue", value: event.target.value } : undefined,
            )
          }
        />
      ) : null}
    </div>
  );
}
