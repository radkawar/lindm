import { create, toJsonString } from "@bufbuild/protobuf";
import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import {
  DynamicTargetGroupSchema,
  PutDynamicGroupRequestSchema,
  type DynamicTargetGroup,
} from "../../../gen/lindm/admin/v1/targeting_pb";
import { Button } from "@/components/ui/button";
import { TechnicalDetails } from "@/components/ui/technical-details";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
import { newRequestId } from "@/lib/ids";
import { adminClient } from "@/lib/rpc";
import {
  ConditionText,
  DynamicGroupFields,
  freshnessChoices,
  freshnessLabel,
  parseExpression,
  validateDynamicGroup,
} from "./dynamic-group";
import { discardSettledAttempt, TargetMutation } from "./mutation";
import type { NameSlot } from "./pickers";
import { dynamicGroupsQueryOptions } from "./queries";
import { ListStatus, TargetPagination } from "./list";

export function DynamicGroupsView({ groupName }: { groupName: NameSlot }) {
  const lifetime = useAuthLifetime();
  const [afterId, setAfterId] = useState("");
  const [creating, setCreating] = useState(false);
  const [createGeneration, setCreateGeneration] = useState(0);
  const list = useQuery(dynamicGroupsQueryOptions(lifetime, afterId));
  const groups = [...(list.data ?? [])].sort((a, b) => a.name.localeCompare(b.name));
  const startCreate = () => {
    discardSettledAttempt("dynamic-group:new");
    setCreateGeneration((value) => value + 1);
    setCreating(true);
  };
  return (
    <section
      className="grid min-w-0 gap-4"
      aria-labelledby="dynamic-groups-title"
      aria-busy={list.isFetching}
    >
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="grid max-w-3xl gap-1">
          <h2 id="dynamic-groups-title" className="text-base font-semibold">
            Dynamic groups
          </h2>
          <p className="text-sm text-muted-foreground">
            Include devices automatically from their latest inventory. Use them as rollout targets.
          </p>
        </div>
        {creating ? null : <Button onClick={startCreate}>New dynamic group</Button>}
      </div>
      {creating ? (
        <div className="grid min-w-0 gap-2">
          <TargetMutation
            key={createGeneration}
            title="Create dynamic group"
            formKey="dynamic-group:new"
            schema={PutDynamicGroupRequestSchema}
            initial={() =>
              create(PutDynamicGroupRequestSchema, {
                requestId: newRequestId(),
                group: {
                  groupId: newRequestId(),
                  expression: { inventoryMaxAgeSeconds: freshnessChoices[1].seconds },
                },
                expectedRevision: 0n,
              })
            }
            send={(request, signal) => adminClient.putDynamicGroup(request, { signal })}
            onAccepted={() => setCreating(false)}
            validate={validateDynamicGroup}
            fields={(request, change, disabled) => (
              <DynamicGroupFields
                request={request}
                change={change}
                disabled={disabled}
                groupName={groupName}
              />
            )}
          />
          <Button variant="outline" className="w-fit" onClick={() => setCreating(false)}>
            Close
          </Button>
        </div>
      ) : null}
      <ListStatus
        pending={list.isPending}
        error={list.error}
        empty={list.data?.length === 0}
        firstPage={!afterId}
        noun="dynamic groups"
        emptyDescription="Create one to target devices by operating system, label, hostname, custom attribute or group membership."
        emptyAction={creating ? null : <Button onClick={startCreate}>New dynamic group</Button>}
      />
      {!list.error && groups.length > 0 ? (
        <ul className="grid min-w-0 divide-y border" aria-label="Dynamic groups">
          {groups.map((group) => (
            <DynamicGroupRow key={group.groupId} group={group} groupName={groupName} />
          ))}
        </ul>
      ) : null}
      <TargetPagination
        afterId={afterId}
        nextId={list.data?.length === 100 ? list.data.at(-1)?.groupId : undefined}
        busy={list.isFetching}
        onPage={setAfterId}
      />
    </section>
  );
}

function DynamicGroupRow({ group, groupName }: { group: DynamicTargetGroup; groupName: NameSlot }) {
  const [editing, setEditing] = useState(false);
  const parsed = parseExpression(group.expression);
  const seconds = group.expression?.inventoryMaxAgeSeconds ?? 0;
  return (
    <li className="grid min-w-0 gap-2 p-4">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <h3 className="min-w-0 break-words font-medium">{group.name || "Unnamed group"}</h3>
        <Button
          variant="outline"
          size="sm"
          aria-expanded={editing}
          aria-label={`${editing ? "Close editor for" : "Edit"} ${group.name || "unnamed group"}`}
          onClick={() => {
            if (!editing) discardSettledAttempt(`dynamic-group:${group.groupId}`);
            setEditing(!editing);
          }}
        >
          {editing ? "Close" : "Edit"}
        </Button>
      </div>
      {parsed ? (
        <div className="grid gap-1 text-sm">
          <p className="text-muted-foreground">
            {parsed.conditions.length === 1
              ? "Includes devices where:"
              : parsed.match === "all"
                ? "Includes devices that match all of:"
                : "Includes devices that match any of:"}
          </p>
          <ul className="grid list-disc gap-0.5 pl-5">
            {parsed.conditions.map((condition) => (
              <li key={condition.key} className="break-words">
                <ConditionText condition={condition} groupName={groupName} />
              </li>
            ))}
          </ul>
        </div>
      ) : (
        <p className="text-sm text-muted-foreground">
          Nested conditions. Open Details to inspect them.
        </p>
      )}
      <p className="text-xs text-muted-foreground">
        Inventory must be newer than {freshnessLabel(seconds)}.
      </p>
      <TechnicalDetails
        items={[
          { label: "Group ID", value: group.groupId },
          { label: "Revision", value: group.revision.toString() },
        ]}
      >
        <pre className="mt-2 overflow-auto whitespace-pre-wrap break-all text-xs">
          {toJsonString(DynamicTargetGroupSchema, group, { prettySpaces: 2 })}
        </pre>
      </TechnicalDetails>
      {editing ? (
        <TargetMutation
          key={`${group.groupId}:${group.revision}`}
          title="Save dynamic group"
          formKey={`dynamic-group:${group.groupId}`}
          schema={PutDynamicGroupRequestSchema}
          initial={() =>
            create(PutDynamicGroupRequestSchema, {
              requestId: newRequestId(),
              group,
              expectedRevision: group.revision,
            })
          }
          send={(request, signal) => adminClient.putDynamicGroup(request, { signal })}
          onAccepted={() => setEditing(false)}
          validate={validateDynamicGroup}
          fields={(request, change, disabled) => (
            <DynamicGroupFields
              request={request}
              change={change}
              disabled={disabled}
              groupName={groupName}
            />
          )}
        />
      ) : null}
    </li>
  );
}
