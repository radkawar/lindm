import { create } from "@bufbuild/protobuf";
import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import {
  PutDynamicGroupRequestSchema,
  type DynamicTargetGroup,
} from "../../../gen/lindm/admin/v1/targeting_pb";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
import { newRequestId } from "@/lib/ids";
import { adminClient } from "@/lib/rpc";
import {
  ConditionsText,
  DynamicGroupFields,
  freshnessChoices,
  freshnessLabel,
  MembershipPreview,
  parseExpression,
  validateDynamicGroup,
} from "./dynamic-group";
import { discardSettledAttempt, TargetMutation } from "./mutation";
import type { NameSlot } from "./pickers";
import { dynamicGroupsQueryOptions } from "./queries";
import { ListStatus, TargetPagination } from "./list";

// What saving a dynamic group does, verified against the targeting service:
// assignments evaluate the conditions at their next preview and rollouts keep
// the cohort they froze when they started. Nothing is locked after saving.
const SAVE_EFFECT =
  "Saving changes no device by itself. Assignments use these conditions at their next preview; running rollouts keep the devices they started with. You can edit the group later.";
const MEMBERS_LISTED = 10;

export function DynamicGroupsView({ groupName }: { groupName: NameSlot }) {
  const lifetime = useAuthLifetime();
  const [afterId, setAfterId] = useState("");
  const [creating, setCreating] = useState(false);
  const [createGeneration, setCreateGeneration] = useState(0);
  const list = useQuery(dynamicGroupsQueryOptions(lifetime, afterId, ""));
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
        <Button onClick={startCreate}>New dynamic group</Button>
      </div>
      <Dialog open={creating} onOpenChange={setCreating}>
        <DialogContent className="max-h-[90svh] overflow-y-auto sm:max-w-3xl">
          <DialogHeader>
            <DialogTitle>New dynamic group</DialogTitle>
            <DialogDescription>{SAVE_EFFECT}</DialogDescription>
          </DialogHeader>
          <TargetMutation
            key={createGeneration}
            title="Create group"
            framed={false}
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
        </DialogContent>
      </Dialog>
      <ListStatus
        pending={list.isPending}
        error={list.error}
        empty={list.data?.length === 0}
        firstPage={!afterId}
        noun="dynamic groups"
        emptyDescription="Create one to target devices by operating system, label, hostname, last contact, custom attribute or group membership."
        emptyAction={<Button onClick={startCreate}>New dynamic group</Button>}
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
  const name = group.name || "Unnamed group";
  const parsed = parseExpression(group.expression);
  const seconds = group.expression?.inventoryMaxAgeSeconds ?? 0;
  return (
    <li className="grid min-w-0 gap-2 p-4">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <h3 className="min-w-0 break-words font-medium">{name}</h3>
        <Button
          variant="outline"
          size="sm"
          aria-label={`Edit ${name}`}
          onClick={() => {
            discardSettledAttempt(`dynamic-group:${group.groupId}`);
            setEditing(true);
          }}
        >
          Edit
        </Button>
      </div>
      <div className="text-sm">
        {parsed ? (
          <ConditionsText value={parsed} groupName={groupName} />
        ) : (
          <span className="text-muted-foreground">
            Conditions nested more deeply than this page shows. Edit to replace them.
          </span>
        )}
      </div>
      {group.expression ? (
        <MembershipPreview expression={group.expression} ready sampleSize={MEMBERS_LISTED} />
      ) : null}
      <p className="text-xs text-muted-foreground">
        Inventory must be newer than {freshnessLabel(seconds)}.
      </p>
      <Dialog open={editing} onOpenChange={setEditing}>
        <DialogContent className="max-h-[90svh] overflow-y-auto sm:max-w-3xl">
          <DialogHeader>
            <DialogTitle>Edit {name}</DialogTitle>
            <DialogDescription>{SAVE_EFFECT}</DialogDescription>
          </DialogHeader>
          {editing ? (
            <TargetMutation
              key={`${group.groupId}:${group.revision}`}
              title="Save group"
              framed={false}
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
        </DialogContent>
      </Dialog>
    </li>
  );
}
