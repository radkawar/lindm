import { create, createRegistry } from "@bufbuild/protobuf";
import { createValidator } from "@bufbuild/protovalidate";
import { queryOptions, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { toast } from "sonner";
import {
  DeleteDeviceGroupRequestSchema,
  SetDeviceGroupRequestSchema,
  type DeviceGroup,
  type SetDeviceGroupRequest,
  type DeleteDeviceGroupRequest,
} from "../../../gen/lindm/admin/v1/authz_groups_pb";
import { audit_reason } from "../../../gen/lindm/validation/v1/string_rules_pb";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { EmptyState } from "@/components/ui/empty-state";
import { RpcError } from "@/components/ui/rpc-error";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { TechnicalDetails } from "@/components/ui/technical-details";
import { MultiPicker, type PickerSlot } from "@/components/ui/search-picker";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
import type { AuthLifetime } from "@/lib/auth-lifetime";
import { classifyRpcFailure, toRpcFailure, type RpcFailure } from "@/lib/errors";
import { adminClient } from "@/lib/rpc";
import { describeViolations } from "@/lib/validation";

const validator = createValidator({ registry: createRegistry(audit_reason) });

export function groupsQueryOptions(lifetime: AuthLifetime, pageToken: string) {
  return queryOptions({
    queryKey: ["device-groups", lifetime.generation, pageToken] as const,
    meta: { authGeneration: lifetime.generation },
    queryFn: async ({ signal }) => {
      const result = await adminClient.listDeviceGroups(
        { pageSize: 50, pageToken },
        { signal: AbortSignal.any([signal, lifetime.signal]), timeoutMs: 30_000 },
      );
      lifetime.signal.throwIfAborted();
      return result;
    },
    retry: false,
  });
}

function deviceCount(count: number) {
  return count === 1 ? "1 device" : `${count} devices`;
}

export function GroupsView({ devicePicker }: { devicePicker: PickerSlot }) {
  const lifetime = useAuthLifetime();
  const [pageToken, setPageToken] = useState("");
  const [creating, setCreating] = useState(false);
  const [createGeneration, setCreateGeneration] = useState(0);
  const list = useQuery(groupsQueryOptions(lifetime, pageToken));
  const groups = [...(list.data?.groups ?? [])].sort((a, b) => a.name.localeCompare(b.name));
  const startCreate = () => {
    setCreateGeneration((value) => value + 1);
    setCreating(true);
  };
  return (
    <section
      className="grid min-w-0 gap-4"
      aria-labelledby="device-groups-title"
      aria-busy={list.isFetching}
    >
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="grid max-w-3xl gap-1">
          <h2 id="device-groups-title" className="text-base font-semibold">
            Device groups
          </h2>
          <p className="text-sm text-muted-foreground">
            Named sets of devices. Accounts limited to a group can manage only its devices. Only
            admins with access to all devices can edit groups.
          </p>
        </div>
        {creating ? null : <Button onClick={startCreate}>New group</Button>}
      </div>
      {creating ? (
        <div className="grid min-w-0 gap-2">
          <GroupEditor
            key={createGeneration}
            devicePicker={devicePicker}
            onDone={() => setCreating(false)}
          />
          <Button variant="outline" className="w-fit" onClick={() => setCreating(false)}>
            Close
          </Button>
        </div>
      ) : null}
      {list.isPending ? (
        <div role="status" className="grid gap-3">
          <span className="text-sm text-muted-foreground">Loading groups…</span>
          <Skeleton className="h-24 w-full" />
        </div>
      ) : null}
      {list.error ? (
        <RpcError failure={toRpcFailure(list.error)}>
          {list.data ? <p>Showing the groups from the last refresh.</p> : null}
        </RpcError>
      ) : null}
      {groups.length > 0 ? (
        <ul className="grid min-w-0 divide-y border" aria-label="Device groups">
          {groups.map((group) => (
            <GroupRow
              key={`${group.id}:${group.name}:${group.deviceIds.join(",")}`}
              group={group}
              devicePicker={devicePicker}
            />
          ))}
        </ul>
      ) : null}
      {!list.error && list.data?.groups.length === 0 ? (
        pageToken ? (
          <EmptyState title="No more device groups" description="Return to the first page." />
        ) : (
          <EmptyState
            title="No device groups yet"
            description="Create a group to limit an account to a set of devices."
            action={creating ? null : <Button onClick={startCreate}>New group</Button>}
          />
        )
      ) : null}
      {pageToken || list.data?.nextPageToken ? (
        <div className="flex flex-wrap gap-2">
          <Button
            variant="outline"
            disabled={!pageToken || list.isFetching}
            onClick={() => setPageToken("")}
          >
            First page
          </Button>
          <Button
            variant="outline"
            disabled={!list.data?.nextPageToken || list.isFetching}
            onClick={() => setPageToken(list.data?.nextPageToken ?? "")}
          >
            Next page
          </Button>
        </div>
      ) : null}
    </section>
  );
}

function GroupRow({ group, devicePicker }: { group: DeviceGroup; devicePicker: PickerSlot }) {
  const [editing, setEditing] = useState(false);
  const name = group.name || "Unnamed group";
  return (
    <li className="grid min-w-0 gap-2 p-4">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div className="grid min-w-0 gap-0.5">
          <h3 className="break-words font-medium">{name}</h3>
          <p className="text-sm text-muted-foreground">{deviceCount(group.deviceIds.length)}</p>
        </div>
        <Button
          variant="outline"
          size="sm"
          aria-expanded={editing}
          aria-label={`${editing ? "Close editor for" : "Edit"} ${name}`}
          onClick={() => setEditing(!editing)}
        >
          {editing ? "Close" : "Edit"}
        </Button>
      </div>
      <TechnicalDetails items={[{ label: "Group ID", value: group.id }]} />
      {editing ? (
        <GroupEditor group={group} devicePicker={devicePicker} onDone={() => setEditing(false)} />
      ) : null}
    </li>
  );
}

function GroupEditor({
  group,
  onDone,
  devicePicker,
}: {
  group?: DeviceGroup;
  onDone: () => void;
  devicePicker: PickerSlot;
}) {
  const lifetime = useAuthLifetime();
  const client = useQueryClient();
  const [groupId] = useState(() => group?.id ?? crypto.randomUUID());
  const [name, setName] = useState(group?.name ?? "");
  const [members, setMembers] = useState(group?.deviceIds ?? []);
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [failure, setFailure] = useState<RpcFailure | null>(null);
  const [completed, setCompleted] = useState(false);
  const [attempt, setAttempt] = useState<SetDeviceGroupRequest | DeleteDeviceGroupRequest | null>(
    null,
  );

  async function save(remove: boolean) {
    if (busy || lifetime.signal.aborted) return;
    const exact =
      attempt ??
      (remove
        ? create(DeleteDeviceGroupRequestSchema, {
            requestId: crypto.randomUUID(),
            groupId,
            reason,
          })
        : create(SetDeviceGroupRequestSchema, {
            requestId: crypto.randomUUID(),
            groupId,
            name,
            reason,
            deviceIds: members.filter(Boolean),
          }));
    const validation =
      exact.$typeName === "lindm.admin.v1.SetDeviceGroupRequest"
        ? validator.validate(SetDeviceGroupRequestSchema, exact)
        : validator.validate(DeleteDeviceGroupRequestSchema, exact);
    if (validation.kind !== "valid") {
      setError(
        validation.kind === "invalid"
          ? describeViolations(validation.violations)
          : validation.error.message,
      );
      return;
    }
    setAttempt(exact);
    setBusy(true);
    setError("");
    setFailure(null);
    try {
      const options = { signal: lifetime.signal, timeoutMs: 30_000 };
      if (exact.$typeName === "lindm.admin.v1.SetDeviceGroupRequest")
        await adminClient.setDeviceGroup(exact, options);
      else await adminClient.deleteDeviceGroup(exact, options);
      lifetime.signal.throwIfAborted();
      setCompleted(true);
      toast.success(
        exact.$typeName === "lindm.admin.v1.DeleteDeviceGroupRequest"
          ? "Group deleted"
          : "Group saved",
      );
      await client.invalidateQueries({ queryKey: ["device-groups", lifetime.generation] });
      onDone();
    } catch (cause) {
      if (!lifetime.signal.aborted) {
        const normalized = toRpcFailure(cause);
        setFailure(normalized);
        const feedback = classifyRpcFailure(normalized);
        const notify = feedback.tone === "destructive" ? toast.error : toast;
        notify(feedback.title, { description: feedback.action });
        if (!normalized.ambiguous) setAttempt(null);
      }
    } finally {
      if (!lifetime.signal.aborted) setBusy(false);
    }
  }

  return (
    <form
      aria-label={group ? `Edit ${group.name || "unnamed group"}` : undefined}
      className={
        group ? "grid min-w-0 gap-4 border-t pt-4" : "grid min-w-0 gap-4 border bg-card p-4 sm:p-6"
      }
      onSubmit={(event) => {
        event.preventDefault();
        void save(false);
      }}
    >
      {group ? null : <h3 className="font-semibold">Create group</h3>}
      <label className="grid gap-2 text-sm font-medium">
        Group name
        <Input
          aria-label="Group name"
          data-freeform="new or renamed group name"
          required
          maxLength={128}
          value={name}
          disabled={busy || attempt !== null}
          onChange={(event) => setName(event.target.value)}
        />
      </label>
      <MultiPicker
        label="Member devices"
        values={members}
        onChange={setMembers}
        picker={devicePicker}
        disabled={busy || attempt !== null}
      />
      <label className="grid gap-2 text-sm font-medium">
        Reason for this change
        <Input
          aria-label="Group change reason"
          data-freeform="audit reason"
          required
          value={reason}
          disabled={busy || attempt !== null}
          onChange={(event) => setReason(event.target.value)}
        />
      </label>
      {error ? (
        <Alert variant="destructive">
          <AlertTitle>Check group details</AlertTitle>
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      ) : null}
      {failure ? <RpcError failure={failure} /> : null}
      {busy ? (
        <p role="status" className="text-sm text-muted-foreground">
          Saving group…
        </p>
      ) : null}
      {completed ? (
        <p role="status" className="border bg-muted/30 p-3 text-sm">
          {attempt?.$typeName === "lindm.admin.v1.DeleteDeviceGroupRequest"
            ? "Group deleted."
            : "Group saved."}
        </p>
      ) : (
        <div className="flex flex-wrap gap-2">
          <Button
            type="submit"
            disabled={busy || attempt?.$typeName === "lindm.admin.v1.DeleteDeviceGroupRequest"}
          >
            {attempt ? "Try again" : "Save group"}
          </Button>
          {group ? (
            <Button
              type="button"
              variant="destructive"
              aria-describedby={reason.trim() === "" ? `${groupId}-delete-help` : undefined}
              disabled={
                busy ||
                reason.trim() === "" ||
                attempt?.$typeName === "lindm.admin.v1.SetDeviceGroupRequest"
              }
              onClick={() => {
                if (
                  attempt ||
                  window.confirm(
                    `Delete the group “${group.name}” (${deviceCount(group.deviceIds.length)})? Accounts limited to this group lose access to these devices. The devices stay enrolled. This can't be undone.`,
                  )
                )
                  void save(true);
              }}
            >
              {attempt ? "Try deleting again" : "Delete group"}
            </Button>
          ) : null}
          {group && reason.trim() === "" ? (
            <p id={`${groupId}-delete-help`} className="self-center text-xs text-muted-foreground">
              Enter a reason to delete this group.
            </p>
          ) : null}
        </div>
      )}
    </form>
  );
}
