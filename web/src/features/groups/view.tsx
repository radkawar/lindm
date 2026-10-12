import { create } from "@bufbuild/protobuf";
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
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { EmptyState } from "@/components/ui/empty-state";
import { RpcError } from "@/components/ui/rpc-error";
import { Button } from "@/components/ui/button";
import { ListPagination } from "@/components/ui/list-pagination";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import type { PickerSlot } from "@/components/ui/search-picker";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
import type { AuthLifetime } from "@/lib/auth-lifetime";
import { classifyRpcFailure, toRpcFailure, type RpcFailure } from "@/lib/errors";
import { adminClient } from "@/lib/rpc";
import { checkRequest } from "@/lib/validation";
import { DeviceMembersField, type DeviceLabelSlot } from "./device-members";

const MAX_MEMBERS = 1000; // SetDeviceGroupRequest.device_ids max_items
const LISTED_MEMBERS = 5;

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

// One device group by ID. The API lists groups in pages only, so this reads
// pages until the group is found (null when it no longer exists), bounded at
// 4,000 groups.
export function deviceGroupQueryOptions(lifetime: AuthLifetime, groupId: string) {
  return queryOptions({
    queryKey: ["device-groups", lifetime.generation, "group", groupId] as const,
    meta: { authGeneration: lifetime.generation },
    queryFn: async ({ signal }): Promise<DeviceGroup | null> => {
      let pageToken = "";
      for (let page = 0; page < 40; page += 1) {
        const result = await adminClient.listDeviceGroups(
          { pageSize: 100, pageToken },
          { signal: AbortSignal.any([signal, lifetime.signal]), timeoutMs: 30_000 },
        );
        lifetime.signal.throwIfAborted();
        const group = result.groups.find((item) => item.id === groupId);
        if (group) return group;
        if (!result.nextPageToken) return null;
        pageToken = result.nextPageToken;
      }
      return null;
    },
    retry: false,
  });
}

function deviceCount(count: number) {
  return count === 1 ? "1 device" : `${count} devices`;
}

export function GroupsView({
  devicePicker,
  deviceLabel,
  creating,
  onCreatingChange,
}: {
  devicePicker: PickerSlot;
  deviceLabel: DeviceLabelSlot;
  // Owned by the route so a link (for example the command palette) can open it.
  creating: boolean;
  onCreatingChange: (creating: boolean) => void;
}) {
  const lifetime = useAuthLifetime();
  const [pageToken, setPageToken] = useState("");
  const [createGeneration, setCreateGeneration] = useState(0);
  const list = useQuery(groupsQueryOptions(lifetime, pageToken));
  const groups = [...(list.data?.groups ?? [])].sort((a, b) => a.name.localeCompare(b.name));
  const startCreate = () => {
    setCreateGeneration((value) => value + 1);
    onCreatingChange(true);
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
            Named sets of devices. Accounts limited to a group can manage only its devices.
          </p>
        </div>
        <Button onClick={startCreate}>New group</Button>
      </div>
      <Dialog open={creating} onOpenChange={onCreatingChange}>
        <DialogContent className="max-h-[90svh] overflow-y-auto sm:max-w-xl">
          <DialogHeader>
            <DialogTitle>New device group</DialogTitle>
            <DialogDescription>
              Saving creates the group. Accounts you later limit to it can manage only these
              devices.
            </DialogDescription>
          </DialogHeader>
          <GroupEditor
            key={createGeneration}
            devicePicker={devicePicker}
            deviceLabel={deviceLabel}
            onDone={() => onCreatingChange(false)}
          />
        </DialogContent>
      </Dialog>
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
              deviceLabel={deviceLabel}
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
            action={<Button onClick={startCreate}>New group</Button>}
          />
        )
      ) : null}
      <ListPagination
        label="Device group pages"
        busy={list.isFetching}
        onPrevious={pageToken ? () => setPageToken("") : undefined}
        onNext={
          list.data?.nextPageToken ? () => setPageToken(list.data?.nextPageToken ?? "") : undefined
        }
      />
    </section>
  );
}

function GroupRow({
  group,
  devicePicker,
  deviceLabel: DeviceLabel,
}: {
  group: DeviceGroup;
  devicePicker: PickerSlot;
  deviceLabel: DeviceLabelSlot;
}) {
  const [editing, setEditing] = useState(false);
  const name = group.name || "Unnamed group";
  const listed = group.deviceIds.slice(0, LISTED_MEMBERS);
  const more = group.deviceIds.length - listed.length;
  return (
    <li className="grid min-w-0 gap-2 p-4">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div className="grid min-w-0 gap-1">
          <h3 className="break-words font-medium">{name}</h3>
          <p className="text-sm text-muted-foreground">{deviceCount(group.deviceIds.length)}</p>
        </div>
        <Button
          variant="outline"
          size="sm"
          aria-label={`Edit ${name}`}
          onClick={() => setEditing(true)}
        >
          Edit
        </Button>
      </div>
      {listed.length > 0 ? (
        <ul
          aria-label={`Devices in ${name}`}
          className="flex min-w-0 flex-wrap gap-x-4 gap-y-1 text-sm"
        >
          {listed.map((id) => (
            <li key={id} className="min-w-0">
              <DeviceLabel value={id} />
            </li>
          ))}
          {more > 0 ? (
            <li className="text-muted-foreground">and {deviceCount(more)} more</li>
          ) : null}
        </ul>
      ) : null}
      <Dialog open={editing} onOpenChange={setEditing}>
        <DialogContent className="max-h-[90svh] overflow-y-auto sm:max-w-xl">
          <DialogHeader>
            <DialogTitle>Edit {name}</DialogTitle>
            <DialogDescription>
              Saving replaces this group&apos;s name and devices. Accounts limited to it gain or
              lose access to the devices you add or remove.
            </DialogDescription>
          </DialogHeader>
          {editing ? (
            <GroupEditor
              group={group}
              devicePicker={devicePicker}
              deviceLabel={DeviceLabel}
              onDone={() => setEditing(false)}
            />
          ) : null}
        </DialogContent>
      </Dialog>
    </li>
  );
}

// The administrator's checks, in words, before protobuf validation; a request
// that still fails the schema is described, never shown as a violation path.
function problem(request: SetDeviceGroupRequest | DeleteDeviceGroupRequest) {
  if (request.$typeName === "lindm.admin.v1.SetDeviceGroupRequest") {
    if (!request.name.trim()) return "Enter a group name.";
    if (request.deviceIds.length > MAX_MEMBERS)
      return `A group can have up to ${MAX_MEMBERS.toLocaleString()} devices. Remove ${(request.deviceIds.length - MAX_MEMBERS).toLocaleString()}.`;
  }
  if (!request.reason.trim()) return "Enter a reason for this change.";
  const hints = {
    name: "Use a group name of up to 128 characters.",
    reason: "Use a reason of up to 1,024 characters.",
  };
  const invalid =
    request.$typeName === "lindm.admin.v1.SetDeviceGroupRequest"
      ? checkRequest(SetDeviceGroupRequestSchema, request, hints)
      : checkRequest(DeleteDeviceGroupRequestSchema, request, hints);
  return invalid?.message ?? "";
}

function GroupEditor({
  group,
  onDone,
  devicePicker,
  deviceLabel,
}: {
  group?: DeviceGroup;
  onDone: () => void;
  devicePicker: PickerSlot;
  deviceLabel: DeviceLabelSlot;
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
            deviceIds: members,
          }));
    const message = problem(exact);
    if (message) {
      setError(message);
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

  const frozen = busy || attempt !== null;
  return (
    <form
      aria-label={group ? `Edit ${group.name || "unnamed group"}` : "New device group"}
      className="grid min-w-0 gap-4"
      onSubmit={(event) => {
        event.preventDefault();
        void save(false);
      }}
    >
      <label className="grid gap-2 text-sm font-medium">
        Group name
        <Input
          aria-label="Group name"
          data-freeform="new or renamed group name"
          required
          maxLength={128}
          value={name}
          disabled={frozen}
          onChange={(event) => setName(event.target.value)}
        />
      </label>
      <DeviceMembersField
        label="Devices"
        values={members}
        onChange={setMembers}
        picker={devicePicker}
        deviceLabel={deviceLabel}
        disabled={frozen}
      />
      <label className="grid gap-2 text-sm font-medium">
        Reason for this change
        <Input
          aria-label="Group change reason"
          data-freeform="audit reason"
          required
          value={reason}
          disabled={frozen}
          onChange={(event) => setReason(event.target.value)}
        />
      </label>
      {error ? (
        <Alert variant="destructive">
          <AlertTitle>Check group details</AlertTitle>
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      ) : null}
      {failure ? (
        <RpcError failure={failure}>
          {failure.ambiguous ? (
            <p>We couldn&apos;t confirm the change. Try again: it won&apos;t apply twice.</p>
          ) : null}
        </RpcError>
      ) : null}
      {busy ? (
        <p role="status" className="text-sm text-muted-foreground">
          Saving group…
        </p>
      ) : null}
      <div className="flex flex-wrap items-center gap-2">
        <Button
          type="submit"
          disabled={busy || attempt?.$typeName === "lindm.admin.v1.DeleteDeviceGroupRequest"}
        >
          {attempt?.$typeName === "lindm.admin.v1.SetDeviceGroupRequest"
            ? "Try again"
            : group
              ? "Save group"
              : "Create group"}
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
            {attempt?.$typeName === "lindm.admin.v1.DeleteDeviceGroupRequest"
              ? "Try deleting again"
              : "Delete group"}
          </Button>
        ) : null}
        {group && reason.trim() === "" ? (
          <p id={`${groupId}-delete-help`} className="text-xs text-muted-foreground">
            Enter a reason to delete this group.
          </p>
        ) : null}
      </div>
    </form>
  );
}
