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
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { Textarea } from "@/components/ui/textarea";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
import type { AuthLifetime } from "@/lib/auth-lifetime";
import { toRpcFailure } from "@/lib/errors";
import { adminClient } from "@/lib/rpc";

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

export function GroupsView() {
  const lifetime = useAuthLifetime();
  const [pageToken, setPageToken] = useState("");
  const [createGeneration, setCreateGeneration] = useState(0);
  const list = useQuery(groupsQueryOptions(lifetime, pageToken));
  return (
    <section className="grid min-w-0 gap-6" aria-busy={list.isFetching}>
      <header className="space-y-2">
        <h1 className="text-2xl font-semibold tracking-tight">Authorization device groups</h1>
        <p className="max-w-3xl text-sm text-muted-foreground">
          Static group membership changes authorization scope, not inventory metadata. Only
          unrestricted account managers can manage these groups.
        </p>
      </header>
      <GroupEditor
        key={createGeneration}
        onCreated={() => setCreateGeneration((value) => value + 1)}
      />
      <Button
        className="w-fit"
        variant="outline"
        disabled={list.isFetching}
        onClick={() => void list.refetch()}
      >
        Refresh groups
      </Button>
      {list.isPending ? (
        <div role="status" className="grid gap-3">
          <span className="text-sm text-muted-foreground">Loading groups…</span>
          <Skeleton className="h-40 w-full" />
        </div>
      ) : null}
      {list.error ? (
        <Alert variant="destructive">
          <AlertTitle>Groups unavailable</AlertTitle>
          <AlertDescription>{toRpcFailure(list.error).message}</AlertDescription>
        </Alert>
      ) : null}
      {list.data?.groups.map((group) => (
        <GroupEditor key={`${group.id}:${group.name}:${group.deviceIds.join(",")}`} group={group} />
      ))}
      {list.data?.groups.length === 0 ? (
        <p
          role="status"
          className="border border-dashed bg-muted/30 px-6 py-10 text-center text-sm text-muted-foreground"
        >
          No groups on this page.
        </p>
      ) : null}
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
    </section>
  );
}

function GroupEditor({ group, onCreated }: { group?: DeviceGroup; onCreated?: () => void }) {
  const lifetime = useAuthLifetime();
  const client = useQueryClient();
  const [groupId] = useState(() => group?.id ?? crypto.randomUUID());
  const [name, setName] = useState(group?.name ?? "");
  const [members, setMembers] = useState(group?.deviceIds.join("\n") ?? "");
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
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
            deviceIds: members.split(/\s+/).filter(Boolean),
          }));
    const validation =
      exact.$typeName === "lindm.admin.v1.SetDeviceGroupRequest"
        ? validator.validate(SetDeviceGroupRequestSchema, exact)
        : validator.validate(DeleteDeviceGroupRequestSchema, exact);
    if (validation.kind !== "valid") {
      setError(
        validation.kind === "invalid"
          ? validation.violations.map((item) => item.toString()).join("; ")
          : validation.error.message,
      );
      return;
    }
    setAttempt(exact);
    setBusy(true);
    setError("");
    try {
      const options = { signal: lifetime.signal, timeoutMs: 30_000 };
      if (exact.$typeName === "lindm.admin.v1.SetDeviceGroupRequest")
        await adminClient.setDeviceGroup(exact, options);
      else await adminClient.deleteDeviceGroup(exact, options);
      lifetime.signal.throwIfAborted();
      setCompleted(true);
      toast.success("Authorization group change completed");
      await client.invalidateQueries({ queryKey: ["device-groups", lifetime.generation] });
      if (!group) onCreated?.();
    } catch (failure) {
      if (!lifetime.signal.aborted) {
        const normalized = toRpcFailure(failure);
        setError(
          `${normalized.message}${normalized.ambiguous ? " Outcome unknown; retry preserves the exact request ID and payload." : ""}`,
        );
        toast.error(normalized.ambiguous ? "Group change outcome unknown" : "Group change failed", {
          description: "Review the inline result before continuing.",
        });
        if (!normalized.ambiguous) setAttempt(null);
      }
    } finally {
      if (!lifetime.signal.aborted) setBusy(false);
    }
  }

  return (
    <form
      className="grid min-w-0 gap-4 border bg-card p-4 sm:p-6"
      onSubmit={(event) => {
        event.preventDefault();
        void save(false);
      }}
    >
      <h2 className="break-words font-semibold">{group ? group.name : "Create group"}</h2>
      <p className="break-all font-mono text-xs text-muted-foreground">Group ID: {groupId}</p>
      <label className="grid gap-2 text-sm font-medium">
        Group name
        <Input
          aria-label="Group name"
          required
          value={name}
          disabled={busy || attempt !== null}
          onChange={(event) => setName(event.target.value)}
        />
      </label>
      <label className="grid gap-2 text-sm font-medium">
        Member device UUIDs, separated by whitespace
        <Textarea
          className="min-h-28 font-mono text-xs"
          aria-label="Member device UUIDs, separated by whitespace"
          value={members}
          disabled={busy || attempt !== null}
          onChange={(event) => setMembers(event.target.value)}
        />
      </label>
      <label className="grid gap-2 text-sm font-medium">
        Audit reason
        <Input
          aria-label="Group change reason"
          required
          value={reason}
          disabled={busy || attempt !== null}
          onChange={(event) => setReason(event.target.value)}
        />
      </label>
      {error ? (
        <Alert variant="destructive">
          <AlertTitle>Group change not confirmed</AlertTitle>
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      ) : null}
      {busy ? (
        <p role="status" className="text-sm text-muted-foreground">
          Submitting exact group change…
        </p>
      ) : null}
      {completed ? (
        <p role="status" className="border bg-muted/30 p-3 text-sm">
          Group change completed.
        </p>
      ) : (
        <div className="flex flex-wrap gap-2">
          <Button
            type="submit"
            disabled={busy || attempt?.$typeName === "lindm.admin.v1.DeleteDeviceGroupRequest"}
          >
            {attempt ? "Retry exact save" : "Save group"}
          </Button>
          {group ? (
            <Button
              type="button"
              variant="destructive"
              disabled={
                busy ||
                reason.trim() === "" ||
                attempt?.$typeName === "lindm.admin.v1.SetDeviceGroupRequest"
              }
              onClick={() => {
                if (
                  attempt ||
                  window.confirm(
                    "Delete this authorization group? Its scoped grants will no longer match members.",
                  )
                )
                  void save(true);
              }}
            >
              {attempt ? "Retry exact deletion" : "Delete group"}
            </Button>
          ) : null}
        </div>
      )}
    </form>
  );
}
