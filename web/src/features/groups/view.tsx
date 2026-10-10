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
import { PageHeader } from "@/components/ui/page-header";
import { RpcError } from "@/components/ui/rpc-error";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { Textarea } from "@/components/ui/textarea";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
import type { AuthLifetime } from "@/lib/auth-lifetime";
import { classifyRpcFailure, toRpcFailure, type RpcFailure } from "@/lib/errors";
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
      <PageHeader
        title="Authorization groups"
        description="Static device membership controls access scopes. Only unrestricted account managers can edit these groups."
      />
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
        <RpcError failure={toRpcFailure(list.error)}>
          {list.data ? <p>The groups below are from the last successful refresh.</p> : null}
        </RpcError>
      ) : null}
      {list.data?.groups.map((group) => (
        <GroupEditor key={`${group.id}:${group.name}:${group.deviceIds.join(",")}`} group={group} />
      ))}
      {!list.error && list.data?.groups.length === 0 ? (
        <EmptyState title="No authorization groups on this page" />
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
    setFailure(null);
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
