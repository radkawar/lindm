import { useQuery, useQueryClient, type UseQueryResult } from "@tanstack/react-query";
import { useId, useRef, useState, type ReactNode } from "react";
import { Link } from "@tanstack/react-router";
import { toast } from "sonner";
import {
  EnrollmentGrantStatus,
  EnrollmentGrantView,
  type EnrollmentGrant,
  type ListEnrollmentGrantsResponse,
} from "../../../gen/lindm/admin/v1/enrollment_grants_pb";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { EmptyState } from "@/components/ui/empty-state";
import { RpcError } from "@/components/ui/rpc-error";
import { Skeleton } from "@/components/ui/skeleton";
import { StatusBadge } from "@/components/ui/status-badge";
import { TechnicalDetails } from "@/components/ui/technical-details";
import { Textarea } from "@/components/ui/textarea";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
import { toRpcFailure, type RpcFailure } from "@/lib/errors";
import { newRequestId } from "@/lib/ids";
import { reasonError } from "@/lib/reason";
import { adminClient } from "@/lib/rpc";
import { formatTimestamp } from "@/lib/time";
import { enrollmentGrantsQueryOptions } from "./queries";

const grantStatusLabels: Record<EnrollmentGrantStatus, string> = {
  [EnrollmentGrantStatus.UNSPECIFIED]: "Unknown",
  [EnrollmentGrantStatus.ACTIVE]: "Active",
  [EnrollmentGrantStatus.CONSUMED]: "Used",
  [EnrollmentGrantStatus.EXPIRED]: "Expired",
  [EnrollmentGrantStatus.REVOKED]: "Revoked",
};

export function EnrollmentGrants() {
  const lifetime = useAuthLifetime();
  const client = useQueryClient();
  const historyId = useId();
  const [activePage, setActivePage] = useState("");
  const [historyPage, setHistoryPage] = useState("");
  const [showHistory, setShowHistory] = useState(false);
  const active = useQuery(
    enrollmentGrantsQueryOptions(lifetime, EnrollmentGrantView.ACTIVE, activePage),
  );
  const history = useQuery({
    ...enrollmentGrantsQueryOptions(lifetime, EnrollmentGrantView.INACTIVE, historyPage),
    enabled: showHistory,
  });
  const historyCount = active.data?.inactiveCount;
  return (
    <section className="grid gap-4" aria-label="One-time enrollment grants">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <p className="text-sm text-muted-foreground">Codes that can still enroll a device.</p>
        <Button
          variant="outline"
          disabled={active.isFetching || history.isFetching}
          onClick={() =>
            void client.invalidateQueries({ queryKey: ["enrollment-grants", lifetime.generation] })
          }
        >
          Refresh
        </Button>
      </div>
      <GrantList
        list={active}
        pageToken={activePage}
        onPage={setActivePage}
        empty={
          <EmptyState
            title="No active one-time codes"
            description="Use Create one-time code above to make one."
          />
        }
      />
      {historyCount !== undefined && (historyCount > 0 || showHistory) ? (
        <Button
          variant="ghost"
          className="w-fit"
          aria-expanded={showHistory}
          aria-controls={historyId}
          onClick={() => setShowHistory((shown) => !shown)}
        >
          {`${showHistory ? "Hide" : "Show"} used and expired (${historyCount})`}
        </Button>
      ) : null}
      <section
        id={historyId}
        aria-label="Used and expired codes"
        className="grid gap-4"
        hidden={!showHistory}
      >
        {showHistory ? (
          <GrantList
            list={history}
            pageToken={historyPage}
            onPage={setHistoryPage}
            empty={<EmptyState title="No used, expired or revoked codes" />}
          />
        ) : null}
      </section>
    </section>
  );
}

function GrantList({
  list,
  pageToken,
  onPage,
  empty,
}: {
  list: UseQueryResult<ListEnrollmentGrantsResponse>;
  pageToken: string;
  onPage: (pageToken: string) => void;
  empty: ReactNode;
}) {
  return (
    <>
      {list.isPending ? (
        <div role="status" className="grid gap-3">
          <span className="text-sm text-muted-foreground">Loading codes…</span>
          <Skeleton className="h-28 w-full" />
        </div>
      ) : null}
      {list.error ? <RpcError failure={toRpcFailure(list.error)} /> : null}
      {!list.error && list.data?.grants.length === 0 ? empty : null}
      {!list.error
        ? list.data?.grants.map((grant) => <GrantRow key={grant.grantId} grant={grant} />)
        : null}
      {pageToken || list.data?.nextPageToken ? (
        <div className="flex gap-2">
          <Button
            variant="outline"
            disabled={!pageToken || list.isFetching}
            onClick={() => onPage("")}
          >
            First page
          </Button>
          <Button
            variant="outline"
            disabled={!list.data?.nextPageToken || list.isFetching}
            onClick={() => onPage(list.data?.nextPageToken ?? "")}
          >
            Next page
          </Button>
        </div>
      ) : null}
    </>
  );
}

function GrantRow({ grant }: { grant: EnrollmentGrant }) {
  const lifetime = useAuthLifetime();
  const client = useQueryClient();
  const [open, setOpen] = useState(false);
  const [reason, setReason] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState<RpcFailure | null>(null);
  const [captured, setCaptured] = useState<{
    requestId: string;
    grantId: string;
    reason: string;
  } | null>(null);
  const inFlight = useRef(false);
  async function revoke() {
    if (inFlight.current || lifetime.signal.aborted) return;
    const validation = captured ? "" : reasonError(reason);
    if (validation) {
      setError(validation);
      return;
    }
    const request = captured ?? {
      requestId: newRequestId(),
      grantId: grant.grantId,
      reason: reason.trim(),
    };
    setCaptured(request);
    setError("");
    setFailure(null);
    setBusy(true);
    inFlight.current = true;
    try {
      await adminClient.revokeEnrollmentGrant(request, {
        signal: lifetime.signal,
        timeoutMs: 30_000,
      });
      lifetime.signal.throwIfAborted();
      setOpen(false);
      setCaptured(null);
      setReason("");
      toast.success("Code revoked");
      void client.invalidateQueries({ queryKey: ["enrollment-grants", lifetime.generation] });
    } catch (error) {
      if (!lifetime.signal.aborted) {
        const next = toRpcFailure(error);
        setFailure(next);
        if (!next.ambiguous) setCaptured(null);
      }
    } finally {
      inFlight.current = false;
      if (!lifetime.signal.aborted) setBusy(false);
    }
  }
  return (
    <article className="grid gap-3 border bg-card p-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h3 className="font-medium">One-time enrollment code</h3>
        <StatusBadge status={grant.status === EnrollmentGrantStatus.ACTIVE ? "success" : "neutral"}>
          {grantStatusLabels[grant.status] ?? "Unknown"}
        </StatusBadge>
      </div>
      <dl className="grid gap-3 text-sm sm:grid-cols-2 lg:grid-cols-4 [&_dt]:mb-1 [&_dt]:text-muted-foreground">
        <div>
          <dt>Uses</dt>
          <dd>
            {grant.usedCount} / {grant.maxUses}
          </dd>
        </div>
        <div>
          <dt>Expires</dt>
          <dd>{formatTimestamp(grant.expiresAt).local}</dd>
        </div>
        <div>
          <dt>Created by</dt>
          <dd>{grant.creatorDisplayName || "Creator name unavailable"}</dd>
        </div>
        <div>
          <dt>Created</dt>
          <dd>{formatTimestamp(grant.createdAt).local}</dd>
        </div>
      </dl>
      {grant.consumedDeviceId ? (
        <p className="text-sm">
          Enrolled device:{" "}
          <Link
            to="/devices/$deviceId"
            params={{ deviceId: grant.consumedDeviceId }}
            search={{ pageSize: 50, pageToken: "", manager: "", namePrefix: "" }}
            className="underline underline-offset-4"
          >
            {grant.consumedDeviceHostname || "Device name unavailable"}
          </Link>
        </p>
      ) : null}
      <TechnicalDetails
        items={[
          { label: "Grant ID", value: grant.grantId },
          { label: "Creator ID", value: grant.createdBy },
          { label: "Device ID", value: grant.consumedDeviceId },
        ]}
      />
      {grant.status === EnrollmentGrantStatus.ACTIVE ? (
        <Button
          className="w-fit"
          variant="outline"
          aria-haspopup="dialog"
          onClick={() => setOpen(true)}
        >
          Revoke code
        </Button>
      ) : null}
      <Dialog
        open={open}
        onOpenChange={(value) => {
          if (!busy && !failure?.ambiguous) setOpen(value);
        }}
      >
        <DialogContent
          keepMounted
          className="sm:max-w-lg"
          showCloseButton={!busy && !failure?.ambiguous}
        >
          <DialogHeader>
            <DialogTitle>Revoke this one-time code?</DialogTitle>
            <DialogDescription>
              The code can no longer enroll a device. Devices already enrolled are not affected.
            </DialogDescription>
          </DialogHeader>
          <form
            className="grid gap-3"
            onSubmit={(event) => {
              event.preventDefault();
              void revoke();
            }}
          >
            <label className="grid gap-2 text-sm font-medium">
              Reason
              <Textarea
                required
                value={reason}
                disabled={busy || captured !== null}
                onChange={(event) => setReason(event.target.value)}
              />
            </label>
            {error ? (
              <p role="alert" className="text-sm text-destructive">
                {error}
              </p>
            ) : null}
            {failure ? <RpcError failure={failure} /> : null}
            <div className="flex flex-wrap gap-2">
              <Button type="submit" variant="destructive" disabled={busy}>
                {busy ? "Revoking…" : captured ? "Try again" : "Revoke code"}
              </Button>
              <Button
                type="button"
                variant="outline"
                disabled={busy || failure?.ambiguous}
                onClick={() => setOpen(false)}
              >
                Cancel
              </Button>
            </div>
          </form>
        </DialogContent>
      </Dialog>
    </article>
  );
}
