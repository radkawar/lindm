import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { useId, useState } from "react";
import type { PendingEnrollment } from "../../../gen/lindm/admin/v1/provisioning_pb";
import { StatusBadge } from "@/components/ui/status-badge";
import { Button } from "@/components/ui/button";
import { TechnicalDetails } from "@/components/ui/technical-details";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
import { toRpcFailure } from "@/lib/errors";
import { formatTimestamp } from "@/lib/time";
import { RpcError } from "@/components/ui/rpc-error";
import { pendingEnrollmentsQueryOptions } from "./queries";

const closedStateLabels: Record<string, string> = {
  rejected: "Approval rejected",
  expired: "Expired before approval",
};

export function PendingEnrollments() {
  const lifetime = useAuthLifetime();
  const headingId = useId();
  const closedId = useId();
  const [pageToken, setPageToken] = useState("");
  const [showClosed, setShowClosed] = useState(false);
  const list = useQuery(pendingEnrollmentsQueryOptions(lifetime, pageToken));
  if (list.isPending) {
    return (
      <p role="status" className="text-sm text-muted-foreground">
        Checking for devices waiting for approval…
      </p>
    );
  }
  if (list.error) {
    return (
      <section className="grid gap-3" aria-label="Devices waiting for approval">
        <RpcError failure={toRpcFailure(list.error)} />
        <Button
          variant="outline"
          className="w-fit"
          disabled={list.isFetching}
          onClick={() => void list.refetch()}
        >
          Try again
        </Button>
      </section>
    );
  }
  const enrollments = list.data.enrollments;
  const waiting = enrollments.filter((enrollment) => enrollment.state === "pending_approval");
  const approved = enrollments.filter((enrollment) => enrollment.state === "approved");
  const closed = enrollments.filter(
    (enrollment) => enrollment.state !== "pending_approval" && enrollment.state !== "approved",
  );
  const open = [...waiting, ...approved];
  const paged = pageToken !== "" || list.data.nextPageToken !== "";
  const devices = (count: number) => `${count} ${count === 1 ? "device" : "devices"}`;
  const waitingText = `${devices(waiting.length)} waiting for approval`;
  const approvedText = `${waiting.length > 0 ? approved.length : devices(approved.length)} approved, waiting to finish enrolling`;
  const heading =
    (waiting.length === 0
      ? approvedText
      : approved.length === 0
        ? waitingText
        : `${waitingText}; ${approvedText}`) + (paged ? " on this page" : "");
  const closedToggle =
    closed.length > 0 ? (
      <Button
        variant="ghost"
        className="w-fit"
        aria-expanded={showClosed}
        aria-controls={closedId}
        onClick={() => setShowClosed((shown) => !shown)}
      >
        {`${showClosed ? "Hide" : "Show"} rejected and expired requests (${closed.length})`}
      </Button>
    ) : null;
  const closedList = (
    <div id={closedId} className="grid gap-3" hidden={!showClosed}>
      {showClosed
        ? closed.map((enrollment) => (
            <PendingRow key={enrollment.transactionId} enrollment={enrollment} />
          ))
        : null}
    </div>
  );
  const pages = paged ? (
    <div className="flex gap-2">
      <Button
        variant="outline"
        disabled={!pageToken || list.isFetching}
        onClick={() => setPageToken("")}
      >
        First page
      </Button>
      <Button
        variant="outline"
        disabled={!list.data.nextPageToken || list.isFetching}
        onClick={() => setPageToken(list.data.nextPageToken)}
      >
        Next page
      </Button>
    </div>
  ) : null;
  if (open.length === 0) {
    return (
      <section className="grid gap-3" aria-label="Devices waiting for approval">
        <p className="text-sm text-muted-foreground">
          {paged
            ? "No devices waiting for approval on this page."
            : "No devices waiting for approval."}
        </p>
        {closedToggle}
        {closedList}
        {pages}
      </section>
    );
  }
  return (
    <section className="grid gap-3 rounded-lg border bg-card p-4" aria-labelledby={headingId}>
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h2 id={headingId} className="text-base font-semibold">
          {heading}
        </h2>
        <div className="flex flex-wrap items-center gap-2">
          <Button variant="outline" disabled={list.isFetching} onClick={() => void list.refetch()}>
            Refresh
          </Button>
          <Button render={<Link to="/approvals" />}>Open approval inbox</Button>
        </div>
      </div>
      {waiting.length > 0 ? (
        <p className="text-sm text-muted-foreground">
          Another admin must approve each device in the approval inbox before it can finish
          enrolling.
        </p>
      ) : null}
      {approved.length > 0 ? (
        <p className="text-sm text-muted-foreground">
          An approved device finishes enrolling once the admin who created its provisioning token
          runs the approval in the approval inbox.
        </p>
      ) : null}
      {open.map((enrollment) => (
        <PendingRow key={enrollment.transactionId} enrollment={enrollment} />
      ))}
      {closedToggle}
      {closedList}
      {pages}
    </section>
  );
}

// Pending installations have not reported inventory, so the token's preassigned
// owner name is the only human identity available.
function ownerName(enrollment: PendingEnrollment): string | null {
  const owner = enrollment.metadata?.owner;
  return owner?.case === "ownerText" && owner.value.trim()
    ? `New device for ${owner.value.trim()}`
    : null;
}

function PendingRow({ enrollment }: { enrollment: PendingEnrollment }) {
  const waiting = enrollment.state === "pending_approval";
  const approved = enrollment.state === "approved";
  return (
    <article className="grid gap-3 border p-4">
      <div className="flex flex-wrap justify-between gap-2">
        <h3 className="min-w-0 break-words text-sm font-medium">
          {ownerName(enrollment) ?? "New device, hostname not reported yet"}
        </h3>
        <StatusBadge status={waiting ? "warning" : approved ? "info" : "neutral"}>
          {waiting
            ? "Awaiting approval"
            : approved
              ? "Approved, not finished"
              : (closedStateLabels[enrollment.state] ?? "No longer waiting")}
        </StatusBadge>
      </div>
      <dl className="grid gap-1 text-sm sm:grid-cols-2">
        <dt className="text-muted-foreground">Requested</dt>
        <dd>{formatTimestamp(enrollment.createdAt).local}</dd>
        <dt className="text-muted-foreground">Expires</dt>
        <dd>{formatTimestamp(enrollment.expiresAt).local}</dd>
      </dl>
      <Link
        to="/devices/$deviceId"
        params={{ deviceId: enrollment.deviceId }}
        className="w-fit text-sm underline underline-offset-4"
      >
        Open device
      </Link>
      <TechnicalDetails
        items={[
          { label: "Device ID", value: enrollment.deviceId },
          { label: "Transaction ID", value: enrollment.transactionId },
          { label: "Enrollment generation", value: enrollment.enrollmentGeneration },
          { label: "Installation ID", value: enrollment.installationId },
          { label: "Token ID", value: enrollment.tokenId },
          { label: "Approval ID", value: enrollment.approvalId },
          { label: "State", value: enrollment.state },
        ]}
      />
    </article>
  );
}
