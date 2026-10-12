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
  const closed = enrollments.filter((enrollment) => enrollment.state !== "pending_approval");
  const paged = pageToken !== "" || list.data.nextPageToken !== "";
  const noun = waiting.length === 1 ? "device" : "devices";
  const heading = `${waiting.length} ${noun} waiting for approval${paged ? " on this page" : ""}`;
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
  if (waiting.length === 0) {
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
      <p className="text-sm text-muted-foreground">
        Another admin must approve each device in the approval inbox before it can finish enrolling.
      </p>
      {waiting.map((enrollment) => (
        <PendingRow key={enrollment.transactionId} enrollment={enrollment} />
      ))}
      {closedToggle}
      {closedList}
      {pages}
    </section>
  );
}

function PendingRow({ enrollment }: { enrollment: PendingEnrollment }) {
  const waiting = enrollment.state === "pending_approval";
  return (
    <article className="grid gap-3 border p-4">
      <div className="flex flex-wrap justify-between gap-2">
        <Link
          to="/devices/$deviceId"
          params={{ deviceId: enrollment.deviceId }}
          className="break-all text-sm underline underline-offset-4"
        >
          Open device
        </Link>
        <StatusBadge status={waiting ? "warning" : "neutral"}>
          {waiting
            ? "Awaiting approval"
            : (closedStateLabels[enrollment.state] ?? "No longer waiting")}
        </StatusBadge>
      </div>
      <dl className="grid gap-1 text-sm sm:grid-cols-2">
        <dt className="text-muted-foreground">Requested</dt>
        <dd>{formatTimestamp(enrollment.createdAt).local}</dd>
        <dt className="text-muted-foreground">Expires</dt>
        <dd>{formatTimestamp(enrollment.expiresAt).local}</dd>
      </dl>
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
