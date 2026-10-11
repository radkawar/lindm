import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { useState } from "react";
import { EmptyState } from "@/components/ui/empty-state";
import { StatusBadge } from "@/components/ui/status-badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { TechnicalDetails } from "@/components/ui/technical-details";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
import { toRpcFailure } from "@/lib/errors";
import { formatTimestamp } from "@/lib/time";
import { RpcError } from "@/components/ui/rpc-error";
import { pendingEnrollmentsQueryOptions } from "./queries";

export function PendingEnrollments() {
  const lifetime = useAuthLifetime();
  const [pageToken, setPageToken] = useState("");
  const list = useQuery(pendingEnrollmentsQueryOptions(lifetime, pageToken));
  return (
    <Card>
      <CardHeader>
        <CardTitle>Devices waiting to enroll</CardTitle>
      </CardHeader>
      <CardContent className="grid gap-4">
        <p className="text-sm text-muted-foreground">
          Another admin must approve each device in the approval inbox before it can finish
          enrolling.
        </p>
        <div className="flex flex-wrap items-center gap-3">
          <Button variant="outline" disabled={list.isFetching} onClick={() => void list.refetch()}>
            Refresh
          </Button>
          <Link to="/approvals" className="text-sm underline underline-offset-4">
            Open approval inbox
          </Link>
        </div>
        {list.isPending ? <p role="status">Loading waiting devices…</p> : null}
        {list.error ? <RpcError failure={toRpcFailure(list.error)} /> : null}
        {!list.error && list.data?.enrollments.length === 0 ? (
          <EmptyState title="No devices waiting to enroll" />
        ) : null}
        {!list.error &&
          list.data?.enrollments.map((enrollment) => (
            <article key={enrollment.transactionId} className="grid gap-3 border p-4">
              <div className="flex flex-wrap justify-between gap-2">
                <Link
                  to="/devices/$deviceId"
                  params={{ deviceId: enrollment.deviceId }}
                  className="break-all text-sm underline underline-offset-4"
                >
                  Open device
                </Link>
                <StatusBadge
                  status={enrollment.state === "pending_approval" ? "warning" : "neutral"}
                >
                  {enrollment.state === "pending_approval"
                    ? "Awaiting approval"
                    : enrollment.state.replaceAll("_", " ")}
                </StatusBadge>
              </div>
              <dl className="grid gap-1 text-sm sm:grid-cols-2">
                <dt className="text-muted-foreground">Requested</dt>
                <dd>{formatTimestamp(enrollment.createdAt).local}</dd>
                <dt className="text-muted-foreground">Expires</dt>
                <dd>{formatTimestamp(enrollment.expiresAt).local}</dd>
                <dt className="text-muted-foreground">Approval</dt>
                <dd>{enrollment.approvalId ? "Needed" : "Not needed"}</dd>
              </dl>
              <TechnicalDetails
                items={[
                  { label: "Device ID", value: enrollment.deviceId },
                  { label: "Transaction ID", value: enrollment.transactionId },
                  { label: "Enrollment generation", value: enrollment.enrollmentGeneration },
                  { label: "Installation ID", value: enrollment.installationId },
                  { label: "Token ID", value: enrollment.tokenId },
                  { label: "Approval ID", value: enrollment.approvalId },
                ]}
              />
            </article>
          ))}
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
            disabled={!list.data?.nextPageToken || list.isFetching}
            onClick={() => setPageToken(list.data?.nextPageToken ?? "")}
          >
            Next page
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}
