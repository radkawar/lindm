import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { useState } from "react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
import { toRpcFailure } from "@/lib/errors";
import { formatTimestamp } from "@/lib/time";
import { EnrollmentFailure } from "./provisioning";
import { pendingEnrollmentsQueryOptions } from "./queries";

export function PendingEnrollments() {
  const lifetime = useAuthLifetime();
  const [pageToken, setPageToken] = useState("");
  const list = useQuery(pendingEnrollmentsQueryOptions(lifetime, pageToken));
  return (
    <Card>
      <CardHeader>
        <CardTitle>Enrollment transactions</CardTitle>
      </CardHeader>
      <CardContent className="grid gap-4">
        <p className="text-sm text-muted-foreground">
          Waiting devices have no usable device credential. A different authorized human must
          approve the exact inbox payload, then the requester executes it. The device resumes using
          its same protected installation and key; a new bootstrap is not a retry. The server
          rechecks current scope.
        </p>
        <div className="flex flex-wrap items-center gap-3">
          <Button variant="outline" disabled={list.isFetching} onClick={() => void list.refetch()}>
            Refresh enrollment transactions
          </Button>
          <Link to="/approvals" className="text-sm underline underline-offset-4">
            Open approval inbox
          </Link>
        </div>
        {list.isPending ? <p role="status">Loading enrollment transactions…</p> : null}
        {list.error ? <EnrollmentFailure failure={toRpcFailure(list.error)} /> : null}
        {!list.error && list.data?.enrollments.length === 0 ? (
          <p>No enrollment transactions in the current scope.</p>
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
                  Device {enrollment.deviceId}
                </Link>
                <Badge variant="outline">{enrollment.state.replaceAll("_", " ")}</Badge>
              </div>
              <dl className="grid gap-1 break-all text-sm sm:grid-cols-2">
                <dt className="text-muted-foreground">Transaction</dt>
                <dd>{enrollment.transactionId}</dd>
                <dt className="text-muted-foreground">Generation</dt>
                <dd>{enrollment.enrollmentGeneration}</dd>
                <dt className="text-muted-foreground">Installation</dt>
                <dd>{enrollment.installationId}</dd>
                <dt className="text-muted-foreground">Token</dt>
                <dd>{enrollment.tokenId}</dd>
                <dt className="text-muted-foreground">Approval</dt>
                <dd>{enrollment.approvalId || "Not required"}</dd>
                <dt className="text-muted-foreground">Expires</dt>
                <dd>{formatTimestamp(enrollment.expiresAt).local}</dd>
              </dl>
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
