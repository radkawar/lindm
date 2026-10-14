// SPDX-License-Identifier: Apache-2.0

import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import {
  ServerStatusState,
  type ServerStatusCheck,
} from "../../../gen/lindm/admin/v1/server_status_pb";
import { EmptyState } from "@/components/ui/empty-state";
import { PageHeader } from "@/components/ui/page-header";
import { RpcError } from "@/components/ui/rpc-error";
import { Skeleton } from "@/components/ui/skeleton";
import { StatusBadge, type StatusTone } from "@/components/ui/status-badge";
import { TechnicalDetails } from "@/components/ui/technical-details";
import { Timestamp } from "@/components/ui/timestamp";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
import { toRpcFailure } from "@/lib/errors";
import { serverStatusQueryOptions } from "./queries";
import { RecoveryCustodyTask } from "./custody-task";

const COMPONENTS: Record<string, string> = {
  database: "Device database connection",
  admin_database: "Console database connection",
  https_certificate: "Server HTTPS certificate",
  device_ca: "Device certificate authority",
  backups: "Encrypted backups",
  server_release_feed: "Offline server release notices",
  agent_repository: "Agent installation",
  advisory_feeds: "Advisory feeds",
  disk: "Server state storage",
  job_queue: "Delivery and report work",
};

// Put decisions and missing evidence before confirmed checks. Preserve server
// order within each state so repeated refreshes do not move equivalent checks.
const CHECK_PRIORITY: Record<ServerStatusState, number> = {
  [ServerStatusState.FAILED]: 0,
  [ServerStatusState.ATTENTION]: 1,
  [ServerStatusState.UNKNOWN]: 2,
  [ServerStatusState.UNSPECIFIED]: 2,
  [ServerStatusState.INACTIVE]: 3,
  [ServerStatusState.OK]: 4,
};

function statePresentation(state: ServerStatusState): { label: string; tone: StatusTone } {
  switch (state) {
    case ServerStatusState.OK:
      return { label: "Check confirmed", tone: "success" };
    case ServerStatusState.FAILED:
      return { label: "Failed", tone: "destructive" };
    case ServerStatusState.ATTENTION:
      return { label: "Needs attention", tone: "warning" };
    case ServerStatusState.INACTIVE:
      return { label: "Not configured", tone: "neutral" };
    default:
      return { label: "Unknown", tone: "neutral" };
  }
}

function EvidenceRow({ check }: { check: ServerStatusCheck }) {
  const state = statePresentation(check.state);
  return (
    <li className="grid min-w-0 gap-2 border-t py-4 sm:grid-cols-[minmax(12rem,1fr)_minmax(0,2fr)] sm:gap-6">
      <div className="grid content-start justify-items-start gap-2">
        <h3 className="text-sm font-semibold">{COMPONENTS[check.component] ?? "Server check"}</h3>
        <StatusBadge status={state.tone}>{state.label}</StatusBadge>
      </div>
      <div className="grid min-w-0 gap-2 text-sm">
        <p>{check.summary || "The server returned no explanation for this check."}</p>
        <p className="text-muted-foreground">
          {check.nextAction || "Inspect the server service journal."}
        </p>
        <dl className="flex flex-wrap gap-x-6 gap-y-2 text-xs text-muted-foreground">
          <div className="min-w-0">
            <dt className="font-medium">Checked</dt>
            <dd className="break-words">
              {check.observedAt ? <Timestamp value={check.observedAt} /> : "No completed check"}
            </dd>
          </div>
          <div className="min-w-0">
            <dt className="font-medium">Evidence</dt>
            <dd className="break-words">
              {check.evidenceAt ? <Timestamp value={check.evidenceAt} /> : "Not available"}
            </dd>
          </div>
          {check.expiresAt ? (
            <div className="min-w-0">
              <dt className="font-medium">Expires</dt>
              <dd className="break-words">
                <Timestamp value={check.expiresAt} />
              </dd>
            </div>
          ) : null}
        </dl>
        <TechnicalDetails
          items={[
            { label: "Check", value: check.component },
            { label: "Evidence detail", value: check.detail },
          ]}
        />
      </div>
    </li>
  );
}

export function ServerStatusPage({ canReviewInstallation }: { canReviewInstallation: boolean }) {
  const lifetime = useAuthLifetime();
  const query = useQuery(serverStatusQueryOptions(lifetime));
  const response = query.data;
  const failed =
    response?.checks.filter((check) => check.state === ServerStatusState.FAILED).length ?? 0;
  const attention =
    response?.checks.filter((check) => check.state === ServerStatusState.ATTENTION).length ?? 0;
  const unknown =
    response?.checks.filter(
      (check) =>
        check.state === ServerStatusState.UNKNOWN || check.state === ServerStatusState.UNSPECIFIED,
    ).length ?? 0;
  return (
    <div className="grid min-w-0 gap-6">
      <PageHeader
        title="Server status"
        description="Review server checks and their evidence before planning maintenance."
        onRefresh={() => void query.refetch()}
        refreshing={query.isFetching}
      />
      {query.isError ? <RpcError failure={toRpcFailure(query.error)} /> : null}
      {query.isPending ? <Skeleton className="h-32 w-full" /> : null}
      {response ? (
        <>
          <RecoveryCustodyTask
            key={response.recoveryKeyCustody?.confirmationDigest || "custody-without-exports"}
            custody={response.recoveryKeyCustody}
            stale={query.isError}
          />
          {response.checks.length ? (
            <section
              aria-labelledby="status-decision"
              className="grid gap-2 border-l-2 border-primary pl-4"
            >
              <h2 id="status-decision" className="text-base font-semibold">
                {query.isError
                  ? "The latest read failed; retained checks may be stale"
                  : failed || attention
                    ? "Review the checks that need action"
                    : unknown
                      ? "Resolve missing evidence before relying on these checks"
                      : "Review the scope and freshness of each check"}
              </h2>
              <p className="text-sm">
                {failed} failed checks, {attention} checks need attention, {unknown} checks lack
                evidence.
              </p>
              <p className="text-xs text-muted-foreground">
                Last observation:{" "}
                {response.observedAt ? (
                  <Timestamp value={response.observedAt} />
                ) : (
                  "No completed observation"
                )}
              </p>
              <div className="flex flex-wrap gap-4 text-sm">
                <Link to="/integrations" className="underline underline-offset-4">
                  Review alert deliveries
                </Link>
                {canReviewInstallation ? (
                  <Link to="/settings" className="underline underline-offset-4">
                    Review installation readiness
                  </Link>
                ) : (
                  <p className="text-muted-foreground">
                    Ask an enrollment administrator to review agent installation.
                  </p>
                )}
              </div>
            </section>
          ) : null}
          {response.checks.length ? (
            <section aria-labelledby="status-evidence" className="grid gap-2">
              <h2 id="status-evidence" className="text-base font-semibold">
                Evidence from this server
              </h2>
              <ul>
                {[...response.checks]
                  .sort((a, b) => CHECK_PRIORITY[a.state] - CHECK_PRIORITY[b.state])
                  .map((check) => (
                    <EvidenceRow key={check.component} check={check} />
                  ))}
              </ul>
            </section>
          ) : (
            <EmptyState
              title="The server returned no checks"
              description="Inspect the server service journal, then refresh this page."
            />
          )}
          <TechnicalDetails
            items={[{ label: "Server release", value: response.version || "Unavailable" }]}
          />
        </>
      ) : null}
    </div>
  );
}
