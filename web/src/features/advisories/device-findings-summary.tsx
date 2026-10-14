// SPDX-License-Identifier: Apache-2.0

import { useQuery } from "@tanstack/react-query";
import { AdvisoryFindingState } from "../../../gen/lindm/admin/v1/advisories_pb";
import { StatusBadge } from "@/components/ui/status-badge";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
import { advisoryReasonText, unexpired, useFreshnessClock } from "./display";
import { deviceFindingsQueryOptions } from "./queries";

function plural(count: number, one: string, many: string) {
  return `${count.toLocaleString()} ${count === 1 ? one : many}`;
}

// One-line findings state for the device overview; shares the Findings tab's first page.
export function DeviceFindingsSummary({ deviceId }: { deviceId: string }) {
  const lifetime = useAuthLifetime();
  const now = useFreshnessClock();
  const findings = useQuery(deviceFindingsQueryOptions(lifetime, deviceId, ""));
  if (findings.isPending) return <span role="status">Checking findings…</span>;
  if (findings.error) return <span>Findings unavailable. Open Findings for the error.</span>;
  const { freshness } = findings.data;
  const current =
    freshness !== undefined &&
    unexpired(freshness.inventoryExpiresAt, now) &&
    unexpired(freshness.feedExpiresAt, now);
  if (!current || freshness.state === AdvisoryFindingState.UNKNOWN) {
    return (
      <span className="flex flex-wrap items-center gap-2">
        <StatusBadge status="neutral">Unknown</StatusBadge>
        {current && freshness.reason
          ? `Not checked: ${advisoryReasonText(freshness.reason)}.`
          : "The device inventory or advisory sources are out of date."}
      </span>
    );
  }
  // Totals cover every page; the first page alone undercounts large sets.
  const totals = findings.data.totals;
  const affected = Number(totals?.open ?? 0n);
  const accepted = Number(totals?.accepted ?? 0n);
  const severe = Number((totals?.critical ?? 0n) + (totals?.high ?? 0n));
  const parts = [
    affected
      ? `${plural(affected, "open finding", "open findings")} · ${
          severe
            ? `${totals?.critical.toLocaleString()} critical, ${totals?.high.toLocaleString()} high`
            : "none critical or high"
        }`
      : "No open findings",
  ];
  if (accepted) parts.push(plural(accepted, "accepted risk", "accepted risks"));
  if (freshness.state === AdvisoryFindingState.PARTIAL)
    parts.push(
      plural(Number(freshness.uncoveredPackages), "package not checked", "packages not checked"),
    );
  return (
    <span className="flex flex-wrap items-center gap-2">
      <StatusBadge
        status={
          affected
            ? "destructive"
            : accepted || freshness.state === AdvisoryFindingState.PARTIAL
              ? "warning"
              : "success"
        }
      >
        {affected
          ? "Affected"
          : freshness.state === AdvisoryFindingState.PARTIAL
            ? "Partly checked"
            : accepted
              ? "Accepted"
              : "Clear"}
      </StatusBadge>
      {parts.join(" · ")}
    </span>
  );
}
