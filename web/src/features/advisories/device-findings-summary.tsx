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
  const { freshness, nextPageToken } = findings.data;
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
  const more = nextPageToken !== "" ? "+" : "";
  const affected = findings.data.findings.filter(
    (finding) => finding.state === AdvisoryFindingState.AFFECTED,
  ).length;
  const accepted = findings.data.findings.filter(
    (finding) => finding.state === AdvisoryFindingState.ACCEPTED,
  ).length;
  const noun = affected === 1 && !more ? "finding" : "findings";
  const parts = [
    affected ? `${affected.toLocaleString()}${more} open ${noun}` : "No open findings",
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
