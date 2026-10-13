import type { Timestamp } from "@bufbuild/protobuf/wkt";
import { useEffect, useState } from "react";
import {
  AdvisoryFindingState,
  type AdvisoryFeedStatus,
} from "../../../gen/lindm/admin/v1/advisories_pb";
import { Button } from "@/components/ui/button";
import { StatusBadge } from "@/components/ui/status-badge";

export function useFreshnessClock() {
  const [now, setNow] = useState(Date.now);
  useEffect(() => {
    const timer = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, []);
  return now;
}
export function unexpired(expiry: Timestamp | undefined, now: number) {
  return expiry !== undefined && Number(expiry.seconds) * 1000 + expiry.nanos / 1_000_000 > now;
}
export function findingStateLabel(state: AdvisoryFindingState) {
  const label = AdvisoryFindingState[state];
  return !label || label === "UNSPECIFIED"
    ? "Unknown"
    : label.charAt(0) + label.slice(1).toLowerCase().replaceAll("_", " ");
}

// Vendors that rate nothing send an empty or placeholder severity. That is an
// absent rating, not an error or a severity level of its own.
const unpublishedSeverities: Record<string, true> = { "": true, unknown: true, unspecified: true };

function publishedSeverity(severity: string) {
  const value = severity.trim();
  return Object.hasOwn(unpublishedSeverities, value.toLowerCase())
    ? ""
    : value.charAt(0).toUpperCase() + value.slice(1).toLowerCase();
}

// A rated severity is a neutral badge; an unrated one is plain muted text that
// says the source gave no rating, so it never reads as a failure.
export function Severity({ value, badge = true }: { value: string; badge?: boolean }) {
  const severity = publishedSeverity(value);
  if (!severity) {
    return (
      <span data-advisory-severity="unrated" className="text-muted-foreground">
        Not rated by the source
      </span>
    );
  }
  return badge ? (
    <StatusBadge status="neutral" data-advisory-severity="rated">
      {severity}
    </StatusBadge>
  ) : (
    <span data-advisory-severity="rated">{severity}</span>
  );
}

// Registry display name, else the reported os-release identity.
export function osLabel(name: string, id: string, version: string) {
  return name || `${id} ${version}`.trim() || "an unidentified OS";
}

export function feedOSLabel(feed: AdvisoryFeedStatus) {
  return osLabel(feed.osName, feed.distro, feed.release);
}

export function sourceAnchor(feedId: string) {
  return `advisory-source-${feedId}`;
}

// How the server's advisory sources are set up (operator documentation).
export const advisorySourcesDocsUrl = "/help/engineering.md#advisory-feed-operations";

// Why a refreshed, unexpired source is still incomplete, as one sentence, and
// its remedy in admin terms. The banner states the device consequence; this is
// the only place the gap itself is explained. An unscoped skipped entry voids
// completeness; otherwise the source never claimed to list every advisory.
export function sourceGap(feed: AdvisoryFeedStatus) {
  const os = feedOSLabel(feed);
  const unscoped = feed.rejectedRecords.filter(
    (record) => record.unscoped || record.packageNames.length === 0,
  ).length;
  if (unscoped === 0) {
    return {
      missing: `Missing the complete ${os} advisory list; this source has only selected advisories.`,
      remedy: `Add a source that lists every ${os} advisory to the lindm server.`,
    };
  }
  const entries = unscoped === 1 ? `1 skipped ${os} entry` : `${unscoped} skipped ${os} entries`;
  return {
    missing: `Missing the affected packages of ${entries}.`,
    remedy: `Review the skipped entries below; ${os} devices stay unchecked until the vendor names their packages.`,
  };
}

// Derivative vendors whose packages no published feed covers. The evaluation
// reason names the vendor; uncovered vendor packages share that text.
const vendorFeedText: Record<string, string> = {
  vendor_feed_unavailable_linuxmint: "vendor feed unavailable for Linux Mint packages",
  vendor_feed_unavailable_pop: "vendor feed unavailable for Pop!_OS packages",
};

// Server evaluation reasons (internal/advisory/match.go), in operator words.
const evaluationReasonText: Record<string, string> = {
  device_not_active: "the device has not enrolled",
  inventory_unavailable: "the device has not sent package inventory",
  inventory_stale: "the package inventory is out of date",
  host_inventory_stale_or_failed: "the latest device inventory is out of date or failed",
  package_collection_failed: "the last package scan failed",
  rhel_platform_stream_unavailable: "the device did not report its RHEL platform stream",
  feed_unavailable: "no advisory source covers this operating system",
  feed_stale: "the advisory source is out of date",
  feed_partial_coverage: "vulnerability data for this release is incomplete",
  matching_capacity_exceeded: "too many packages to match in one check",
};

const uncoveredReasonText: Record<string, string> = {
  origin_unavailable: "APT origin evidence unavailable",
  origin_unlisted: "no APT source lists the installed version",
  origin_ambiguous: "a non-Ubuntu source also lists this version",
  origin_unverified: "only unsigned or unverified APT sources list this version",
  origin_not_covered: "no advisory feed covers the sources that list this version",
  base_pocket_uncovered: "Ubuntu pocket without security support (backports or proposed)",
};

export function advisoryReasonText(reason: string) {
  return vendorFeedText[reason] ?? evaluationReasonText[reason] ?? reason.replaceAll("_", " ");
}

export function uncoveredPackageReasonText(reason: string, evaluationReason: string) {
  if (reason === "vendor_feed_unavailable") {
    return vendorFeedText[evaluationReason] ?? "vendor feed unavailable";
  }
  return uncoveredReasonText[reason] ?? reason.replaceAll("_", " ");
}
export function AdvisoryPaging({
  token,
  next,
  busy,
  onPage,
}: {
  token: string;
  next: string;
  busy: boolean;
  onPage: (token: string) => void;
}) {
  return (
    <div className="flex flex-wrap gap-2">
      <Button variant="outline" disabled={!token || busy} onClick={() => onPage("")}>
        First page
      </Button>
      <Button variant="outline" disabled={!next || busy} onClick={() => onPage(next)}>
        Next page
      </Button>
    </div>
  );
}
