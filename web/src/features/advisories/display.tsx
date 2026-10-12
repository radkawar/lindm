import type { Timestamp } from "@bufbuild/protobuf/wkt";
import { useEffect, useState } from "react";
import {
  AdvisoryFindingState,
  type AdvisoryFeedStatus,
} from "../../../gen/lindm/admin/v1/advisories_pb";
import { Button } from "@/components/ui/button";

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

export function publishedSeverity(severity: string) {
  const value = severity.trim();
  return Object.hasOwn(unpublishedSeverities, value.toLowerCase())
    ? ""
    : value.charAt(0).toUpperCase() + value.slice(1).toLowerCase();
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

// Why a refreshed, unexpired source is still incomplete, as one sentence, and
// its remedy. An unscoped skipped entry voids completeness; otherwise the source
// never claimed to list every advisory of its release.
export function sourceGap(feed: AdvisoryFeedStatus) {
  const os = feedOSLabel(feed);
  const unscoped = feed.rejectedRecords.filter(
    (record) => record.unscoped || record.packageNames.length === 0,
  ).length;
  if (unscoped === 0) {
    return {
      missing: `Missing the complete ${os} advisory list; this source has only selected advisories, so no ${os} device can be shown as unaffected.`,
      remedy: `Configure a source that lists every ${os} advisory under advisories.feeds in the server configuration.`,
    };
  }
  const entries = unscoped === 1 ? "1 skipped entry" : `${unscoped} skipped entries`;
  return {
    missing: `Missing the affected packages of ${entries}, so no ${os} device can be shown as unaffected.`,
    remedy: `Review the skipped entries below; ${os} devices stay unchecked until the vendor names their packages.`,
  };
}

// Derivative vendors whose packages no published feed covers. The evaluation
// reason names the vendor; uncovered vendor packages share that text.
const vendorFeedText: Record<string, string> = {
  vendor_feed_unavailable_linuxmint: "vendor feed unavailable for Linux Mint packages",
  vendor_feed_unavailable_pop: "vendor feed unavailable for Pop!_OS packages",
};

const uncoveredReasonText: Record<string, string> = {
  origin_unavailable: "APT origin evidence unavailable",
  origin_unlisted: "installed version not listed by any APT source",
  origin_ambiguous: "version also listed by a non-Ubuntu source",
  origin_unverified: "listed only by unsigned or unverified APT sources",
  origin_not_covered: "listed only by sources no advisory feed covers",
  base_pocket_uncovered: "Ubuntu pocket without security support (backports or proposed)",
};

export function advisoryReasonText(reason: string) {
  return vendorFeedText[reason] ?? reason.replaceAll("_", " ");
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
