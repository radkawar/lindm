// SPDX-License-Identifier: Apache-2.0

import { create, toJsonString } from "@bufbuild/protobuf";
import { Link } from "@tanstack/react-router";
import { TriangleAlertIcon } from "lucide-react";
import type { ReactNode } from "react";
import {
  AdvisoryUncheckedReason,
  type AdvisoryFeedStatus,
  type ListAdvisorySummaryResponse,
} from "../../../gen/lindm/admin/v1/advisories_pb";
import { DeviceFilterSchema } from "../../../gen/lindm/admin/v1/inventory_management_pb";
import { Button, buttonVariants } from "@/components/ui/button";
import { feedOSLabel, osLabel, sourceAnchor } from "./display";

// The remedy a cause offers: wait for the background check, act on the devices
// (request inventory, inspect their evidence), or fix the advisory source setup.
type Fix = "reload" | "devices" | "source" | "sources";

function describe(
  reason: AdvisoryUncheckedReason,
  os: string,
  feed: AdvisoryFeedStatus | undefined,
): { title: string; detail: string; fix: Fix } {
  switch (reason) {
    case AdvisoryUncheckedReason.EVALUATION_PENDING:
      return {
        title: "Check not finished",
        detail:
          "lindm hasn't yet compared their latest inventory with the current sources; this runs automatically.",
        fix: "reload",
      };
    case AdvisoryUncheckedReason.INVENTORY_UNAVAILABLE:
      return {
        title: "No inventory yet",
        detail: "These devices haven't sent a package inventory, so there is nothing to check.",
        fix: "devices",
      };
    case AdvisoryUncheckedReason.INVENTORY_STALE:
      return {
        title: "Inventory out of date",
        detail: "Their last package inventory is too old to trust. Request fresh inventory.",
        fix: "devices",
      };
    case AdvisoryUncheckedReason.HOST_INVENTORY_STALE_OR_FAILED:
      return {
        title: "OS details missing or out of date",
        detail: "These devices haven't reported a current OS release and architecture.",
        fix: "devices",
      };
    case AdvisoryUncheckedReason.PACKAGE_COLLECTION_FAILED:
      return {
        title: "Package list failed",
        detail: "The last attempt to list installed packages failed on these devices.",
        fix: "devices",
      };
    case AdvisoryUncheckedReason.FEED_UNAVAILABLE:
      return {
        title: `No advisory source for ${os}`,
        detail: `The lindm server has no ${os} advisory source to check these devices against.`,
        fix: "sources",
      };
    case AdvisoryUncheckedReason.RHEL_PLATFORM_STREAM_UNAVAILABLE:
      return {
        title: "Update stream not reported",
        detail:
          "These devices haven't reported which RHEL update stream they follow, so no source applies.",
        fix: "devices",
      };
    case AdvisoryUncheckedReason.FEED_STALE:
      return {
        title: `Source out of date for ${os}`,
        detail: `The ${os} source expired without a successful refresh; its card shows why.`,
        fix: "source",
      };
    case AdvisoryUncheckedReason.FEED_PARTIAL_COVERAGE:
      return {
        title: `Source incomplete for ${os}`,
        detail: feed
          ? "Device exposure remains unknown until the source lists every advisory."
          : `The ${os} source doesn't list every ${os} advisory, so these devices stay unchecked.`,
        fix: "source",
      };
    case AdvisoryUncheckedReason.SOURCE_PACKAGE_IDENTITY_MISSING:
      return {
        title: "Package source names missing",
        detail:
          "Devices reported some installed packages without the source names that advisories use.",
        fix: "devices",
      };
    case AdvisoryUncheckedReason.PACKAGE_ARCHITECTURE_UNCOVERED:
      return {
        title: "Package architecture not covered",
        detail: `Some installed packages use an architecture the ${os} source doesn't cover.`,
        fix: "source",
      };
    case AdvisoryUncheckedReason.PACKAGE_ORIGIN_UNAVAILABLE:
      return {
        title: "Package origins unknown",
        detail: `lindm could not trace any installed package to a repository that the ${os} source covers.`,
        fix: "devices",
      };
    case AdvisoryUncheckedReason.PACKAGE_VERSION_UNRECOGNIZED:
      return {
        title: "Package version not understood",
        detail: "lindm could not compare an installed package version with an advisory's fix.",
        fix: "devices",
      };
    case AdvisoryUncheckedReason.NATIVE_MODULE_IDENTITY_UNAVAILABLE:
      return {
        title: "Module streams not reported",
        detail: "These devices haven't reported which module stream their packages come from.",
        fix: "devices",
      };
    case AdvisoryUncheckedReason.NATIVE_PACKAGE_INSTANCES_UNAVAILABLE:
      return {
        title: "Installed package details missing",
        detail: "Devices did not report every installed copy of a package that an advisory needs.",
        fix: "devices",
      };
    case AdvisoryUncheckedReason.NATIVE_PRODUCT_PREDICATE_UNSATISFIED:
      return {
        title: "Release package not confirmed",
        detail:
          "An advisory requires a specific release package. Device evidence does not confirm this package.",
        fix: "devices",
      };
    case AdvisoryUncheckedReason.ADVISORY_RECORD_INVALID:
      return {
        title: "Unreadable advisory entry",
        detail: `lindm could not read an entry in the ${os} source.`,
        fix: "source",
      };
    case AdvisoryUncheckedReason.SOURCE_RECORD_REJECTED:
      return {
        title: "Skipped advisory entry",
        detail: `The ${os} source skipped an entry naming a package installed on these devices.`,
        fix: "source",
      };
    case AdvisoryUncheckedReason.VENDOR_ASSESSMENT_UNKNOWN:
      return {
        title: "Vendor assessment pending",
        detail: "The vendor still lists an installed package as under investigation.",
        fix: "devices",
      };
    case AdvisoryUncheckedReason.VENDOR_MODULE_BINDING_AMBIGUOUS:
      return {
        title: "Advisory module unclear",
        detail: `An ${os} advisory doesn't say which module stream it applies to.`,
        fix: "source",
      };
    case AdvisoryUncheckedReason.MATCHING_CAPACITY_EXCEEDED:
      return {
        title: "Too many matches",
        detail: "More advisories matched than lindm can record for one device.",
        fix: "devices",
      };
    default:
      return {
        title: "Cause not named by this console",
        detail: "Open a device's Advisories tab to see the reported cause.",
        fix: "devices",
      };
  }
}

const fixClass = buttonVariants({ variant: "outline", size: "sm" });

function CauseRow({
  title,
  detail,
  devices,
  children,
}: {
  title: string;
  detail: string;
  devices: bigint;
  children: ReactNode;
}) {
  return (
    <li
      data-advisory-unchecked-group=""
      data-devices={devices.toString()}
      className="flex min-w-0 flex-wrap items-start justify-between gap-x-4 gap-y-2 py-3"
    >
      <div className="grid min-w-0 flex-1 basis-80 gap-1">
        <p className="font-medium">
          {title}{" "}
          <span className="font-normal text-muted-foreground tabular-nums">
            · {devices.toString()} {devices === 1n ? "device" : "devices"}
          </span>
        </p>
        <p className="text-muted-foreground">{detail}</p>
      </div>
      {children}
    </li>
  );
}

// Leads /advisories whenever devices are unchecked: why, grouped by cause and OS
// release, with one remedy per group. Counts come from the same summary as the
// "Devices not checked" total, so the groups add up to it. Source remedies need
// fleet-wide access; other readers are told who acts instead.
export function CoverageBanner({
  summary,
  feeds,
  canReviewSources,
  reloading,
  onReload,
}: {
  summary: ListAdvisorySummaryResponse;
  feeds: readonly AdvisoryFeedStatus[];
  canReviewSources: boolean;
  reloading: boolean;
  onReload: () => void;
}) {
  const total = summary.unknownDevices;
  if (total === 0n) return null;
  const listed = summary.uncheckedGroups.reduce((sum, group) => sum + group.devices, 0n);
  return (
    <section
      aria-labelledby="advisory-coverage-title"
      data-advisory-coverage-banner=""
      className="grid min-w-0 gap-3 rounded-lg border border-l-4 border-warning/40 border-l-warning bg-card p-4 text-sm text-card-foreground"
    >
      <div className="flex items-start gap-2">
        <TriangleAlertIcon aria-hidden="true" className="mt-0.5 size-4 shrink-0 text-warning" />
        <div className="grid gap-1">
          <h2 id="advisory-coverage-title" className="text-base font-semibold">
            {total === 1n
              ? "lindm has not checked 1 device for advisories"
              : `lindm has not checked ${total.toString()} devices for advisories`}
          </h2>
          <p className="text-muted-foreground">
            Exposure remains unknown until you resolve the causes below.
          </p>
        </div>
      </div>
      <ul className="grid min-w-0 divide-y divide-warning/25 border-t border-warning/25">
        {summary.uncheckedGroups.map((group) => {
          const os = osLabel(group.osName, group.osId, group.osVersion);
          const feed = feeds.find((item) => item.id === group.feedId);
          const cause = describe(group.reason, os, feed);
          const filter = toJsonString(
            DeviceFilterSchema,
            create(DeviceFilterSchema, { osId: group.osId, osVersion: group.osVersion }),
          );
          return (
            <CauseRow
              key={`${group.reason}/${group.feedId}/${group.osId}/${group.osVersion}`}
              title={cause.title}
              detail={cause.detail}
              devices={group.devices}
            >
              {cause.fix === "reload" ? (
                <Button variant="outline" size="sm" disabled={reloading} onClick={onReload}>
                  {reloading ? "Reloading…" : "Reload status"}
                </Button>
              ) : cause.fix !== "devices" && !canReviewSources ? (
                <p className="text-muted-foreground">An owner or admin manages advisory sources.</p>
              ) : cause.fix === "source" && feed ? (
                <Link to="/advisories" hash={sourceAnchor(feed.id)} className={fixClass}>
                  Review {feedOSLabel(feed)} source
                </Link>
              ) : cause.fix !== "devices" ? (
                <Link to="/advisories" hash="advisory-sources" className={fixClass}>
                  Review advisory sources
                </Link>
              ) : (
                <Link
                  to="/devices"
                  search={{ pageSize: 50, pageToken: "", filter: group.osId ? filter : "" }}
                  className={fixClass}
                >
                  {group.osId ? `Show ${os} devices` : "Show devices"}
                </Link>
              )}
            </CauseRow>
          );
        })}
        {total > listed ? (
          <CauseRow
            title="Other causes"
            detail="Open a device's Advisories tab to see its reported cause."
            devices={total - listed}
          >
            <Link to="/devices" className={fixClass}>
              Show devices
            </Link>
          </CauseRow>
        ) : null}
      </ul>
    </section>
  );
}
