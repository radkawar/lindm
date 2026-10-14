// SPDX-License-Identifier: Apache-2.0

import { equals } from "@bufbuild/protobuf";
import { Link } from "@tanstack/react-router";
import { createContext, Fragment, useContext, type ReactNode } from "react";
import type {
  PreviewTargetAssignmentImpactResponse,
  ProfileVersionLabel,
  TargetAssignmentDeviceImpact,
} from "../../../gen/lindm/admin/v1/targeting_pb";
import {
  ResourceResolutionDisposition,
  TargetMatch,
  type ResolvedResource,
} from "../../../gen/lindm/policy/v1/targeting_pb";
import { ProfileResourceSchema } from "../../../gen/lindm/policy/v1/profile_pb";
import { OwnershipMode } from "../../../gen/lindm/resource/v1/common_pb";
import { ResourceKind, type ResourceRef } from "../../../gen/lindm/resource/v1/identity_pb";
import type { ResourceDesiredState } from "../../../gen/lindm/resource/v1/resource_pb";
import { Alert, AlertTitle, AlertDescription } from "@/components/ui/alert";
import { StatusBadge } from "@/components/ui/status-badge";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Timestamp } from "@/components/ui/timestamp";
import { resourceKindLabel } from "@/lib/resource-labels";
import { settingTitle } from "@/lib/setting-identity";
import { ProfileVersionName, TargetName } from "./pickers";

// "Server hardening, version 1" from the server's label, never an identifier.
export function versionText(label?: ProfileVersionLabel) {
  return label ? `${label.profileName}, version ${label.revisionNumber.toString()}` : "";
}

// The review page names every profile version its rows refer to; the picker
// lookup remains only a fallback for a label the page could not carry.
const RevisionLabels = createContext<ReadonlyMap<string, ProfileVersionLabel>>(new Map());

function VersionName({ value }: { value: string }) {
  const label = useContext(RevisionLabels).get(value);
  return label ? <>{versionText(label)}</> : <ProfileVersionName value={value} />;
}

export const reasonLabels: Record<string, string> = {
  native_capabilities_unknown: "The review checked server support only. Device support is unknown.",
  host_inventory_unknown: "Its inventory is missing. Request fresh inventory on this device.",
  host_inventory_stale:
    "Its inventory is older than 24 hours. Request fresh inventory on this device.",
  membership_inventory_stale:
    "Its inventory is too old to tell whether it's in the target. Request fresh inventory.",
  device_not_active: "It isn't enrolled for active management.",
  membership_unknown:
    "Its inventory is missing or too old to tell whether it's in the target. Request fresh inventory.",
  resolution_has_unknown_membership:
    "Another assignment cannot confirm this device's membership. That assignment can still change its settings.",
  candidate_limit: "The target has more devices than one review covers. Narrow the target.",
  report_byte_limit: "The review is too large to keep. Narrow the target.",
  device_visibility_incomplete:
    "Some affected devices are outside your access. Ask an administrator with full device access to review.",
};

// A setting in admin words: its kind, then its key as a technical value, e.g.
// "Kernel setting kernel.kptr_restrict". A firewall zone's key is a generated
// id, so it is named by kind only. Without `kind`, only the key is shown.
function Setting({
  value,
  desired,
  kind = true,
}: {
  value?: ResourceRef;
  desired?: ResourceDesiredState;
  kind?: boolean;
}) {
  const label = resourceKindLabel(value?.kind);
  // Firewall zones read by name ("Unnamed zone" without one), never their UUID.
  const identity = settingTitle(value, desired) ?? "";
  if (!identity) return <>{label}</>;
  if (value?.kind === ResourceKind.FIREWALL_ZONE)
    return <>{kind ? `${label} ${identity}` : identity}</>;
  return (
    <>
      {kind ? `${label} ` : ""}
      <code className="font-mono text-[0.92em] break-all">{identity}</code>
    </>
  );
}

// At most three settings, then "and N more".
export function SettingList({
  refs,
  resources,
  kind = true,
}: {
  refs?: (ResourceRef | undefined)[];
  resources?: ResolvedResource[];
  kind?: boolean;
}) {
  const items = resources
    ? resources.map((item) => ({ ref: item.ref, desired: item.resource?.desired }))
    : (refs ?? []).map((ref) => ({ ref, desired: undefined }));
  return (
    <>
      {items.slice(0, 3).map((item, index) => (
        <Fragment key={index}>
          {index ? ", " : ""}
          <Setting value={item.ref} desired={item.desired} kind={kind} />
        </Fragment>
      ))}
      {items.length > 3 ? ` and ${items.length - 3} more` : ""}
    </>
  );
}

function plural(count: number, one: string, many = `${one}s`) {
  return `${count} ${count === 1 ? one : many}`;
}

// Settings grouped by the profile versions that provide them, one line each.
function bySource(resources: ResolvedResource[], ids: (resource: ResolvedResource) => string[]) {
  const groups = new Map<string, ResolvedResource[]>();
  for (const resource of resources) {
    const key = ids(resource)[0] ?? "";
    groups.set(key, [...(groups.get(key) ?? []), resource]);
  }
  return [...groups];
}

const key = (resource: ResolvedResource) => `${resource.ref?.kind}:${resource.ref?.canonicalKey}`;

// What one device's reviewed change does, compared with its current settings.
function deviceChange(device: TargetAssignmentDeviceImpact) {
  const current = new Map((device.currentResolution?.resources ?? []).map((r) => [key(r), r]));
  const proposed = device.proposedResolution?.resources ?? [];
  const proposedKeys = new Set(proposed.map(key));
  const added: ResolvedResource[] = [];
  const updated: ResolvedResource[] = [];
  for (const resource of proposed) {
    const before = current.get(key(resource));
    if (!before) added.push(resource);
    else if (
      before.disposition !== resource.disposition ||
      !before.resource !== !resource.resource ||
      (before.resource &&
        resource.resource &&
        !equals(ProfileResourceSchema, before.resource, resource.resource))
    )
      updated.push(resource);
  }
  return {
    added,
    updated,
    removed: [...current.values()].filter((resource) => !proposedKeys.has(key(resource))),
    overriding: proposed.filter((resource) => resource.overriddenRevisionIds.length > 0),
    adopting: proposed.filter(
      (resource) =>
        resource.resource?.ownership?.mode === OwnershipMode.APPROVED_ADOPTION &&
        !current.has(key(resource)),
    ),
    problems: proposed.filter(
      (resource) => resource.disposition !== ResourceResolutionDisposition.READY,
    ),
  };
}

// "Adopts the existing kernel.kptr_restrict on 2 devices"; nothing without adoptions.
export function Adoption({ adopted, devices }: { adopted: ResourceRef[]; devices: number }) {
  if (adopted.length === 0 || devices === 0) return null;
  return (
    <>
      Adopts the existing <SettingList refs={adopted} kind={false} /> on {plural(devices, "device")}
    </>
  );
}

// A projection of desired settings, not a promise of successful device execution.
export function impactSummary(review: PreviewTargetAssignmentImpactResponse) {
  const changing = review.changedCount + review.removingCount;
  const parts = [
    `Proposed changes on ${review.complete ? "" : "at least "}${plural(changing, "device")}`,
  ];
  const unchanged = Math.max(0, review.includedCount - review.changedCount);
  if (unchanged) parts.push(`${unchanged} unchanged`);
  const untargeted = Math.max(0, review.excludedCount - review.removingCount);
  if (untargeted) parts.push(`${untargeted} not targeted`);
  if (review.unknownCount) parts.push(`${review.unknownCount} unknown`);
  return parts.join(" · ");
}

function ChangeList({ device }: { device: TargetAssignmentDeviceImpact }) {
  if (device.match === TargetMatch.UNKNOWN)
    return (
      <p>
        {device.reasons.map((reason) => reasonLabels[reason]).find(Boolean) ??
          reasonLabels.membership_unknown}{" "}
        It won't change in this rollout.
      </p>
    );
  if (!device.proposedResolution)
    return (
      <p>The server could not determine settings. Review this device again before activation.</p>
    );
  if (
    !device.changed &&
    device.proposedResolution.resources.every(
      (resource) => resource.disposition === ResourceResolutionDisposition.READY,
    )
  )
    return <p className="text-muted-foreground">Already has these settings; nothing changes.</p>;
  const change = deviceChange(device);
  const lines: { key: string; text: ReactNode; tone?: "warning" | "destructive" }[] = [];
  // An adopted setting is named once, as an adoption.
  const gets = change.added.filter((resource) => !change.adopting.includes(resource));
  if (gets.length)
    lines.push({
      key: "added",
      text: (
        <>
          Gets <SettingList resources={gets} />
        </>
      ),
    });
  if (change.updated.length)
    lines.push({
      key: "updated",
      text: (
        <>
          Updates <SettingList resources={change.updated} />
        </>
      ),
    });
  for (const [source, resources] of bySource(change.removed, (r) => r.contributingRevisionIds))
    lines.push({
      key: `removed:${source}`,
      tone: "warning",
      text: (
        <>
          Stops managing {plural(resources.length, "setting")} from{" "}
          {source ? <VersionName value={source} /> : "an earlier assignment"}:{" "}
          <SettingList resources={resources} />
        </>
      ),
    });
  for (const [source, resources] of bySource(change.overriding, (r) => r.overriddenRevisionIds))
    lines.push({
      key: `overrides:${source}`,
      text: (
        <>
          Takes precedence over <VersionName value={source} /> for{" "}
          <SettingList resources={resources} />
        </>
      ),
    });
  if (change.adopting.length)
    lines.push({
      key: "adopts",
      tone: "warning",
      text: (
        <>
          Adopts the existing <SettingList resources={change.adopting} kind={false} />
        </>
      ),
    });
  for (const resource of change.problems)
    lines.push({
      key: `problem:${key(resource)}`,
      tone: "destructive",
      text: (
        <>
          <Setting value={resource.ref} />{" "}
          {resource.disposition === ResourceResolutionDisposition.CONFLICT
            ? "conflicts with another assignment of equal priority"
            : resource.disposition === ResourceResolutionDisposition.BLOCKED
              ? `cannot apply${resource.reason ? ` (${resource.reason.replaceAll("_", " ")})` : ""}`
              : "has no resolved value"}
          . Resolve the problem before this device changes.
        </>
      ),
    });
  if (!lines.length) lines.push({ key: "order", text: "The settings change order or source." });
  return (
    <ul className="grid gap-1">
      {lines.map((line) => (
        <li
          key={line.key}
          className={
            line.tone === "destructive"
              ? "text-destructive"
              : line.tone === "warning"
                ? "text-warning"
                : undefined
          }
        >
          {line.text}
        </li>
      ))}
    </ul>
  );
}

function deviceStatus(device: TargetAssignmentDeviceImpact) {
  if (device.match === TargetMatch.UNKNOWN)
    return <StatusBadge status="warning">Membership unknown</StatusBadge>;
  if (device.match !== TargetMatch.INCLUDED)
    return <StatusBadge status="warning">Leaves this assignment</StatusBadge>;
  if (
    !device.proposedResolution ||
    device.proposedResolution.resources.some(
      (resource) => resource.disposition !== ResourceResolutionDisposition.READY,
    )
  )
    return <StatusBadge status="warning">Needs review</StatusBadge>;
  return device.changed ? (
    <StatusBadge status="info">Proposed change</StatusBadge>
  ) : (
    <StatusBadge status="neutral">Unchanged</StatusBadge>
  );
}

function DeviceLink({ device }: { device: TargetAssignmentDeviceImpact }) {
  return (
    <Link
      to="/devices/$deviceId"
      params={{ deviceId: device.deviceId }}
      className="break-words font-medium underline underline-offset-4"
    >
      {device.hostname || "Unnamed device"}
    </Link>
  );
}

export function AssignmentImpact({
  review,
  expired,
}: {
  review: PreviewTargetAssignmentImpactResponse;
  expired: boolean;
}) {
  // Not-targeted devices whose settings stay the same are context, not consequence.
  const shown = review.devices.filter(
    (device) => device.match !== TargetMatch.EXCLUDED || device.changed,
  );
  const untargeted = review.devices.filter(
    (device) => device.match === TargetMatch.EXCLUDED && !device.changed,
  );
  const adopting = review.adopted.length > 0 && review.adoptingCount > 0;
  const labels = new Map(review.revisionLabels.map((label) => [label.revisionId, label]));
  return (
    <RevisionLabels.Provider value={labels}>
      <section className="grid min-w-0 gap-3" aria-labelledby="impact-title">
        <h3 id="impact-title" className="text-base font-semibold">
          Impact
        </h3>
        <p className="text-sm font-medium" data-impact-summary>
          {impactSummary(review)}
        </p>
        {adopting ? (
          <p className="text-sm" data-impact-adoption>
            <Adoption adopted={review.adopted} devices={review.adoptingCount} />. Another
            administrator must approve adopting settings the device already has.
          </p>
        ) : null}
        {review.unknownCount > 0 ? (
          <p className="text-sm text-muted-foreground">
            The review cannot confirm membership for {plural(review.unknownCount, "device")} in{" "}
            <TargetName target={review.assignment?.target} />. Inventory is missing or too old. This
            rollout skips those devices. Refresh inventory. Review impact again to include them.
          </p>
        ) : null}
        {!review.complete ? (
          <Alert>
            <AlertTitle>This review doesn't cover every device</AlertTitle>
            <AlertDescription>
              {review.reasons.map((reason) => reasonLabels[reason]).find(Boolean) ??
                "Narrow the target or ask an administrator with full device access to review it."}{" "}
              You can't roll out an incomplete review.
            </AlertDescription>
          </Alert>
        ) : review.reasons.length ? (
          <ul className="list-inside list-disc text-sm">
            {review.reasons.map((reason) => (
              <li key={reason}>{reasonLabels[reason] ?? reason.replaceAll("_", " ")}</li>
            ))}
          </ul>
        ) : null}
        {expired ? (
          <Alert>
            <AlertTitle>This review has expired</AlertTitle>
            <AlertDescription>Review impact again before rolling out.</AlertDescription>
          </Alert>
        ) : null}
        {shown.length ? (
          <Table aria-label="Devices in this review">
            <TableHeader>
              <TableRow>
                <TableHead>Device</TableHead>
                <TableHead>What changes</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {shown.map((device) => (
                <TableRow key={device.deviceId} data-impact-match={TargetMatch[device.match]}>
                  <TableCell className="min-w-36 align-top whitespace-normal">
                    <div className="grid gap-1">
                      <DeviceLink device={device} />
                      <span className="text-xs text-muted-foreground">
                        {[device.osId, device.osVersion].filter(Boolean).join(" ") ||
                          "Operating system unknown"}
                      </span>
                    </div>
                  </TableCell>
                  <TableCell className="align-top whitespace-normal">
                    <div className="grid gap-1.5">
                      <div>{deviceStatus(device)}</div>
                      <ChangeList device={device} />
                    </div>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        ) : review.devices.length === 0 ? (
          <p className="text-sm">
            The target includes no devices. Check the target and its exclusions before rollout.
          </p>
        ) : null}
        {untargeted.length ? (
          <details className="text-sm" data-impact-untargeted>
            <summary className="w-fit cursor-pointer py-1">
              {plural(untargeted.length, "device")} on this page not targeted
            </summary>
            <ul className="mt-2 grid gap-1">
              {untargeted.map((device) => (
                <li key={device.deviceId} className="flex flex-wrap gap-2">
                  <DeviceLink device={device} />
                  <span className="text-muted-foreground">Not targeted; nothing changes.</span>
                </li>
              ))}
            </ul>
          </details>
        ) : null}
        <p className="text-xs text-muted-foreground">
          Checked <Timestamp value={review.evaluatedAt} />. Valid until{" "}
          <Timestamp value={review.validUntil} relative={false} />.
        </p>
      </section>
    </RevisionLabels.Provider>
  );
}
