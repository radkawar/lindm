import { toJsonString } from "@bufbuild/protobuf";
import { Link } from "@tanstack/react-router";
import type { PreviewTargetAssignmentImpactResponse } from "../../../gen/lindm/admin/v1/targeting_pb";
import {
  ResourceResolutionDisposition,
  TargetMatch,
  type TargetResolution,
} from "../../../gen/lindm/policy/v1/targeting_pb";
import { ProfileResourceSchema } from "../../../gen/lindm/policy/v1/profile_pb";
import { Alert, AlertTitle, AlertDescription } from "@/components/ui/alert";
import { StatusBadge } from "@/components/ui/status-badge";
import { TechnicalDetails } from "@/components/ui/technical-details";
import { settingTechnicalIds, settingTitle } from "@/lib/setting-identity";
import { blockedReasonLabel } from "@/lib/errors";
import { resourceKindLabel } from "@/lib/resource-labels";
import { formatTimestamp } from "@/lib/time";

const reasonLabels: Record<string, string> = {
  native_capabilities_unknown:
    "Device execution support is unknown; this review only checks server-side support.",
  host_inventory_unknown: "Inventory is missing. Request fresh inventory on this device.",
  host_inventory_stale: "Inventory is older than 24 hours. Request fresh inventory on this device.",
  membership_inventory_stale:
    "Inventory is too old to confirm target membership. Request fresh inventory on this device.",
  device_not_active: "This device is not enrolled for active management.",
  membership_unknown: "Target membership is unknown. Check group rules and fresh inventory.",
  resolution_has_unknown_membership:
    "Other assignments have unknown membership. Resolve these before activation.",
  candidate_limit: "The target exceeds the review device limit. Narrow the target.",
  report_byte_limit: "The impact report exceeds the review size limit. Narrow the target.",
  device_visibility_incomplete:
    "Some affected devices are outside your access. Ask an administrator with full device access to review.",
};
const stateLabels: Record<string, string> = {
  active: "Enrolled",
  revoked: "Revoked",
  recovery_hold: "Recovery hold",
  pending: "Waiting to enroll",
};

function Resolution({ title, value }: { title: string; value?: TargetResolution }) {
  return (
    <section className="grid content-start gap-2">
      <h4 className="text-sm font-medium">{title}</h4>
      {!value ? (
        <p className="text-sm text-muted-foreground">
          Settings could not be resolved. Inspect this device before activation.
        </p>
      ) : value.resources.length === 0 ? (
        <p className="text-sm text-muted-foreground">No settings selected.</p>
      ) : (
        <ul className="grid gap-2">
          {value.resources.map((resource, index) => (
            <li key={index} className="grid gap-1 border p-2 text-sm">
              <span className="font-medium">{resourceKindLabel(resource.ref?.kind)}</span>
              <span className="break-all">
                {settingTitle(resource.ref, resource.resource?.desired) ??
                  "Setting identity unavailable"}
              </span>
              <div className="flex flex-wrap gap-2">
                <StatusBadge
                  status={
                    resource.disposition === ResourceResolutionDisposition.CONFLICT
                      ? "destructive"
                      : resource.disposition === ResourceResolutionDisposition.BLOCKED
                        ? "warning"
                        : "neutral"
                  }
                >
                  {resource.disposition === ResourceResolutionDisposition.READY
                    ? "Ready for activation review"
                    : resource.disposition === ResourceResolutionDisposition.CONFLICT
                      ? "Conflicting settings"
                      : resource.disposition === ResourceResolutionDisposition.BLOCKED
                        ? "Blocked"
                        : "Resolution unknown"}
                </StatusBadge>
                {!resource.dispatchSupported ? (
                  <StatusBadge status="warning">Not supported by server</StatusBadge>
                ) : null}
              </div>
              {resource.reason ? <p>{blockedReasonLabel(resource.reason)}</p> : null}
              {resource.overriddenRevisionIds.length ? (
                <p>
                  Overrides {resource.overriddenRevisionIds.length} other profile{" "}
                  {resource.overriddenRevisionIds.length === 1 ? "version" : "versions"}.
                </p>
              ) : null}
              <TechnicalDetails
                items={[
                  { label: "Required capability", value: resource.capabilityId },
                  ...settingTechnicalIds(resource.ref),
                  { label: "Reason code", value: resource.reason },
                  {
                    label: "Contributing profile versions",
                    value: resource.contributingRevisionIds.join(", "),
                  },
                  {
                    label: "Overridden profile versions",
                    value: resource.overriddenRevisionIds.join(", "),
                  },
                ]}
              >
                {resource.resource ? (
                  <pre className="mt-2 overflow-auto whitespace-pre-wrap break-all">
                    {toJsonString(ProfileResourceSchema, resource.resource, { prettySpaces: 2 })}
                  </pre>
                ) : null}
              </TechnicalDetails>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

export function AssignmentImpact({
  review,
  expired,
}: {
  review: PreviewTargetAssignmentImpactResponse;
  expired: boolean;
}) {
  return (
    <section className="grid min-w-0 gap-4 border-t pt-4" aria-label="Affected devices">
      <div className="grid gap-2">
        <h3 className="text-base font-semibold">Affected devices</h3>
        <p className="text-sm">
          {review.includedCount} included, {review.excludedCount} excluded, {review.unknownCount}{" "}
          unknown among {review.evaluatedDeviceCount} evaluated devices
          {review.complete ? "." : "; these counts are lower bounds."}
        </p>
        <p className="text-sm text-muted-foreground">
          {review.complete ? "" : "At least "}
          {review.targetCount} devices match or may match the selected target before exclusions and
          timing; {review.candidateCount} candidates include any previous assignment scope.
        </p>
        <p className="text-xs text-muted-foreground">
          Checked {formatTimestamp(review.evaluatedAt).local}. Valid until{" "}
          {formatTimestamp(review.validUntil).local}.
        </p>
      </div>
      {!review.complete ? (
        <Alert>
          <AlertTitle>Impact coverage is incomplete</AlertTitle>
          <AlertDescription>
            Do not treat these devices as the complete affected set. Narrow the target or ask an
            administrator with full device access to review it. Saving is blocked.
          </AlertDescription>
        </Alert>
      ) : null}
      {review.reasons.length ? (
        <ul className="list-inside list-disc text-sm">
          {review.reasons.map((reason) => (
            <li key={reason}>{reasonLabels[reason] ?? reason.replaceAll("_", " ")}</li>
          ))}
        </ul>
      ) : null}
      {expired ? (
        <Alert>
          <AlertTitle>This review has expired</AlertTitle>
          <AlertDescription>
            Review affected devices again before starting a save. An uncertain save must still be
            retried with the same request.
          </AlertDescription>
        </Alert>
      ) : null}
      {review.unknownCount > 0 ? (
        <Alert>
          <AlertTitle>Some targeting is unknown</AlertTitle>
          <AlertDescription>
            Missing or old inventory can prevent a reliable match. Inspect the named devices and
            refresh their inventory before activation.
          </AlertDescription>
        </Alert>
      ) : null}
      <p className="text-sm text-muted-foreground">
        This compares currently assigned settings with the proposal for a separate activation. It is
        not evidence that devices have applied either version.
      </p>
      {review.devices.length === 0 ? (
        <p className="text-sm">
          No devices appear in this review. Check the selected target, exclusions and timing before
          saving.
        </p>
      ) : (
        <ul className="grid gap-3">
          {review.devices.map((device) => (
            <li key={device.deviceId} className="grid min-w-0 gap-3 border p-3">
              <div className="flex flex-wrap items-start justify-between gap-2">
                <div className="grid min-w-0 gap-1">
                  <Link
                    to="/devices/$deviceId"
                    params={{ deviceId: device.deviceId }}
                    className="break-words text-sm font-semibold underline"
                  >
                    {device.hostname || "Unnamed device"}
                  </Link>
                  <p className="text-xs text-muted-foreground">
                    {[device.osId, device.osVersion, device.architecture]
                      .filter(Boolean)
                      .join(" · ") || "Operating system unknown"}
                  </p>
                </div>
                <div className="flex flex-wrap gap-2">
                  <StatusBadge
                    status={
                      device.state === "revoked"
                        ? "destructive"
                        : device.state === "recovery_hold"
                          ? "warning"
                          : "neutral"
                    }
                  >
                    {stateLabels[device.state] ?? "Enrollment state unknown"}
                  </StatusBadge>
                  <StatusBadge
                    status={device.match === TargetMatch.UNKNOWN ? "warning" : "neutral"}
                  >
                    {device.match === TargetMatch.INCLUDED
                      ? "Included"
                      : device.match === TargetMatch.EXCLUDED
                        ? "Excluded"
                        : "Match unknown"}
                  </StatusBadge>
                  <StatusBadge status={device.changed ? "info" : "neutral"}>
                    {device.changed ? "Settings would change" : "No resolved settings difference"}
                  </StatusBadge>
                </div>
              </div>
              <p className="text-xs text-muted-foreground">
                Inventory received:{" "}
                {device.hostReceivedAt
                  ? formatTimestamp(device.hostReceivedAt).local
                  : "Unknown. Request fresh inventory on this device."}
              </p>
              {device.reasons.length ? (
                <ul className="list-inside list-disc text-sm">
                  {device.reasons.map((reason) => (
                    <li key={reason}>{reasonLabels[reason] ?? reason.replaceAll("_", " ")}</li>
                  ))}
                </ul>
              ) : null}
              <div className="grid min-w-0 gap-4 md:grid-cols-2">
                <Resolution title="Currently assigned settings" value={device.currentResolution} />
                <Resolution
                  title="Proposed settings for separate activation"
                  value={device.proposedResolution}
                />
              </div>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
