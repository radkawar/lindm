import { Link } from "@tanstack/react-router";
import { cn } from "cn";
import type { ReactNode } from "react";
import type {
  CapabilityPolicyScope,
  DeviceCapabilityState,
} from "../../../gen/lindm/admin/v1/capabilities_pb";
import {
  CapabilityPolicyState,
  CapabilityStatus,
} from "../../../gen/lindm/agent/v1/capability_policy_pb";
import type { ManagementCapability } from "../../../gen/lindm/agent/v1/management_capability_pb";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { CapabilityIssuanceAlert } from "@/components/ui/capability-issuance";
import { StatusBadge, type StatusTone } from "@/components/ui/status-badge";
import { TechnicalDetails } from "@/components/ui/technical-details";
import { Timestamp } from "@/components/ui/timestamp";
import {
  CAPABILITIES_PATH,
  capabilityName,
  capabilityStatusLabels,
  localCapabilities,
  localCapabilityField,
  remoteCapabilities,
  reportedCapability,
  unavailableCause,
} from "@/lib/capabilities";

export type CapabilityScopeNameSlot = (props: { scope: CapabilityPolicyScope }) => ReactNode;

const statusTones: Record<CapabilityStatus, StatusTone> = {
  [CapabilityStatus.UNSPECIFIED]: "neutral",
  [CapabilityStatus.NOT_ENABLED]: "neutral",
  [CapabilityStatus.ENABLED]: "success",
  [CapabilityStatus.LOCAL]: "success",
  [CapabilityStatus.UNAVAILABLE]: "warning",
};

function AppliedPolicy({ state }: { state: DeviceCapabilityState }) {
  const reported = state.reported;
  if (!reported)
    return (
      <p>
        The device hasn&apos;t reported its capabilities. Agents older than capability policies
        never report them and use only their local{" "}
        <code className="font-mono text-xs">/etc/lindm/executor.json</code>; until it reports, what
        it actually manages is unknown.
      </p>
    );
  const issued = state.issuedVersion;
  const applied = reported.appliedVersion;
  switch (reported.state) {
    case CapabilityPolicyState.REFUSED_LOCALLY:
      return (
        <p className="text-warning">
          This device refuses capability policies from the server: root on the device set{" "}
          <code className="font-mono text-xs">capability_policy.refuse_remote</code> in{" "}
          <code className="font-mono text-xs">/etc/lindm/executor.json</code>. Only its local
          settings apply.
        </p>
      );
    case CapabilityPolicyState.INERT:
      return (
        <p className="text-warning">
          The policy the device holds (version {applied.toString()}) was signed by a key the current
          execution delegation no longer trusts, so it allows nothing until a newly signed version
          arrives.
        </p>
      );
    case CapabilityPolicyState.ACTIVE:
      return (
        <p>
          The device applies version {applied.toString()}, accepted{" "}
          <Timestamp value={reported.acceptedAt} />.
          {issued > applied
            ? ` Version ${issued.toString()} is waiting for the device's next check-in.`
            : ""}
        </p>
      );
    default:
      return (
        <p>
          The device hasn&apos;t accepted a capability policy yet
          {issued > 0n ? "; it picks one up at its next check-in" : ""}.
        </p>
      );
  }
}

function CapabilityRow({
  capability,
  state,
  scopeName: ScopeName,
  local,
}: {
  capability: ManagementCapability;
  state: DeviceCapabilityState;
  scopeName: CapabilityScopeNameSlot;
  local?: boolean;
}) {
  const sources = state.granted.find((grant) => grant.capability === capability)?.sources ?? [];
  const reported = reportedCapability(state.reported, capability);
  const status = reported?.status ?? CapabilityStatus.UNSPECIFIED;
  return (
    <li
      className={cn(
        "grid min-w-0 gap-1 border-b pb-2 text-sm sm:gap-3",
        state.reported
          ? "sm:grid-cols-[minmax(0,14rem)_minmax(0,1fr)_minmax(0,16rem)]"
          : "sm:grid-cols-[minmax(0,14rem)_minmax(0,1fr)]",
      )}
    >
      <span className="font-medium">{capabilityName(capability)}</span>
      <span className="min-w-0 break-words text-muted-foreground">
        {local ? (
          <>
            Set on the device only (
            <code className="font-mono text-xs">{localCapabilityField[capability]}</code>)
          </>
        ) : sources.length ? (
          <>
            Allowed for{" "}
            {sources.map((scope, index) => (
              <span key={index}>
                {index ? ", " : ""}
                <ScopeName scope={scope} />
              </span>
            ))}
          </>
        ) : (
          "Not allowed by any policy"
        )}
      </span>
      {/* Without a report there is no status to show per capability; the
          card says so once. */}
      {state.reported ? (
        <span className="grid min-w-0 gap-1">
          <StatusBadge status={statusTones[status]} className="w-fit">
            {capabilityStatusLabels[status]}
          </StatusBadge>
          {status === CapabilityStatus.UNAVAILABLE ? (
            <span className="break-words">{unavailableCause(reported?.detail ?? "")}</span>
          ) : null}
        </span>
      ) : null}
    </li>
  );
}

export function DeviceCapabilities({
  state,
  scopeName,
  canReview,
}: {
  // Absent before the device has an enrollment.
  state: DeviceCapabilityState | undefined;
  scopeName: CapabilityScopeNameSlot;
  canReview: boolean;
}) {
  const causes = state?.reported?.capabilities
    .filter((entry) => entry.detail)
    .map((entry) => `${capabilityName(entry.capability)}: ${entry.detail}`)
    .join("; ");
  return (
    <Card className="min-w-0">
      <CardHeader>
        <CardTitle>
          <h2>Management capabilities</h2>
        </CardTitle>
        <CardDescription>
          The policy limits agent changes. The device reports which policy it applied.
        </CardDescription>
      </CardHeader>
      <CardContent className="grid min-w-0 gap-4 text-sm">
        {!state ? (
          <p>This device has no enrollment yet, so no capability policy applies to it.</p>
        ) : (
          <>
            <CapabilityIssuanceAlert reason={state.issuanceUnavailableReason} />
            <div className="grid gap-1">
              <p>
                {state.issuedVersion > 0n ? (
                  <>
                    The server issued version {state.issuedVersion.toString()}{" "}
                    <Timestamp value={state.issuedAt} />.
                  </>
                ) : (
                  "The server hasn't issued a capability policy for this device yet."
                )}
              </p>
              <AppliedPolicy state={state} />
              {state.reported ? (
                <p className="text-muted-foreground">
                  Reported <Timestamp value={state.reportedAt} />.
                </p>
              ) : null}
            </div>
            <ul className="grid min-w-0 gap-2" aria-label="Capabilities">
              {remoteCapabilities.map((capability) => (
                <CapabilityRow
                  key={capability}
                  capability={capability}
                  state={state}
                  scopeName={scopeName}
                />
              ))}
              {localCapabilities.map((capability) => (
                <CapabilityRow
                  key={capability}
                  capability={capability}
                  state={state}
                  scopeName={scopeName}
                  local
                />
              ))}
            </ul>
            {canReview ? (
              <Link to={CAPABILITIES_PATH} className="w-fit underline underline-offset-4">
                Change capabilities in Settings → Device capabilities
              </Link>
            ) : null}
            <TechnicalDetails
              items={[
                { label: "Issued version", value: state.issuedVersion.toString() },
                { label: "Applied version", value: state.reported?.appliedVersion.toString() },
                {
                  label: "Applied policy SHA-256",
                  value: state.reported?.appliedSha256.length
                    ? [...state.reported.appliedSha256]
                        .map((byte) => byte.toString(16).padStart(2, "0"))
                        .join("")
                    : "",
                },
                { label: "Signing unavailable reason", value: state.issuanceUnavailableReason },
                {
                  label: "Device state",
                  value: state.reported ? CapabilityPolicyState[state.reported.state] : "",
                },
                { label: "Unavailable causes", value: causes },
              ]}
            />
          </>
        )}
      </CardContent>
    </Card>
  );
}
