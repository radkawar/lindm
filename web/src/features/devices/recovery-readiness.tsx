import type { RecoveryReadiness } from "../../../gen/lindm/admin/v1/device_actions_pb";
import { StatusBadge } from "@/components/ui/status-badge";
import { TechnicalDetails } from "@/components/ui/technical-details";
import { exactBytes, formatBytes } from "@/lib/bytes";
import { Fact, ObservedTime } from "./observations";
import { recoveryReadinessMessage, recoveryReadinessTone } from "@/lib/errors";

// The Details items RecoveryReadinessView shows, for screens that render one
// merged disclosure with `technicalDetails={false}`.
export function recoveryReadinessDetailItems(readiness: RecoveryReadiness | undefined) {
  const observation = readiness?.observation;
  const observed = observation?.available === true;
  return [
    { label: "Boot partition UUID", value: observed ? observation.espUuid : undefined },
    {
      label: "Exact available space",
      value: observed && readiness ? exactBytes(readiness.availableBytes) : undefined,
    },
    {
      label: "Exact required space",
      value:
        readiness && readiness.neededBytes > 0n ? exactBytes(readiness.neededBytes) : undefined,
    },
    {
      label: "Exact recovery image size",
      value: readiness && readiness.imageSize > 0n ? exactBytes(readiness.imageSize) : undefined,
    },
    { label: "Reason code", value: readiness?.reason },
  ];
}

export function RecoveryReadinessView({
  readiness,
  technicalDetails = true,
}: {
  readiness: RecoveryReadiness | undefined;
  technicalDetails?: boolean;
}) {
  const observation = readiness?.observation;
  const observed = observation?.available === true;
  const reason = readiness?.reason || "device_action_recovery_readiness_missing";
  return (
    <section className="grid gap-3 border p-4" aria-label="Recovery readiness">
      <div className="flex flex-wrap items-center gap-2">
        <h3 className="text-sm font-medium">Recovery readiness</h3>
        <StatusBadge status={readiness?.ready ? "success" : recoveryReadinessTone(reason)}>
          {readiness?.ready
            ? "Ready"
            : reason === "device_action_esp_insufficient"
              ? "Not enough boot partition space"
              : "Not ready"}
        </StatusBadge>
      </div>
      {!readiness?.ready ? <p className="text-sm">{recoveryReadinessMessage(reason)}</p> : null}
      {reason === "device_action_esp_insufficient" ? (
        <p className="text-sm text-muted-foreground">
          You&apos;ll need physical access to boot this device from external recovery media.
        </p>
      ) : null}
      <dl className="grid gap-3 text-sm sm:grid-cols-2">
        <Fact label="Reported">
          <ObservedTime value={observation?.observedAt} />
        </Fact>
        <Fact label="Boot partition">{observed ? observation.espPath : "Not available"}</Fact>
        <Fact label="Available space">
          {observed ? formatBytes(readiness!.availableBytes) : "Not available"}
        </Fact>
        <Fact label="Required space">
          {readiness && readiness.neededBytes > 0n
            ? formatBytes(readiness.neededBytes)
            : "Enter a recovery image"}
        </Fact>
        <Fact label="Recovery image size">
          {readiness && readiness.imageSize > 0n
            ? formatBytes(readiness.imageSize)
            : "Not available"}
        </Fact>
        <Fact label="Secure Boot">
          {observed ? (observation.secureBoot ? "Enabled" : "Disabled") : "Not available"}
        </Fact>
        <Fact label="UKI support">
          {observed ? (observation.ukiCapable ? "Supported" : "Not supported") : "Not available"}
        </Fact>
      </dl>
      {technicalDetails ? (
        <TechnicalDetails items={recoveryReadinessDetailItems(readiness)} />
      ) : null}
    </section>
  );
}
