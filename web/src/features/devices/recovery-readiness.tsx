import type { RecoveryReadiness } from "../../../gen/lindm/admin/v1/device_actions_pb";
import { StatusBadge } from "@/components/ui/status-badge";
import { Fact, ObservedTime } from "./observations";
import { recoveryReadinessMessage, recoveryReadinessTone } from "@/lib/errors";

export function RecoveryReadinessView({ readiness }: { readiness: RecoveryReadiness | undefined }) {
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
              ? "Unsupported: ESP capacity"
              : "Not ready"}
        </StatusBadge>
      </div>
      {!readiness?.ready ? <p className="text-sm">{recoveryReadinessMessage(reason)}</p> : null}
      {reason === "device_action_esp_insufficient" ? (
        <p className="text-sm text-muted-foreground">
          External recovery requires physical access, protected off-target state, exact media
          revalidation and fresh two-person authorization. It is not remote wipe of a lost or stolen
          device.
        </p>
      ) : null}
      <dl className="grid gap-3 text-sm sm:grid-cols-2">
        <Fact label="Observed">
          <ObservedTime value={observation?.observedAt} />
        </Fact>
        <Fact label="EFI system partition">
          {observed ? `${observation.espPath} (${observation.espUuid})` : "Not available"}
        </Fact>
        <Fact label="Available space">
          {observed ? `${readiness!.availableBytes.toLocaleString()} bytes` : "Not available"}
        </Fact>
        <Fact label="Required space">
          {readiness && readiness.neededBytes > 0n
            ? `${readiness.neededBytes.toLocaleString()} bytes`
            : "Select a signed image"}
        </Fact>
        <Fact label="Signed image size">
          {readiness && readiness.imageSize > 0n
            ? `${readiness.imageSize.toLocaleString()} bytes`
            : "Not available"}
        </Fact>
        <Fact label="Secure Boot">
          {observed ? (observation.secureBoot ? "Enabled" : "Disabled") : "Not available"}
        </Fact>
        <Fact label="UKI support">
          {observed ? (observation.ukiCapable ? "Supported" : "Not supported") : "Not available"}
        </Fact>
      </dl>
      {readiness?.reason ? (
        <p className="break-words text-xs text-muted-foreground">Reason: {readiness.reason}</p>
      ) : null}
    </section>
  );
}
