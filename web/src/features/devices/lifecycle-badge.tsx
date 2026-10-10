import { DeviceState } from "../../../gen/lindm/admin/v1/admin_pb";
import { StatusBadge } from "@/components/ui/status-badge";

const labels: Record<DeviceState, string> = {
  [DeviceState.UNSPECIFIED]: "Not reported",
  [DeviceState.PENDING]: "Pending",
  [DeviceState.ACTIVE]: "Active",
  [DeviceState.REVOKED]: "Revoked",
  [DeviceState.RECOVERY_HOLD]: "Recovery hold",
};

export function DeviceLifecycleBadge({ state }: { state: DeviceState }) {
  return (
    <StatusBadge
      dot
      status={
        state === DeviceState.ACTIVE
          ? "success"
          : state === DeviceState.REVOKED
            ? "destructive"
            : state === DeviceState.PENDING || state === DeviceState.RECOVERY_HOLD
              ? "warning"
              : "neutral"
      }
    >
      {labels[state] ?? "Unknown state"}
    </StatusBadge>
  );
}
