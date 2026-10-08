import { DeviceState } from "../../../gen/lindm/admin/v1/admin_pb";
import { Badge } from "@/components/ui/badge";

const labels: Record<DeviceState, string> = {
  [DeviceState.UNSPECIFIED]: "Not reported",
  [DeviceState.PENDING]: "Pending",
  [DeviceState.ACTIVE]: "Active",
  [DeviceState.REVOKED]: "Revoked",
  [DeviceState.RECOVERY_HOLD]: "Recovery hold",
};

export function DeviceLifecycleBadge({ state }: { state: DeviceState }) {
  return (
    <Badge
      variant={
        state === DeviceState.REVOKED || state === DeviceState.RECOVERY_HOLD
          ? "destructive"
          : "outline"
      }
    >
      {labels[state] ?? "Unknown state"}
    </Badge>
  );
}
