import { createFileRoute } from "@tanstack/react-router";
import { useDeviceBreadcrumbTitle } from "@/features/devices/breadcrumb";
import { DeviceRecoveryRevealPage } from "@/features/devices/action-pages";
import { canonicalUuid } from "@/lib/ids";

export const Route = createFileRoute("/_authenticated/devices_/$deviceId_/recovery/$actionId")({
  params: {
    parse: ({ deviceId, actionId }) => {
      const device = canonicalUuid(deviceId);
      const action = canonicalUuid(actionId);
      if (
        !device ||
        !action ||
        device === "00000000-0000-0000-0000-000000000000" ||
        action === "00000000-0000-0000-0000-000000000000"
      )
        throw new Error("The URL must contain valid device and escrow action IDs.");
      return { deviceId: device, actionId: action };
    },
  },
  component: RecoveryRevealRoute,
});

function RecoveryRevealRoute() {
  const { deviceId, actionId } = Route.useParams();
  useDeviceBreadcrumbTitle(deviceId);
  return (
    <DeviceRecoveryRevealPage
      key={`${deviceId}:${actionId}`}
      deviceId={deviceId}
      actionId={actionId}
    />
  );
}
