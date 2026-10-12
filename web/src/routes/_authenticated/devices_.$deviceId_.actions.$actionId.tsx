import { createFileRoute } from "@tanstack/react-router";
import { useDeviceBreadcrumbTitle } from "@/features/devices/breadcrumb";
import { DeviceActionStatusPage } from "@/features/devices/action-pages";
import { canonicalUuid } from "@/lib/ids";

export const Route = createFileRoute("/_authenticated/devices_/$deviceId_/actions/$actionId")({
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
        throw new Error("The URL must contain valid device and action IDs.");
      return { deviceId: device, actionId: action };
    },
  },
  component: ActionStatusRoute,
});

function ActionStatusRoute() {
  const { deviceId, actionId } = Route.useParams();
  useDeviceBreadcrumbTitle(deviceId);
  return (
    <DeviceActionStatusPage
      key={`${deviceId}:${actionId}`}
      deviceId={deviceId}
      actionId={actionId}
    />
  );
}
