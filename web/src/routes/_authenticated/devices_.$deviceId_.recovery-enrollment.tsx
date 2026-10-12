import { createFileRoute } from "@tanstack/react-router";
import { useDeviceBreadcrumbTitle } from "@/features/devices/breadcrumb";
import { DeviceActionPage } from "@/features/devices/action-pages";
import { RecoveryEnrollment } from "@/features/enrollment/recovery";
import { canonicalUuid } from "@/lib/ids";

export const Route = createFileRoute("/_authenticated/devices_/$deviceId_/recovery-enrollment")({
  params: {
    parse: ({ deviceId }) => {
      const id = canonicalUuid(deviceId);
      if (!id || id === "00000000-0000-0000-0000-000000000000")
        throw new Error("The device URL must contain a valid device ID.");
      return { deviceId: id };
    },
  },
  component: RecoveryEnrollmentRoute,
});

function RecoveryEnrollmentRoute() {
  const { deviceId } = Route.useParams();
  useDeviceBreadcrumbTitle(deviceId);
  return (
    <DeviceActionPage deviceId={deviceId} title="Recover device enrollment">
      {(device) => (
        <RecoveryEnrollment
          key={`${device.id}:${device.enrollmentGeneration}:${device.lifecycleState}`}
          device={device}
        />
      )}
    </DeviceActionPage>
  );
}
