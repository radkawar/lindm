import type { Device } from "../../../gen/lindm/admin/v1/admin_pb";

// Operating system as administrators name it (registry display name); the
// reported os-release identity when the release is not registered. Empty when
// never reported.
export function deviceOsLabel(device: Pick<Device, "osId" | "osVersion" | "osName">): string {
  return (
    device.osName || [device.osId, device.osVersion].filter((part) => part.trim() !== "").join(" ")
  );
}
