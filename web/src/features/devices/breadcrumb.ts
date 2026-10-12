import { useQuery } from "@tanstack/react-query";
import { useBreadcrumbTitle } from "@/components/layout/breadcrumb-title";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
import { deviceQueryOptions } from "./queries";

// Names the device in the console breadcrumb from the device read the page already makes.
export function useDeviceBreadcrumbTitle(deviceId: string) {
  const lifetime = useAuthLifetime();
  const device = useQuery({
    ...deviceQueryOptions(lifetime, deviceId),
    select: (response) => response.device,
  });
  useBreadcrumbTitle(device.data ? device.data.hostname.trim() || "Unnamed device" : undefined);
}
