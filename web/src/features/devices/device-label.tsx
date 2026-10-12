import { useQuery } from "@tanstack/react-query";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
import { deviceQueryOptions } from "./queries";

// Read-only hostname and reported operating system for a chosen device ID, for
// chips and member lists composed by other features. A failed read names that
// state; it never falls back to showing the ID.
export function DeviceLabel({ value }: { value: string }) {
  const query = useQuery(deviceQueryOptions(useAuthLifetime(), value));
  const device = query.data?.device;
  if (device) {
    const os = [device.osId, device.osVersion].filter(Boolean).join(" ");
    return (
      <>
        <span className="break-words">{device.hostname.trim() || "Unnamed device"}</span>
        {os ? <span className="text-muted-foreground"> · {os}</span> : null}
      </>
    );
  }
  if (query.isPending) return <span className="text-muted-foreground">Loading device…</span>;
  return <span className="text-muted-foreground">Device unavailable</span>;
}
