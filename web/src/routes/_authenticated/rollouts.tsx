import { useQuery } from "@tanstack/react-query";
import { createFileRoute } from "@tanstack/react-router";
import { RolloutsView } from "@/features/targeting/rollouts";
import { canPermission } from "@/lib/permissions";
import { DevicePicker } from "@/features/devices/picker";
import { deviceQueryOptions } from "@/features/devices/queries";
import { GroupPicker } from "@/features/groups/picker";
import { groupsQueryOptions } from "@/features/groups/view";
import { ProfileRevisionPicker, ProfileVersionName } from "@/features/profiles/picker";
import { TargetPickerProvider } from "@/features/targeting/pickers";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
import { canonicalUuid } from "@/lib/ids";

export const Route = createFileRoute("/_authenticated/rollouts")({
  validateSearch: (search: Record<string, unknown>): { device?: string } => {
    if (search.device === undefined) return {};
    const device = typeof search.device === "string" ? canonicalUuid(search.device) : null;
    if (!device) throw new Error("Choose a valid device from the device list.");
    return { device };
  },
  beforeLoad: ({ context }) => {
    if (!canPermission(context.principal, "resources.assign"))
      throw new Error("Resource rollout management is not authorized.");
  },
  component: RolloutsPage,
});

function DeviceName({ value }: { value: string }) {
  const query = useQuery(deviceQueryOptions(useAuthLifetime(), value));
  if (query.data?.device) return <>{query.data.device.hostname.trim() || "Unnamed device"}</>;
  if (query.isPending) return <>(loading name…)</>;
  return <>(name unavailable)</>;
}

function GroupName({ value }: { value: string }) {
  const query = useQuery(groupsQueryOptions(useAuthLifetime(), ""));
  const group = query.data?.groups.find((item) => item.id === value);
  if (group) return <>{group.name || "(unnamed)"}</>;
  if (query.isPending) return <>(loading name…)</>;
  if (query.error) return <>(name unavailable)</>;
  return <>(not among the first 50 device groups)</>;
}

function RolloutsPage() {
  const { device } = Route.useSearch();
  return (
    <TargetPickerProvider
      pickers={{
        devicePicker: DevicePicker,
        groupPicker: GroupPicker,
        profileRevisionPicker: ProfileRevisionPicker,
      }}
    >
      <RolloutsView
        initialDevice={device}
        names={{
          deviceName: DeviceName,
          groupName: GroupName,
          profileVersionName: ProfileVersionName,
        }}
      />
    </TargetPickerProvider>
  );
}
