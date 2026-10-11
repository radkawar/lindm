import { createFileRoute } from "@tanstack/react-router";
import { RolloutsView } from "@/features/targeting/rollouts";
import { canPermission } from "@/lib/permissions";
import { DevicePicker } from "@/features/devices/picker";
import { GroupPicker } from "@/features/groups/picker";
import { ProfileRevisionPicker } from "@/features/profiles/picker";
import { TargetPickerProvider } from "@/features/targeting/pickers";
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
      <RolloutsView initialDevice={device} />
    </TargetPickerProvider>
  );
}
