import { createFileRoute } from "@tanstack/react-router";
import { useProfileHeadLabel, useTargetRefLabel } from "@/app/target-names";
import { RolloutsView } from "@/features/targeting/rollouts";
import { canPermission } from "@/lib/permissions";
import { DevicePicker } from "@/features/devices/picker";
import { GroupPicker } from "@/features/groups/picker";
import { ProfileRevisionPicker } from "@/features/profiles/picker";
import { TargetPickerProvider } from "@/features/targeting/pickers";
import { canonicalUuid } from "@/lib/ids";

export const Route = createFileRoute("/_authenticated/rollouts")({
  // ?create=true opens the New rollout form.
  validateSearch: (search: Record<string, unknown>): { device?: string; create?: true } => {
    const create = search.create === true ? { create: true as const } : {};
    if (search.device === undefined) return create;
    const device = typeof search.device === "string" ? canonicalUuid(search.device) : null;
    if (!device) throw new Error("Choose a valid device from the device list.");
    return { device, ...create };
  },
  beforeLoad: ({ context }) => {
    if (!canPermission(context.principal, "resources.assign"))
      throw new Error("You do not have rollout-management permission.");
  },
  component: RolloutsPage,
});

function RolloutsPage() {
  const { device, create } = Route.useSearch();
  const navigate = Route.useNavigate();
  return (
    <TargetPickerProvider
      pickers={{
        devicePicker: DevicePicker,
        groupPicker: GroupPicker,
        profileRevisionPicker: ProfileRevisionPicker,
      }}
      names={{ useTargetLabel: useTargetRefLabel, useProfileVersionLabel: useProfileHeadLabel }}
    >
      <RolloutsView
        initialDevice={device}
        creating={create === true}
        onCreatingChange={(next) =>
          void navigate({
            search: (previous) => ({ device: previous.device, ...(next ? { create: true } : {}) }),
            replace: true,
          })
        }
      />
    </TargetPickerProvider>
  );
}
