import { createFileRoute } from "@tanstack/react-router";
import { GroupsView } from "@/features/groups/view";
import { DynamicGroupsView } from "@/features/targeting/groups";
import { usePrincipal } from "@/hooks/use-permissions";
import { canPermission } from "@/lib/permissions";
import { DevicePicker } from "@/features/devices/picker";
import { GroupPicker } from "@/features/groups/picker";
import { ProfileRevisionPicker } from "@/features/profiles/picker";
import { TargetPickerProvider } from "@/features/targeting/pickers";

export const Route = createFileRoute("/_authenticated/groups")({
  beforeLoad: ({ context }) => {
    if (
      !canPermission(context.principal, "accounts.manage", true) &&
      !canPermission(context.principal, "inventory.manage", true)
    )
      throw new Error("Group management is not authorized.");
  },
  component: GroupsPage,
});

function GroupsPage() {
  const principal = usePrincipal();
  return (
    <div className="grid min-w-0 gap-8">
      {canPermission(principal, "accounts.manage", true) ? (
        <GroupsView devicePicker={DevicePicker} />
      ) : null}
      {canPermission(principal, "inventory.manage", true) ? (
        <TargetPickerProvider
          pickers={{
            devicePicker: DevicePicker,
            groupPicker: GroupPicker,
            profileRevisionPicker: ProfileRevisionPicker,
          }}
        >
          <DynamicGroupsView />
        </TargetPickerProvider>
      ) : null}
    </div>
  );
}
