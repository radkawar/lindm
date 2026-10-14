// SPDX-License-Identifier: Apache-2.0

import { useIsFetching, useQueryClient } from "@tanstack/react-query";
import { createFileRoute } from "@tanstack/react-router";
import { GroupsView } from "@/features/groups/view";
import { DynamicGroupsView } from "@/features/targeting/groups";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
import { usePrincipal } from "@/hooks/use-permissions";
import { canPermission } from "@/lib/permissions";
import { DeviceLabel } from "@/features/devices/device-label";
import { DevicePicker } from "@/features/devices/picker";
import { GroupName, GroupPicker } from "@/features/groups/picker";
import { ProfileRevisionPicker } from "@/features/profiles/picker";
import { TargetPickerProvider } from "@/features/targeting/pickers";
import { PageHeader } from "@/components/ui/page-header";

export const Route = createFileRoute("/_authenticated/groups")({
  // ?create=true opens the new device group dialog (for example from the command palette).
  validateSearch: (search: Record<string, unknown>): { create?: true } =>
    search.create === true || search.create === "true" ? { create: true } : {},
  beforeLoad: ({ context }) => {
    if (
      !canPermission(context.principal, "accounts.manage", true) &&
      !canPermission(context.principal, "inventory.manage", true)
    )
      throw new Error("You do not have group-management permission.");
  },
  component: GroupsPage,
});

function GroupsPage() {
  const principal = usePrincipal();
  const lifetime = useAuthLifetime();
  const client = useQueryClient();
  const deviceGroups = ["device-groups", lifetime.generation];
  const dynamicGroups = ["targeting", lifetime.generation, "groups"];
  const fetching =
    useIsFetching({ queryKey: deviceGroups }) + useIsFetching({ queryKey: dynamicGroups });
  const { create } = Route.useSearch();
  const navigate = Route.useNavigate();
  return (
    <div className="grid min-w-0 gap-8">
      <PageHeader
        title="Groups"
        refreshing={fetching > 0}
        onRefresh={() =>
          void Promise.all([
            client.invalidateQueries({ queryKey: deviceGroups }),
            client.invalidateQueries({ queryKey: dynamicGroups }),
          ])
        }
      />
      {canPermission(principal, "accounts.manage", true) ? (
        <GroupsView
          devicePicker={DevicePicker}
          deviceLabel={DeviceLabel}
          creating={create === true}
          onCreatingChange={(next) =>
            void navigate({ search: next ? { create: true } : {}, replace: true })
          }
        />
      ) : null}
      {canPermission(principal, "inventory.manage", true) ? (
        <TargetPickerProvider
          pickers={{
            devicePicker: DevicePicker,
            groupPicker: GroupPicker,
            profileRevisionPicker: ProfileRevisionPicker,
          }}
        >
          <DynamicGroupsView groupName={GroupName} />
        </TargetPickerProvider>
      ) : null}
    </div>
  );
}
