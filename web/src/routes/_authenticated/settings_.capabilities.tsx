import { useQuery } from "@tanstack/react-query";
import { createFileRoute } from "@tanstack/react-router";
import type { CapabilityPolicyScope } from "../../../gen/lindm/admin/v1/capabilities_pb";
import { RestrictedPage } from "@/components/layout/restricted-page";
import { DeviceCapabilitiesView } from "@/features/capabilities/view";
import { fleetSummaryQueryOptions } from "@/features/dashboard/queries";
import { GroupPicker } from "@/features/groups/picker";
import { deviceGroupQueryOptions } from "@/features/groups/view";
import { DynamicGroupPicker } from "@/features/targeting/pickers";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
import { canPermission } from "@/lib/permissions";

export const Route = createFileRoute("/_authenticated/settings_/capabilities")({
  component: DeviceCapabilitiesRoute,
});

function DeviceCapabilitiesRoute() {
  const { principal } = Route.useRouteContext();
  if (!canPermission(principal, "fleet.read", true))
    return (
      <RestrictedPage
        title="Device capabilities"
        restriction="Device capabilities are restricted"
        reason="Capability policies apply across the fleet, so viewing them needs device access without a device scope."
      />
    );
  return (
    <DeviceCapabilitiesView
      groupPicker={GroupPicker}
      dynamicGroupPicker={DynamicGroupPicker}
      scopeDevices={ScopeDevices}
    />
  );
}

// The blast radius of a capability change: active devices for all devices,
// current members for a device group. A dynamic group's matches are evaluated
// at check-in, so they are not counted here.
function ScopeDevices({ scope }: { scope: CapabilityPolicyScope | undefined }) {
  const lifetime = useAuthLifetime();
  const kind = scope?.scope.case;
  const fleet = useQuery({ ...fleetSummaryQueryOptions(lifetime), enabled: kind === "deployment" });
  const groupId = kind === "staticGroupId" ? String(scope?.scope.value) : "";
  const group = useQuery({ ...deviceGroupQueryOptions(lifetime, groupId), enabled: !!groupId });
  const active = fleet.data?.lifecycle?.activeDevices;
  const count =
    kind === "deployment"
      ? active === undefined
        ? undefined
        : Number(active)
      : group.data?.deviceIds.length;
  if (count === undefined) return null;
  return <>{` (${count} ${count === 1 ? "device" : "devices"} now)`}</>;
}
