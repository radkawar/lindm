import { createFileRoute } from "@tanstack/react-router";
import { DeviceFindings } from "@/features/advisories/device-findings";
import { DeviceAssistanceCard } from "@/features/assistance/panel";
import { AccountPicker } from "@/features/auth/picker";
import { DeviceActionHistory } from "@/features/devices/actions";
import { DeviceDetailView } from "@/features/devices/detail";
import { deviceQueryOptions } from "@/features/devices/queries";
import { parsePackageSearch } from "@/features/devices/package-search";
import { DeviceResourceComplianceBadge, DeviceResources } from "@/features/services/view";
import { ResourceAssignmentDialog } from "@/features/services/assignment-form";
import { RevokeApprovalRequest } from "@/features/approvals/revoke";
import { Button } from "@/components/ui/button";
import { Plus } from "lucide-react";
import { getAuthLifetime } from "@/lib/auth-lifetime";
import { canonicalUuid } from "@/lib/ids";

export const Route = createFileRoute("/_authenticated/devices_/$deviceId")({
  validateSearch: parsePackageSearch,
  params: {
    parse: ({ deviceId }) => {
      const canonical = canonicalUuid(deviceId);
      if (canonical === null || canonical === "00000000-0000-0000-0000-000000000000") {
        throw new Error("The device URL must contain a valid device ID.");
      }
      return { deviceId: canonical };
    },
  },
  loader: ({ context, params }) => {
    const lifetime = getAuthLifetime();
    if (lifetime)
      return context.queryClient.prefetchQuery(deviceQueryOptions(lifetime, params.deviceId));
  },
  component: DeviceDetailRoute,
});

function DeviceDetailRoute() {
  const { deviceId } = Route.useParams();
  const search = Route.useSearch();
  const navigate = Route.useNavigate();
  return (
    <DeviceDetailView
      key={deviceId}
      deviceId={deviceId}
      search={search}
      onSearch={(next, replace = false) => void navigate({ search: next, replace })}
      compliance={<DeviceResourceComplianceBadge deviceId={deviceId} />}
      resources={(assignProfile) => (
        <DeviceResources
          deviceId={deviceId}
          emptyAction={
            <Button aria-haspopup="dialog" onClick={assignProfile}>
              <Plus aria-hidden="true" /> Assign profile
            </Button>
          }
        />
      )}
      assignDialog={(open, onOpenChange) => (
        <ResourceAssignmentDialog deviceId={deviceId} open={open} onOpenChange={onOpenChange} />
      )}
      findings={<DeviceFindings deviceId={deviceId} />}
      history={<DeviceActionHistory deviceId={deviceId} />}
      revoke={(device) => <RevokeApprovalRequest deviceId={device.id} />}
      assistance={<DeviceAssistanceCard deviceId={deviceId} />}
      accountPicker={(props) => <AccountPicker {...props} />}
    />
  );
}
