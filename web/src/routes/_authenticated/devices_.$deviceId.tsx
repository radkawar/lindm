import { createFileRoute } from "@tanstack/react-router";
import { DeviceDetailView } from "@/features/devices/detail";
import { deviceQueryOptions } from "@/features/devices/queries";
import { parsePackageSearch } from "@/features/devices/package-search";
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
    />
  );
}
