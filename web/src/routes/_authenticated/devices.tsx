import { createFileRoute } from "@tanstack/react-router";
import { DevicesView } from "@/features/devices/view";
import { parseDeviceSearch } from "@/features/devices/search";
import { RevokeApprovalRequest } from "@/features/approvals/revoke";
import { devicesQueryOptions } from "@/features/devices/queries";
import { getAuthLifetime } from "@/lib/auth-lifetime";

export const Route = createFileRoute("/_authenticated/devices")({
  validateSearch: parseDeviceSearch,
  loaderDeps: ({ search }) => search,
  loader: ({ context, deps }) => {
    const lifetime = getAuthLifetime();
    if (lifetime) return context.queryClient.prefetchQuery(devicesQueryOptions(lifetime, deps));
  },
  component: DevicesRoute,
});

function DevicesRoute() {
  const search = Route.useSearch();
  const navigate = Route.useNavigate();
  return (
    <DevicesView
      key={`${search.filter ?? ""}:${search.pageSize}`}
      search={search}
      onSearch={(next, replace = false) => void navigate({ search: next, replace })}
      renderRevoke={(device) => <RevokeApprovalRequest deviceId={device.id} />}
    />
  );
}
