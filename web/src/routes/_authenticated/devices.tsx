// SPDX-License-Identifier: Apache-2.0

import { createFileRoute, useRouter } from "@tanstack/react-router";
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
  const router = useRouter();
  return (
    <DevicesView
      key={`${search.filter ?? ""}:${search.pageSize}`}
      search={search}
      onSearch={(next, replace = false) => {
        // A replacing write only records the list's page token after a response.
        // If the administrator has already opened a device, it must not pull
        // them back to the list.
        if (replace && router.state.location.pathname !== Route.fullPath) return;
        void navigate({ search: next, replace });
      }}
      renderRevoke={(device) => <RevokeApprovalRequest deviceId={device.id} />}
    />
  );
}
