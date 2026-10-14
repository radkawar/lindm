// SPDX-License-Identifier: Apache-2.0

import { createFileRoute } from "@tanstack/react-router";
import { RestrictedPage } from "@/components/layout/restricted-page";
import { ProfilesView } from "@/features/profiles/view";
import { profilesQueryOptions } from "@/features/profiles/queries";
import { parseProfileListSearch } from "@/features/profiles/search";
import { getAuthLifetime } from "@/lib/auth-lifetime";
import { canPermission } from "@/lib/permissions";

export const Route = createFileRoute("/_authenticated/profiles")({
  validateSearch: parseProfileListSearch,
  loaderDeps: ({ search }) => search,
  loader: ({ context, deps }) => {
    const lifetime = getAuthLifetime();
    if (lifetime && canPermission(context.principal, "fleet.read", true))
      return context.queryClient.prefetchQuery(
        profilesQueryOptions(lifetime, deps.pageSize, deps.pageToken),
      );
  },
  component: ProfilesRoute,
});

function ProfilesRoute() {
  const { principal } = Route.useRouteContext();
  const search = Route.useSearch();
  const navigate = Route.useNavigate();
  if (!canPermission(principal, "fleet.read", true))
    return (
      <RestrictedPage
        title="Profiles"
        restriction="The profile catalog requires permission"
        reason="Profiles apply across the whole fleet, so the catalog needs fleet access without a device scope. A device's Services tab shows the profiles assigned to it."
      />
    );
  return (
    <ProfilesView
      pageSize={search.pageSize}
      pageToken={search.pageToken}
      onSearch={(next) =>
        void navigate({
          search: { pageSize: next.pageSize === 100 ? 100 : 50, pageToken: next.pageToken },
        })
      }
    />
  );
}
