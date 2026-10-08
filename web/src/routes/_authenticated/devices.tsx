import { createFileRoute } from "@tanstack/react-router";
import { DevicesView } from "@/features/devices/view";
import { parseListSearch } from "@/lib/list-search";
import { devicesQueryOptions } from "@/features/devices/queries";
import { getAuthLifetime } from "@/lib/auth-lifetime";

export const Route = createFileRoute("/_authenticated/devices")({
  validateSearch: parseListSearch,
  loaderDeps: ({ search }) => search,
  loader: ({ context, deps }) => {
    const lifetime = getAuthLifetime();
    if (lifetime)
      return context.queryClient.prefetchQuery(
        devicesQueryOptions(lifetime, deps.pageSize, deps.pageToken),
      );
  },
  component: DevicesRoute,
});

function DevicesRoute() {
  const search = Route.useSearch();
  const navigate = Route.useNavigate();
  return (
    <DevicesView
      pageSize={search.pageSize}
      pageToken={search.pageToken}
      onSearch={(next) => void navigate({ search: next })}
    />
  );
}
