import { createFileRoute } from "@tanstack/react-router";
import { ProfilesView } from "@/features/profiles/view";
import { profilesQueryOptions } from "@/features/profiles/queries";
import { parseProfileListSearch } from "@/features/profiles/search";
import { getAuthLifetime } from "@/lib/auth-lifetime";

export const Route = createFileRoute("/_authenticated/profiles")({
  validateSearch: parseProfileListSearch,
  loaderDeps: ({ search }) => search,
  loader: ({ context, deps }) => {
    const lifetime = getAuthLifetime();
    if (lifetime)
      return context.queryClient.prefetchQuery(
        profilesQueryOptions(lifetime, deps.pageSize, deps.pageToken),
      );
  },
  component: ProfilesRoute,
});

function ProfilesRoute() {
  const search = Route.useSearch();
  const navigate = Route.useNavigate();
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
