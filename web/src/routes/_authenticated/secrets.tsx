import { createFileRoute } from "@tanstack/react-router";
import { SecretsView } from "@/features/secrets/view";
import { secretsQueryOptions } from "@/features/secrets/queries";
import { parseListSearch } from "@/lib/list-search";
import { getAuthLifetime } from "@/lib/auth-lifetime";

export const Route = createFileRoute("/_authenticated/secrets")({
  validateSearch: parseListSearch,
  loaderDeps: ({ search }) => search,
  loader: ({ context, deps }) => {
    const lifetime = getAuthLifetime();
    if (lifetime)
      return context.queryClient.prefetchQuery(
        secretsQueryOptions(lifetime, deps.pageSize, deps.pageToken),
      );
  },
  component: SecretsRoute,
});

function SecretsRoute() {
  const search = Route.useSearch();
  const navigate = Route.useNavigate();
  return (
    <SecretsView
      pageSize={search.pageSize}
      pageToken={search.pageToken}
      onSearch={(next) => void navigate({ search: next })}
      onCreated={(secretId) => void navigate({ to: "/secrets/$secretId", params: { secretId } })}
    />
  );
}
