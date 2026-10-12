import { createFileRoute, type SearchSchemaInput } from "@tanstack/react-router";
import { SecretsView } from "@/features/secrets/view";
import { secretsQueryOptions } from "@/features/secrets/queries";
import { parseListSearch, type ListSearch } from "@/lib/list-search";
import { getAuthLifetime } from "@/lib/auth-lifetime";

// `create` opens the Create secret dialog, e.g. from the command palette.
export const Route = createFileRoute("/_authenticated/secrets")({
  validateSearch: (
    search: Partial<ListSearch & { create: boolean }> & SearchSchemaInput,
  ): ListSearch & { create?: true } => ({
    ...parseListSearch(search),
    ...(search.create === true ? { create: true } : {}),
  }),
  loaderDeps: ({ search }) => ({ pageSize: search.pageSize, pageToken: search.pageToken }),
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
      creating={search.create === true}
      onCreatingChange={(creating) =>
        void navigate({
          search: (previous) => ({
            pageSize: previous.pageSize,
            pageToken: previous.pageToken,
            ...(creating ? { create: true as const } : {}),
          }),
          replace: true,
        })
      }
    />
  );
}
