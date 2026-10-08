import { createFileRoute } from "@tanstack/react-router";
import { AuditView } from "@/features/audit/view";
import { auditQueryOptions } from "@/features/audit/queries";
import { parseListSearch } from "@/lib/list-search";
import { getAuthLifetime } from "@/lib/auth-lifetime";

export const Route = createFileRoute("/_authenticated/audit")({
  validateSearch: parseListSearch,
  loaderDeps: ({ search }) => search,
  loader: ({ context, deps }) => {
    const lifetime = getAuthLifetime();
    if (lifetime)
      return context.queryClient.prefetchQuery(
        auditQueryOptions(lifetime, deps.pageSize, deps.pageToken),
      );
  },
  component: AuditRoute,
});

function AuditRoute() {
  const search = Route.useSearch();
  const navigate = Route.useNavigate();
  return (
    <AuditView
      pageSize={search.pageSize}
      pageToken={search.pageToken}
      onSearch={(next) => void navigate({ search: next })}
    />
  );
}
