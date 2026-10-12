import { createFileRoute, Link, type ErrorComponentProps } from "@tanstack/react-router";
import { Button } from "@/components/ui/button";
import { AuditView } from "@/features/audit/view";
import { auditQueryOptions } from "@/features/audit/queries";
import { parseAuditSearch } from "@/features/audit/search";
import { AuditActorPicker, AuditDevicePicker } from "@/features/audit/pickers";
import { getAuthLifetime } from "@/lib/auth-lifetime";
import { RestrictedPage } from "@/components/layout/restricted-page";
import { canPermission } from "@/lib/permissions";

export const Route = createFileRoute("/_authenticated/audit")({
  validateSearch: parseAuditSearch,
  loaderDeps: ({ search }) => search,
  loader: ({ context, deps }) => {
    const lifetime = getAuthLifetime();
    if (lifetime && canPermission(context.principal, "audit.read", true))
      return context.queryClient.prefetchQuery(auditQueryOptions(lifetime, deps));
  },
  component: AuditRoute,
  errorComponent: AuditRouteError,
});

function AuditRoute() {
  const { principal } = Route.useRouteContext();
  const search = Route.useSearch();
  const navigate = Route.useNavigate();
  if (!canPermission(principal, "audit.read", true))
    return (
      <RestrictedPage
        title="Audit log"
        restriction="The audit log is restricted"
        reason="The audit log records actions across the whole fleet, so it needs audit permission without a device scope."
      />
    );
  return (
    <AuditView
      search={search}
      accountPicker={AuditActorPicker}
      devicePicker={AuditDevicePicker}
      onSearch={(next) => void navigate({ search: next })}
    />
  );
}

function AuditRouteError({ error }: ErrorComponentProps) {
  const cause = error instanceof Error && error.cause instanceof Error ? error.cause : error;
  return (
    <section className="mx-auto flex max-w-xl flex-col gap-4 p-6">
      <h1 className="text-2xl font-semibold">Unable to open the audit log</h1>
      <p role="alert">
        {cause instanceof Error ? cause.message : "The audit log could not be loaded."}
      </p>
      <p>
        Resetting clears this link's filters and shows the human actions you are authorized to read.
      </p>
      <Button className="w-fit" render={<Link to="/audit" search={{}} replace />}>
        Reset audit filters
      </Button>
    </section>
  );
}
