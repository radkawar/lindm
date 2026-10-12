import { createFileRoute } from "@tanstack/react-router";
import { RestrictedPage } from "@/components/layout/restricted-page";
import { PageHeader } from "@/components/ui/page-header";
import { AttributeDefinitions } from "@/features/devices/definitions";
import { RepositoryReadinessSection } from "@/features/enrollment/repository-readiness";
import { canPermission } from "@/lib/permissions";

export const Route = createFileRoute("/_authenticated/settings")({
  component: SettingsRoute,
});

function SettingsRoute() {
  const { principal } = Route.useRouteContext();
  const enrollment = canPermission(principal, "enrollment.manage", true);
  if (!enrollment && !canPermission(principal, "inventory.manage", true))
    return (
      <RestrictedPage
        title="Settings"
        restriction="Settings are restricted"
        reason="Server enrollment readiness and device attributes apply to the whole fleet, so they need enrollment or inventory management without a device scope."
      />
    );
  return (
    <div className="grid min-w-0 gap-6">
      <PageHeader
        title="Settings"
        description="Check whether this server can enroll devices, and define the attributes devices carry."
      />
      {enrollment ? <RepositoryReadinessSection /> : null}
      <AttributeDefinitions />
    </div>
  );
}
