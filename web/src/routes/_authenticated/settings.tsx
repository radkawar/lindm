import { createFileRoute } from "@tanstack/react-router";
import { PageHeader } from "@/components/ui/page-header";
import { AttributeDefinitions } from "@/features/devices/definitions";
import { RepositoryReadinessSection } from "@/features/enrollment/repository-readiness";
import { usePrincipal } from "@/hooks/use-permissions";
import { canPermission } from "@/lib/permissions";

export const Route = createFileRoute("/_authenticated/settings")({
  beforeLoad: ({ context }) => {
    if (
      !canPermission(context.principal, "enrollment.manage") &&
      !canPermission(context.principal, "inventory.manage", true)
    )
      throw new Error("Settings require enrollment or inventory management.");
  },
  component: SettingsRoute,
});

function SettingsRoute() {
  const principal = usePrincipal();
  return (
    <div className="grid min-w-0 gap-6">
      <PageHeader
        title="Settings"
        description="Check whether this server can enroll devices, and define the attributes devices carry."
      />
      {canPermission(principal, "enrollment.manage") ? <RepositoryReadinessSection /> : null}
      <AttributeDefinitions />
    </div>
  );
}
