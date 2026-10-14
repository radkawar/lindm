// SPDX-License-Identifier: Apache-2.0

import { useIsFetching, useQueryClient } from "@tanstack/react-query";
import { createFileRoute } from "@tanstack/react-router";
import { RestrictedPage } from "@/components/layout/restricted-page";
import { PageHeader } from "@/components/ui/page-header";
import { MCPAccessSettingsSection } from "@/features/auth/mcp-access";
import { DeviceCapabilitiesSettingsSection } from "@/features/capabilities/view";
import { AttributeDefinitions } from "@/features/devices/definitions";
import { RepositoryReadinessSection } from "@/features/enrollment/repository-readiness";
import { canPermission } from "@/lib/permissions";

export const Route = createFileRoute("/_authenticated/settings")({
  component: SettingsRoute,
});

function SettingsRoute() {
  const { principal } = Route.useRouteContext();
  const queryClient = useQueryClient();
  const fetching = useIsFetching();
  const enrollment = canPermission(principal, "enrollment.manage", true);
  const integrations = canPermission(principal, "integrations.manage", true);
  if (
    !enrollment &&
    !integrations &&
    !canPermission(principal, "inventory.manage", true) &&
    !canPermission(principal, "execution_trust.manage", true)
  )
    return (
      <RestrictedPage
        title="Settings"
        restriction="Settings require permission"
        reason="These settings affect the whole fleet. They require enrollment, inventory, signing-key or integration management permission without device limits."
      />
    );
  return (
    <div className="grid min-w-0 gap-6">
      <PageHeader
        title="Settings"
        description="Check enrollment readiness. Set device attributes and agent permissions. Review assistant access."
        onRefresh={() => void queryClient.refetchQueries({ type: "active" })}
        refreshing={fetching > 0}
      />
      {integrations ? <MCPAccessSettingsSection /> : null}
      {enrollment ? <RepositoryReadinessSection /> : null}
      <AttributeDefinitions />
      <DeviceCapabilitiesSettingsSection />
    </div>
  );
}
