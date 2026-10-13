import { createFileRoute } from "@tanstack/react-router";
import { RestrictedPage } from "@/components/layout/restricted-page";
import { MCPAccessView } from "@/features/auth/mcp-access";
import { canPermission } from "@/lib/permissions";

export const Route = createFileRoute("/_authenticated/settings_/assistant-access")({
  component: AssistantAccessRoute,
});

function AssistantAccessRoute() {
  const { principal } = Route.useRouteContext();
  if (!canPermission(principal, "integrations.manage", true))
    return (
      <RestrictedPage
        title="Assistant access"
        restriction="Assistant access requires permission"
        reason="Assistant settings affect the whole server. You need integration management without a device scope."
      />
    );
  return <MCPAccessView />;
}
