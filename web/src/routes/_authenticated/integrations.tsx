import { createFileRoute } from "@tanstack/react-router";
import { IntegrationsView } from "@/features/integrations/view";
import { canPermission } from "@/lib/permissions";

export const Route = createFileRoute("/_authenticated/integrations")({
  beforeLoad: ({ context }) => {
    if (!canPermission(context.principal, "integrations.manage", true)) {
      throw new Error("You do not have unrestricted integration-management permission.");
    }
  },
  component: IntegrationsView,
});
