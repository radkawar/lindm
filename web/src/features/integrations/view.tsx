import { PageHeader } from "@/components/ui/page-header";
import { Destinations } from "./destinations";
import { Deliveries } from "./deliveries";
import { Reports } from "./reports";

export function IntegrationsView() {
  return (
    <div className="grid min-w-0 gap-8">
      <PageHeader
        title="Integrations and reports"
        description="Manage event export, delivery failures and stored reports. Requires unrestricted integrations.manage permission and configured control-plane integration workers."
      />
      <Destinations />
      <Deliveries />
      <Reports />
    </div>
  );
}
