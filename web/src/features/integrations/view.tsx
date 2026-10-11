import { PageHeader } from "@/components/ui/page-header";
import { Destinations } from "./destinations";
import { Deliveries } from "./deliveries";
import { Reports } from "./reports";

export function IntegrationsView() {
  return (
    <div className="grid min-w-0 gap-8">
      <PageHeader
        title="Integrations and reports"
        description="Send events to other systems, retry failed deliveries and download reports."
      />
      <Destinations />
      <Deliveries />
      <Reports />
    </div>
  );
}
