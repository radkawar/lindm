import { Destinations } from "./destinations";
import { Deliveries } from "./deliveries";
import { Reports } from "./reports";

export function IntegrationsView() {
  return (
    <div className="grid min-w-0 gap-8">
      <header className="space-y-2">
        <h1 className="text-2xl font-semibold tracking-tight">Integrations and reports</h1>
        <p className="max-w-3xl text-sm text-muted-foreground">
          Manage authenticated event export, visible delivery failures and durable reports. Requires
          unrestricted integrations.manage authority and integration workers configured on the
          control plane.
        </p>
      </header>
      <Destinations />
      <Deliveries />
      <Reports />
    </div>
  );
}
