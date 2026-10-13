import { useIsFetching, useQueryClient } from "@tanstack/react-query";
import { PageHeader } from "@/components/ui/page-header";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
import { Destinations } from "./destinations";
import { Deliveries } from "./deliveries";
import { Reports } from "./reports";

export function IntegrationsView() {
  const lifetime = useAuthLifetime();
  const client = useQueryClient();
  const queryKey = ["integrations", lifetime.generation];
  const fetching = useIsFetching({ queryKey }) > 0;
  return (
    <div className="grid min-w-0 gap-8">
      <PageHeader
        title="Integrations and reports"
        description="Send audit events to other systems. Retry failed deliveries. Download reports."
        onRefresh={() => void client.invalidateQueries({ queryKey })}
        refreshing={fetching}
      />
      <Destinations />
      <Deliveries />
      <Reports />
    </div>
  );
}
