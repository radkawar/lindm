// SPDX-License-Identifier: Apache-2.0

import { useIsFetching, useQuery, useQueryClient } from "@tanstack/react-query";
import { Code } from "@connectrpc/connect";
import { EmptyState } from "@/components/ui/empty-state";
import { toRpcFailure } from "@/lib/errors";
import { PageHeader } from "@/components/ui/page-header";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
import { Destinations } from "./destinations";
import { Deliveries } from "./deliveries";
import { Reports } from "./reports";
import { destinationsQueryOptions } from "./queries";

export function IntegrationsView() {
  const lifetime = useAuthLifetime();
  const client = useQueryClient();
  const queryKey = ["integrations", lifetime.generation];
  const fetching = useIsFetching({ queryKey }) > 0;
  const readiness = useQuery({ ...destinationsQueryOptions(lifetime, ""), retry: false });
  const failure = readiness.error ? toRpcFailure(readiness.error) : undefined;
  const unconfigured =
    failure?.code === Code.FailedPrecondition && failure.reason === "integrations_unconfigured";
  return (
    <div className="grid min-w-0 gap-8">
      <PageHeader
        title="Integrations and reports"
        description="Send audit events to other systems. Retry failed deliveries. Download reports."
        onRefresh={() => void client.invalidateQueries({ queryKey })}
        refreshing={fetching}
      />
      {unconfigured ? (
        <EmptyState
          title="Integrations are not set up"
          description="Ask the server administrator to create and back up a protected 32-byte encryption key, set integrations.encryptionKeyFile to its path in the lindmd configuration, then restart lindmd. This enables destinations, deliveries and reports."
        />
      ) : readiness.isPending ? (
        <p role="status" className="text-sm text-muted-foreground">
          Loading integrations…
        </p>
      ) : (
        <>
          <Destinations />
          <Deliveries />
          <Reports />
        </>
      )}
    </div>
  );
}
