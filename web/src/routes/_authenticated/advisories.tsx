import { createFileRoute } from "@tanstack/react-router";
import { AdvisoryFleet } from "@/features/advisories/fleet";
import {
  advisoryFeedsQueryOptions,
  advisorySummaryQueryOptions,
} from "@/features/advisories/queries";
import { getAuthLifetime } from "@/lib/auth-lifetime";
import { canPermission } from "@/lib/permissions";

export const Route = createFileRoute("/_authenticated/advisories")({
  loader: ({ context }) => {
    const lifetime = getAuthLifetime();
    if (lifetime)
      return Promise.all([
        context.queryClient.prefetchQuery(advisorySummaryQueryOptions(lifetime, "")),
        // Sources are fleet-wide; a device-scoped reader is never shown them.
        canPermission(context.principal, "fleet.read", true)
          ? context.queryClient.prefetchQuery(advisoryFeedsQueryOptions(lifetime))
          : undefined,
      ]);
  },
  component: AdvisoryFleet,
});
