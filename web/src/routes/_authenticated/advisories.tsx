import { createFileRoute } from "@tanstack/react-router";
import { AdvisoryFleet } from "@/features/advisories/fleet";
import {
  advisoryFeedsQueryOptions,
  advisorySummaryQueryOptions,
} from "@/features/advisories/queries";
import { getAuthLifetime } from "@/lib/auth-lifetime";

export const Route = createFileRoute("/_authenticated/advisories")({
  loader: ({ context }) => {
    const lifetime = getAuthLifetime();
    if (lifetime)
      return Promise.all([
        context.queryClient.prefetchQuery(advisorySummaryQueryOptions(lifetime, "")),
        context.queryClient.prefetchQuery(advisoryFeedsQueryOptions(lifetime)),
      ]);
  },
  component: AdvisoryFleet,
});
