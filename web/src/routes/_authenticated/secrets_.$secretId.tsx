// SPDX-License-Identifier: Apache-2.0

import { createFileRoute } from "@tanstack/react-router";
import { SecretDetailView } from "@/features/secrets/detail";
import { secretQueryOptions } from "@/features/secrets/queries";
import { getAuthLifetime } from "@/lib/auth-lifetime";
import { canonicalUuid } from "@/lib/ids";

export const Route = createFileRoute("/_authenticated/secrets_/$secretId")({
  params: {
    parse: ({ secretId }) => {
      const canonical = canonicalUuid(secretId);
      if (canonical === null || canonical === "00000000-0000-0000-0000-000000000000") {
        throw new Error("The secret URL must contain a valid secret ID.");
      }
      return { secretId: canonical };
    },
  },
  loader: ({ context, params }) => {
    const lifetime = getAuthLifetime();
    if (lifetime)
      return context.queryClient.prefetchQuery(secretQueryOptions(lifetime, params.secretId));
  },
  component: SecretDetailRoute,
});

function SecretDetailRoute() {
  const { secretId } = Route.useParams();
  return <SecretDetailView key={secretId} secretId={secretId} />;
}
