// SPDX-License-Identifier: Apache-2.0

import { createFileRoute } from "@tanstack/react-router";
import { RestrictedPage } from "@/components/layout/restricted-page";
import { ServerStatusPage } from "@/features/server-status/view";
import { canPermission } from "@/lib/permissions";

export const Route = createFileRoute("/_authenticated/settings_/status")({
  component: StatusRoute,
});

function StatusRoute() {
  const { principal } = Route.useRouteContext();
  if (!canPermission(principal, "integrations.manage", true)) {
    return (
      <RestrictedPage
        title="Server status"
        restriction="Server status is restricted"
        reason="Server checks require integration management without a device scope."
      />
    );
  }
  return (
    <ServerStatusPage canReviewInstallation={canPermission(principal, "enrollment.manage", true)} />
  );
}
