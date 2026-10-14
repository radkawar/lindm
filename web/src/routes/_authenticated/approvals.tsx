// SPDX-License-Identifier: Apache-2.0

import { createFileRoute } from "@tanstack/react-router";
import { useProfileHeadLabel, useTargetRefLabel } from "@/app/target-names";
import { ApprovalsView } from "@/features/approvals/view";

export const Route = createFileRoute("/_authenticated/approvals")({
  component: ApprovalsPage,
});

function ApprovalsPage() {
  return (
    <ApprovalsView
      rolloutNames={{
        useTargetLabel: useTargetRefLabel,
        useProfileVersionLabel: useProfileHeadLabel,
      }}
    />
  );
}
