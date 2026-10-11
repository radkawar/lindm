import { createFileRoute } from "@tanstack/react-router";
import { RepositoryReadinessView } from "@/features/enrollment/repository-readiness";
import { canPermission } from "@/lib/permissions";

export const Route = createFileRoute("/_authenticated/settings")({
  beforeLoad: ({ context }) => {
    if (!canPermission(context.principal, "enrollment.manage"))
      throw new Error("Enrollment management is not authorized.");
  },
  component: RepositoryReadinessView,
});
