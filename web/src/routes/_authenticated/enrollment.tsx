import { createFileRoute } from "@tanstack/react-router";
import { EnrollmentView } from "@/features/enrollment/view";
import { canPermission } from "@/lib/permissions";

export const Route = createFileRoute("/_authenticated/enrollment")({
  beforeLoad: ({ context }) => {
    if (!canPermission(context.principal, "enrollment.manage"))
      throw new Error("Enrollment management is not authorized.");
  },
  component: EnrollmentView,
});
