import { createFileRoute } from "@tanstack/react-router";
import { EnrollmentView } from "@/features/enrollment/view";
import { AccountPicker } from "@/features/auth/picker";
import { GroupPicker } from "@/features/groups/picker";
import { ProfileRevisionPicker } from "@/features/profiles/picker";
import { canPermission } from "@/lib/permissions";

export const Route = createFileRoute("/_authenticated/enrollment")({
  beforeLoad: ({ context }) => {
    if (!canPermission(context.principal, "enrollment.manage"))
      throw new Error("Enrollment management is not authorized.");
  },
  component: EnrollmentPage,
});

function EnrollmentPage() {
  return (
    <EnrollmentView
      accountPicker={AccountPicker}
      groupPicker={GroupPicker}
      profileRevisionPicker={ProfileRevisionPicker}
    />
  );
}
