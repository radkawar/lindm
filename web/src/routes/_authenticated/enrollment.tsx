import { createFileRoute } from "@tanstack/react-router";
import { EnrollmentView } from "@/features/enrollment/view";
import { AccountPicker } from "@/features/auth/picker";
import { GroupPicker } from "@/features/groups/picker";
import { ProfileRevisionPicker } from "@/features/profiles/picker";
import { RestrictedPage } from "@/components/layout/restricted-page";
import { canPermission } from "@/lib/permissions";

export const Route = createFileRoute("/_authenticated/enrollment")({
  component: EnrollmentPage,
});

function EnrollmentPage() {
  const { principal } = Route.useRouteContext();
  if (!canPermission(principal, "enrollment.manage", true))
    return (
      <RestrictedPage
        title="Enroll a device"
        restriction="Enrollment is restricted"
        reason="Enrollment codes and tokens apply to the whole fleet, so they need enrollment permission without a device scope."
      />
    );
  return (
    <EnrollmentView
      accountPicker={AccountPicker}
      groupPicker={GroupPicker}
      profileRevisionPicker={ProfileRevisionPicker}
    />
  );
}
