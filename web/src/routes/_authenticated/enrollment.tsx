import { createFileRoute } from "@tanstack/react-router";
import { EnrollmentView } from "@/features/enrollment/view";
import { AccountPicker } from "@/features/auth/picker";
import { GroupPicker } from "@/features/groups/picker";
import { ProfileRevisionPicker } from "@/features/profiles/picker";
import { RestrictedPage } from "@/components/layout/restricted-page";
import { canPermission } from "@/lib/permissions";

// ?create=code opens the one-time code dialog, ?create=token the provisioning token dialog.
type EnrollmentSearch = { create?: "code" | "token" };

export const Route = createFileRoute("/_authenticated/enrollment")({
  validateSearch: (search: Record<string, unknown>): EnrollmentSearch =>
    search.create === "code" || search.create === "token" ? { create: search.create } : {},
  component: EnrollmentPage,
});

function EnrollmentPage() {
  const { principal } = Route.useRouteContext();
  const { create } = Route.useSearch();
  const navigate = Route.useNavigate();
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
      method={create === "code" ? "grant" : create === "token" ? "provisioning" : null}
      onMethodChange={(method) =>
        void navigate({
          search: method ? { create: method === "grant" ? "code" : "token" } : {},
          replace: true,
        })
      }
    />
  );
}
