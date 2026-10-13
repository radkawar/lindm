import { createFileRoute, Link } from "@tanstack/react-router";
import { Authorization } from "@/features/auth/authorization";
import { DirectoryGroupPicker } from "@/features/auth/directory-group-picker";
import { DevicePicker } from "@/features/devices/picker";
import { GroupPicker } from "@/features/groups/picker";
import { canPermission } from "@/lib/permissions";
import { EmptyState } from "@/components/ui/empty-state";
import { PageHeader } from "@/components/ui/page-header";
import { Button } from "@/components/ui/button";

export const Route = createFileRoute("/_authenticated/authorization")({
  component: AuthorizationPage,
});

function AuthorizationPage() {
  const { principal } = Route.useRouteContext();
  if (!canPermission(principal, "accounts.manage", true))
    return (
      <div className="grid gap-6">
        <PageHeader title="Authorization" description="Manage organization access." />
        <EmptyState
          title="Access policy requires permission"
          description="This policy requires unrestricted account-management permission. Ask an organization owner for access."
          action={<Button render={<Link to="/" />}>Back to dashboard</Button>}
        />
      </div>
    );
  return (
    <Authorization
      devicePicker={DevicePicker}
      groupPicker={GroupPicker}
      directoryGroupPicker={DirectoryGroupPicker}
    />
  );
}
