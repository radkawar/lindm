import { createFileRoute } from "@tanstack/react-router";
import { Accounts } from "@/features/auth/accounts";
import { DevicePicker } from "@/features/devices/picker";
import { GroupPicker } from "@/features/groups/picker";
import { canPermission } from "@/lib/permissions";

export const Route = createFileRoute("/_authenticated/accounts")({
  // ?create=true opens the Create account dialog.
  validateSearch: (search: Record<string, unknown>): { create?: true } =>
    search.create === true ? { create: true } : {},
  beforeLoad: ({ context }) => {
    if (!canPermission(context.principal, "accounts.manage", true))
      throw new Error("Account management is not authorized.");
  },
  component: AccountsPage,
});

function AccountsPage() {
  const { create } = Route.useSearch();
  const navigate = Route.useNavigate();
  return (
    <Accounts
      devicePicker={DevicePicker}
      groupPicker={GroupPicker}
      creating={create === true}
      onCreatingChange={(next) =>
        void navigate({ search: next ? { create: true } : {}, replace: true })
      }
    />
  );
}
