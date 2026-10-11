import { createFileRoute } from "@tanstack/react-router";
import { Accounts } from "@/features/auth/accounts";
import { DevicePicker } from "@/features/devices/picker";
import { GroupPicker } from "@/features/groups/picker";
import { canPermission } from "@/lib/permissions";

export const Route = createFileRoute("/_authenticated/accounts")({
  beforeLoad: ({ context }) => {
    if (!canPermission(context.principal, "accounts.manage"))
      throw new Error("Account management is not authorized.");
  },
  component: AccountsPage,
});

function AccountsPage() {
  return <Accounts devicePicker={DevicePicker} groupPicker={GroupPicker} />;
}
