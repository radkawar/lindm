import { createFileRoute, redirect } from "@tanstack/react-router";
import { Accounts } from "@/features/auth/accounts";

export const Route = createFileRoute("/_authenticated/accounts")({
  beforeLoad: ({ context }) => {
    if (context.principal.role !== "owner") throw redirect({ to: "/devices" });
  },
  component: Accounts,
});
