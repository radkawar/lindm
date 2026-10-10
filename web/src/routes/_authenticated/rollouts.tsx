import { createFileRoute } from "@tanstack/react-router";
import { RolloutsView } from "@/features/targeting/rollouts";
import { canPermission } from "@/lib/permissions";

export const Route = createFileRoute("/_authenticated/rollouts")({
  beforeLoad: ({ context }) => {
    if (!canPermission(context.principal, "resources.assign"))
      throw new Error("Resource rollout management is not authorized.");
  },
  component: RolloutsView,
});
