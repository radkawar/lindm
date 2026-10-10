import { createFileRoute } from "@tanstack/react-router";
import { ApprovalsView } from "@/features/approvals/view";

export const Route = createFileRoute("/_authenticated/approvals")({
  component: ApprovalsView,
});
