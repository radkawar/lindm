import { createFileRoute } from "@tanstack/react-router";
import { DashboardView } from "@/features/dashboard/view";

export const Route = createFileRoute("/_authenticated/dashboard")({
  component: DashboardView,
});
