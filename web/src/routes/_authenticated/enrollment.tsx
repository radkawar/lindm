import { createFileRoute } from "@tanstack/react-router";
import { EnrollmentView } from "@/features/enrollment/view";

export const Route = createFileRoute("/_authenticated/enrollment")({
  component: EnrollmentView,
});
