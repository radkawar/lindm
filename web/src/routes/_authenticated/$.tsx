// SPDX-License-Identifier: Apache-2.0

import { createFileRoute } from "@tanstack/react-router";
import { NotFoundContent } from "@/components/layout/not-found";

// An address no console page matches renders inside the signed-in shell, with
// navigation intact; a signed-out visitor signs in first and returns here.
export const Route = createFileRoute("/_authenticated/$")({
  component: NotFoundContent,
});
