// SPDX-License-Identifier: Apache-2.0

import { Link } from "@tanstack/react-router";
import { Button } from "@/components/ui/button";
import { EmptyState } from "@/components/ui/empty-state";
import { PageHeader } from "@/components/ui/page-header";

// A page reached by URL whose server grants the caller lacks. Navigation hides
// these pages; this states the fact and who can act instead of a page of refusals.
export function RestrictedPage({
  title,
  restriction,
  reason,
}: {
  title: string;
  restriction: string;
  reason: string;
}) {
  return (
    <div className="grid gap-6" data-review-state="restricted">
      <PageHeader title={title} />
      <EmptyState
        title={restriction}
        description={`${reason} Ask an organization owner if you need this access.`}
        action={<Button render={<Link to="/dashboard" />}>Back to dashboard</Button>}
      />
    </div>
  );
}
