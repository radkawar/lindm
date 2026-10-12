import type { ReactNode } from "react";
import { EmptyState } from "@/components/ui/empty-state";
import { RpcError } from "@/components/ui/rpc-error";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { toRpcFailure } from "@/lib/errors";

export function ListStatus({
  pending,
  error,
  empty,
  noun,
  firstPage,
  emptyDescription,
  emptyAction,
}: {
  pending: boolean;
  error: unknown;
  empty: boolean;
  noun: string;
  // An empty first page means none exist; later pages are only empty past the end.
  firstPage: boolean;
  emptyDescription?: string;
  emptyAction?: ReactNode;
}) {
  if (error) {
    const failure = toRpcFailure(error);
    return <RpcError failure={failure} />;
  }
  if (pending)
    return (
      <div role="status" className="grid gap-3">
        <span className="text-sm text-muted-foreground">Loading {noun}…</span>
        <Skeleton className="h-32 w-full" />
      </div>
    );
  if (empty)
    return firstPage ? (
      <EmptyState title={`No ${noun} yet`} description={emptyDescription} action={emptyAction} />
    ) : (
      <EmptyState title={`No more ${noun}`} description="Return to the first page." />
    );
  return null;
}

// Renders nothing while everything fits on the first page.
export function TargetPagination({
  afterId,
  nextId,
  busy,
  onPage,
}: {
  afterId: string;
  nextId?: string;
  busy: boolean;
  onPage: (id: string) => void;
}) {
  if (!afterId && !nextId) return null;
  return (
    <div className="flex flex-wrap gap-2">
      <Button variant="outline" disabled={!afterId || busy} onClick={() => onPage("")}>
        First page
      </Button>
      <Button
        variant="outline"
        disabled={!nextId || busy}
        onClick={() => {
          if (nextId) onPage(nextId);
        }}
      >
        Next page
      </Button>
      <p className="self-center text-sm text-muted-foreground">Up to 100 per page.</p>
    </div>
  );
}
