import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { toRpcFailure } from "@/lib/errors";

export function ListStatus({
  pending,
  error,
  empty,
  noun,
}: {
  pending: boolean;
  error: unknown;
  empty: boolean;
  noun: string;
}) {
  if (error) {
    const failure = toRpcFailure(error);
    return (
      <Alert variant="destructive">
        <AlertTitle>{failure.denied ? "Not authorized" : `${noun} unavailable`}</AlertTitle>
        <AlertDescription>
          {failure.codeName}: {failure.message}
        </AlertDescription>
      </Alert>
    );
  }
  if (pending)
    return (
      <div role="status" className="grid gap-3">
        <span className="text-sm text-muted-foreground">Loading {noun}…</span>
        <Skeleton className="h-32 w-full" />
      </div>
    );
  if (empty)
    return (
      <p
        role="status"
        className="border border-dashed bg-muted/30 p-6 text-center text-sm text-muted-foreground"
      >
        No {noun} on this page.
      </p>
    );
  return null;
}

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
      <p className="self-center text-sm text-muted-foreground">
        At most 100 records per page; these are not fleet totals.
      </p>
    </div>
  );
}
