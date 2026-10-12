import { createFileRoute, Navigate, useRouter } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { Button } from "@/components/ui/button";
import { RpcError } from "@/components/ui/rpc-error";
import { toRpcFailure } from "@/lib/errors";
import { pendingNextPath, rememberNextPath, safeNextPath } from "@/lib/next-path";
import { SignIn } from "@/features/auth/sign-in";
import { sessionQueryOptions } from "@/features/auth/queries";

export const Route = createFileRoute("/")({
  // The page a signed-out visitor asked for; checked again before use.
  validateSearch: (search: Record<string, unknown>): { next?: string } => {
    const next = safeNextPath(search.next);
    return next ? { next } : {};
  },
  component: HomeRoute,
});

function HomeRoute() {
  const session = useQuery(sessionQueryOptions());
  const router = useRouter();
  // The router merges the raw search into useSearch(), so validate again here:
  // never navigate to an unchecked value.
  const next = safeNextPath(Route.useSearch().next);
  // An organization sign-in round trip returns here without the search.
  const [pending] = useState(() => next ?? pendingNextPath());
  const signedIn = !!session.data;
  useEffect(() => {
    if (!signedIn) return;
    rememberNextPath(undefined);
    if (pending) void router.navigate({ href: pending, replace: true });
  }, [signedIn, pending, router]);
  if (session.isPending) {
    return (
      <main className="p-8" aria-busy="true">
        <p role="status">Checking session…</p>
      </main>
    );
  }
  if (session.isError) {
    return (
      <main className="mx-auto max-w-md p-8">
        <RpcError failure={toRpcFailure(session.error)}>
          <Button variant="outline" onClick={() => void session.refetch()}>
            Retry session check
          </Button>
        </RpcError>
      </main>
    );
  }
  if (session.data) {
    if (!pending) return <Navigate to="/dashboard" />;
    return (
      <main className="p-8" aria-busy="true">
        <p role="status">Opening the page you asked for…</p>
      </main>
    );
  }
  return <SignIn notice="" next={pending} />;
}
