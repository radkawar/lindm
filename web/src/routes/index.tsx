import { createFileRoute, Navigate } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { Button } from "@/components/ui/button";
import { RpcError } from "@/components/ui/rpc-error";
import { toRpcFailure } from "@/lib/errors";
import { SignIn } from "@/features/auth/sign-in";
import { sessionQueryOptions } from "@/features/auth/queries";

export const Route = createFileRoute("/")({
  component: HomeRoute,
});

function HomeRoute() {
  const session = useQuery(sessionQueryOptions());
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
  if (session.data) return <Navigate to="/dashboard" />;
  return <SignIn notice="" />;
}
