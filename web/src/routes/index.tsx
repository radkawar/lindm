import { createFileRoute, Navigate } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { Alert, AlertDescription } from "@/components/ui/alert";
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
        <Alert variant="destructive">
          <AlertDescription>{session.error.message}</AlertDescription>
        </Alert>
      </main>
    );
  }
  if (session.data) return <Navigate to="/devices" />;
  return <SignIn notice="" />;
}
