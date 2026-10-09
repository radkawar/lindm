import { createFileRoute, Outlet, redirect, useRouter } from "@tanstack/react-router";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState, useSyncExternalStore } from "react";
import { ConsoleShell } from "@/components/layout/console-shell";
import { accountLabel } from "@/features/auth/session";
import { logout, sessionIdentity, sessionQueryOptions } from "@/features/auth/queries";
import { AuthLifetimeContext } from "@/hooks/use-auth-lifetime";
import { getAuthLifetime, subscribeAuthLifetime } from "@/lib/auth-lifetime";

export const Route = createFileRoute("/_authenticated")({
  beforeLoad: async ({ context }) => {
    const principal = await context.queryClient.fetchQuery(sessionQueryOptions());
    if (!principal) throw redirect({ to: "/" });
    return { principal };
  },
  component: AuthenticatedLayout,
});

function AuthenticatedLayout() {
  const router = useRouter();
  const queryClient = useQueryClient();
  const session = useQuery(sessionQueryOptions());
  const principal = session.data;
  const lifetime = useSyncExternalStore(subscribeAuthLifetime, getAuthLifetime);
  const [loggingOut, setLoggingOut] = useState(false);
  const [logoutError, setLogoutError] = useState("");

  useEffect(() => {
    if (session.isSuccess && session.data === null) {
      void router.navigate({ to: "/" });
    }
  }, [router, session.data, session.isSuccess]);

  if (!principal || !lifetime || lifetime.identity !== sessionIdentity(principal)) {
    return <p role="status">Checking session…</p>;
  }

  return (
    <ConsoleShell
      userLabel={accountLabel(principal)}
      role={principal.role}
      loggingOut={loggingOut}
      onLogout={() => {
        setLoggingOut(true);
        setLogoutError("");
        void logout(queryClient, principal.csrfToken)
          .then(() => {
            return router.navigate({ to: "/" });
          })
          .catch((error: unknown) => {
            setLogoutError(error instanceof Error ? error.message : "Sign-out failed.");
          })
          .finally(() => setLoggingOut(false));
      }}
    >
      {principal.breakGlass ? (
        <div
          role="alert"
          className="sticky top-0 z-50 rounded border-2 border-destructive bg-background p-4 text-destructive"
        >
          <strong>Break-glass emergency session — restricted and audited</strong>
          <p>Incident: {principal.incidentReason}</p>
          <p>Sign out to end this emergency session when the incident is resolved.</p>
        </div>
      ) : null}
      {logoutError !== "" ? <p role="alert">{logoutError}</p> : null}
      <AuthLifetimeContext key={lifetime.generation} value={lifetime}>
        <div id="main">
          <Outlet />
        </div>
      </AuthLifetimeContext>
    </ConsoleShell>
  );
}
