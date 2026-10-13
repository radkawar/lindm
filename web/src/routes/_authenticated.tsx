import { createFileRoute, Outlet, redirect, useRouter } from "@tanstack/react-router";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState, useSyncExternalStore } from "react";
import { ConsoleShell } from "@/components/layout/console-shell";
import { accountLabel } from "@/features/auth/session";
import { logout, sessionIdentity, sessionQueryOptions } from "@/features/auth/queries";
import { AuthLifetimeContext } from "@/hooks/use-auth-lifetime";
import { PrincipalContext } from "@/hooks/use-permissions";
import { getAuthLifetime, subscribeAuthLifetime } from "@/lib/auth-lifetime";
import { CommandPalette } from "@/app/command-palette";
import { Toaster } from "@/components/ui/sonner";
import { Skeleton } from "@/components/ui/skeleton";
import { RpcError } from "@/components/ui/rpc-error";
import { toRpcFailure, type RpcFailure } from "@/lib/errors";

export const Route = createFileRoute("/_authenticated")({
  beforeLoad: async ({ context, location }) => {
    // Every navigation passes through here, in-page ones too: a tab or an action
    // dialog lives in the URL. A known session is therefore rechecked in the
    // background once stale, never awaited; under load that round trip held
    // Escape and Close for seconds. The server still authorizes every request,
    // and a session found ended returns to sign-in (AuthenticatedLayout, app/query.ts).
    const principal = await context.queryClient.ensureQueryData({
      ...sessionQueryOptions(),
      revalidateIfStale: true,
    });
    // Signed out: sign in, then return to the page that was asked for.
    if (!principal) throw redirect({ to: "/", search: { next: location.href } });
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
  const [logoutError, setLogoutError] = useState<RpcFailure | null>(null);

  useEffect(() => {
    // The background recheck found the session ended: sign in, then return here.
    if (session.isSuccess && session.data === null) {
      void router.navigate({ to: "/", search: { next: router.state.location.href } });
    }
  }, [router, session.data, session.isSuccess]);

  if (!principal || !lifetime || lifetime.identity !== sessionIdentity(principal)) {
    return (
      <div className="grid gap-4 p-6" role="status" aria-label="Checking session">
        <Skeleton className="h-10 w-64" />
        <Skeleton className="h-48 w-full" />
        <span className="sr-only">Checking session…</span>
      </div>
    );
  }

  return (
    <ConsoleShell
      userLabel={accountLabel(principal)}
      role={principal.role}
      principal={principal}
      loggingOut={loggingOut}
      commandPalette={
        <CommandPalette key={lifetime.generation} principal={principal} lifetime={lifetime} />
      }
      onLogout={() => {
        setLoggingOut(true);
        setLogoutError(null);
        void logout(queryClient, principal.csrfToken)
          .then(() => {
            return router.navigate({ to: "/" });
          })
          .catch((error: unknown) => {
            setLogoutError(toRpcFailure(error));
          })
          .finally(() => setLoggingOut(false));
      }}
    >
      {principal.breakGlass ? (
        <div
          role="alert"
          className="sticky top-0 z-50 border-2 border-warning bg-background p-4 text-warning"
        >
          <strong>Break-glass emergency session: restricted and audited</strong>
          <p>Incident: {principal.incidentReason}</p>
          <p>Sign out to end this emergency session when the incident is resolved.</p>
        </div>
      ) : null}
      {logoutError ? <RpcError failure={logoutError} title="Sign-out failed" /> : null}
      <AuthLifetimeContext key={lifetime.generation} value={lifetime}>
        <PrincipalContext value={principal}>
          <main id="main" tabIndex={-1} className="min-w-0 outline-none">
            <Outlet />
          </main>
          <Toaster />
        </PrincipalContext>
      </AuthLifetimeContext>
    </ConsoleShell>
  );
}
