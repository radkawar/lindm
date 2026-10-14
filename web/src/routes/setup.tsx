// SPDX-License-Identifier: Apache-2.0

import { useQuery, useQueryClient } from "@tanstack/react-query";
import { createFileRoute, Link, Navigate } from "@tanstack/react-router";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { BrandLogo } from "@/components/ui/brand-logo";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { RpcError } from "@/components/ui/rpc-error";
import { Skeleton } from "@/components/ui/skeleton";
import { LocalForm } from "@/features/auth/local-form";
import { fetchAuthenticationOptions } from "@/features/auth/local-api";
import { sessionQueryKey, sessionQueryOptions } from "@/features/auth/queries";
import { toRpcFailure } from "@/lib/errors";

export const Route = createFileRoute("/setup")({ component: SetupRoute });

function SetupRoute() {
  const client = useQueryClient();
  const session = useQuery(sessionQueryOptions());
  const options = useQuery({
    queryKey: ["authentication-options"],
    queryFn: ({ signal }) => fetchAuthenticationOptions(signal),
    retry: false,
  });
  if (session.data) return <Navigate to="/dashboard" replace />;
  return (
    <main id="main" className="mx-auto flex min-h-svh w-full max-w-lg items-center px-4 py-8">
      <Card className="w-full">
        <CardHeader>
          <BrandLogo stacked className="mx-auto mb-4" />
          <CardTitle>
            <h1 className="text-xl font-semibold tracking-tight sm:text-2xl">
              Set up your owner account
            </h1>
          </CardTitle>
          <CardDescription>Use the setup code from your server installer.</CardDescription>
        </CardHeader>
        <CardContent className="grid gap-5">
          {options.isPending || session.isPending ? (
            <div role="status" className="grid gap-3">
              <span className="text-sm text-muted-foreground">Checking setup access…</span>
              <Skeleton className="h-10 w-full" />
              <Skeleton className="h-10 w-full" />
            </div>
          ) : null}
          {options.isError ? (
            <RpcError failure={toRpcFailure(options.error)}>
              <Button variant="outline" onClick={() => void options.refetch()}>
                Try again
              </Button>
            </RpcError>
          ) : null}
          {session.isError ? (
            <RpcError failure={toRpcFailure(session.error)}>
              <Button variant="outline" onClick={() => void session.refetch()}>
                Check access again
              </Button>
            </RpcError>
          ) : null}
          {options.data?.setupAvailable && !session.isPending && !session.isError ? (
            <>
              <Alert>
                <AlertTitle>Owner access</AlertTitle>
                <AlertDescription>
                  This account controls administrator access and device management. Keep its
                  password and passkey private.
                </AlertDescription>
              </Alert>
              <LocalForm
                setup
                onSuccess={async () => {
                  await client.invalidateQueries({ queryKey: sessionQueryKey });
                  await client.fetchQuery(sessionQueryOptions());
                  await client.invalidateQueries({ queryKey: ["authentication-options"] });
                }}
              />
            </>
          ) : null}
          {options.data && !options.data.setupAvailable ? (
            <Alert>
              <AlertTitle>Setup unavailable</AlertTitle>
              <AlertDescription>
                Sign in if an owner account exists. Otherwise, ask your server administrator for a
                fresh setup code.
              </AlertDescription>
            </Alert>
          ) : null}
          <Link to="/" className="text-sm underline underline-offset-4">
            Return to sign in
          </Link>
        </CardContent>
      </Card>
    </main>
  );
}
