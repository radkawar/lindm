// SPDX-License-Identifier: Apache-2.0

import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { RpcError } from "@/components/ui/rpc-error";
import { BrandLogo } from "@/components/ui/brand-logo";
import { toRpcFailure } from "@/lib/errors";
import { rememberNextPath } from "@/lib/next-path";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { loginHref } from "./session";
import { fetchAuthenticationOptions } from "./local-api";
import { LocalForm } from "./local-form";
import { sessionQueryKey, sessionQueryOptions } from "./queries";

// next: an already validated same-origin console path to open after sign-in.
export function SignIn({ notice, next }: { notice: string; next?: string }) {
  const client = useQueryClient();
  const options = useQuery({
    queryKey: ["authentication-options"],
    queryFn: ({ signal }) => fetchAuthenticationOptions(signal),
    retry: false,
  });
  return (
    <main id="main" className="mx-auto flex min-h-svh w-full max-w-lg items-center px-4 py-8">
      <Card className="w-full">
        <CardHeader>
          <BrandLogo stacked className="mx-auto mb-4" />
          <CardTitle>
            <h1 className="text-2xl font-semibold tracking-tight">lindm console</h1>
          </CardTitle>
          <CardDescription>Sign in to review devices and pending work.</CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-5">
          {notice !== "" ? (
            <p role="status" className="border bg-muted/30 p-3 text-sm">
              {notice}
            </p>
          ) : null}
          {options.isPending ? (
            <div role="status" className="grid gap-3">
              <span className="text-sm text-muted-foreground">Loading sign-in options…</span>
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
          {options.data?.setupAvailable ? (
            <Button render={<Link to="/setup" />}>Set up owner account</Button>
          ) : null}
          {options.data?.externalLogin ? (
            <Button render={<a href={loginHref} onClick={() => rememberNextPath(next)} />}>
              Sign in with organization
            </Button>
          ) : null}
          {options.data?.localLogin && !options.data.setupAvailable ? (
            <LocalForm
              emergency={options.data.breakGlass}
              onSuccess={async () => {
                // The home route then opens `next` or the dashboard.
                await client.invalidateQueries({ queryKey: sessionQueryKey });
                await client.fetchQuery(sessionQueryOptions());
              }}
            />
          ) : null}
          {options.data?.localLogin && !options.data.setupAvailable ? (
            <Link
              to="/enroll"
              className="text-center text-sm text-muted-foreground underline underline-offset-4 hover:text-foreground"
            >
              Enroll a local administrator account
            </Link>
          ) : null}
        </CardContent>
      </Card>
    </main>
  );
}
