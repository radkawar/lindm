import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useRouter } from "@tanstack/react-router";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { loginHref } from "./session";
import { fetchAuthenticationOptions } from "./local-api";
import { LocalForm } from "./local-form";
import { sessionQueryKey, sessionQueryOptions } from "./queries";

export function SignIn({ notice }: { notice: string }) {
  const client = useQueryClient();
  const router = useRouter();
  const options = useQuery({
    queryKey: ["authentication-options"],
    queryFn: ({ signal }) => fetchAuthenticationOptions(signal),
    retry: false,
  });
  return (
    <main id="main" className="mx-auto flex min-h-svh w-full max-w-md items-center px-4 py-8">
      <Card className="w-full">
        <CardHeader>
          <CardTitle>lindm console</CardTitle>
          <CardDescription>Console access is separate from device enrollment.</CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-3">
          {notice !== "" ? <p role="status">{notice}</p> : null}
          {options.isPending ? <p role="status">Loading sign-in options…</p> : null}
          {options.isError ? (
            <p role="alert">Unable to load sign-in options. Reload to try again.</p>
          ) : null}
          {options.data?.externalLogin ? (
            <Button render={<a href={loginHref} />}>Sign in with organization</Button>
          ) : null}
          {options.data?.localLogin ? (
            <LocalForm
              emergency={options.data.breakGlass}
              onSuccess={async () => {
                await client.invalidateQueries({ queryKey: sessionQueryKey });
                await client.fetchQuery(sessionQueryOptions());
                await router.navigate({ to: "/devices" });
              }}
            />
          ) : null}
          {options.data?.localLogin ? (
            <Link to="/enroll">Enroll a local administrator account</Link>
          ) : null}
        </CardContent>
      </Card>
    </main>
  );
}
