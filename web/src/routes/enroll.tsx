import { useQuery } from "@tanstack/react-query";
import { createFileRoute, Link } from "@tanstack/react-router";
import { useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { LocalForm } from "@/features/auth/local-form";
import { fetchAuthenticationOptions } from "@/features/auth/local-api";

export const Route = createFileRoute("/enroll")({ component: EnrollmentRoute });

function EnrollmentRoute() {
  const [complete, setComplete] = useState(false);
  const options = useQuery({
    queryKey: ["authentication-options"],
    queryFn: ({ signal }) => fetchAuthenticationOptions(signal),
    retry: false,
  });
  return (
    <main id="main" className="mx-auto max-w-md px-4 py-12">
      <Card>
        <CardHeader>
          <CardTitle>Enroll local administrator</CardTitle>
        </CardHeader>
        <CardContent className="grid gap-4">
          {options.isPending ? <p role="status">Loading enrollment options…</p> : null}
          {options.isError ? <p role="alert">Unable to load enrollment options.</p> : null}
          {options.data && !options.data.localLogin ? (
            <p role="status">Local administrator enrollment is not configured.</p>
          ) : null}
          {complete ? (
            <p role="status">
              Account enrolled. Sign in with your password and registered authenticator.
            </p>
          ) : null}
          {!complete && options.data?.localLogin ? (
            <LocalForm
              enrollment
              onSuccess={() => {
                setComplete(true);
                return Promise.resolve();
              }}
            />
          ) : null}
          <Link to="/">Back to sign in</Link>
        </CardContent>
      </Card>
    </main>
  );
}
