import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { loginHref } from "./session";

export function SignIn({ notice }: { notice: string }) {
  return (
    <main id="main" className="mx-auto flex min-h-svh w-full max-w-md items-center px-4">
      <Card className="w-full">
        <CardHeader>
          <CardTitle>lindm console</CardTitle>
          <CardDescription>
            Sign in with the configured identity provider. Console access is separate from device
            enrollment.
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-3">
          {notice !== "" ? <p role="status">{notice}</p> : null}
          <Button render={<a href={loginHref} />}>Sign in</Button>
        </CardContent>
      </Card>
    </main>
  );
}
