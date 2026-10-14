// SPDX-License-Identifier: Apache-2.0

import { createRouter, type ErrorComponentProps } from "@tanstack/react-router";
import { bindRouter, queryClient } from "./query";
import { routeTree } from "../routeTree.gen";
import { Button } from "@/components/ui/button";
import { NotFoundContent } from "@/components/layout/not-found";

export const router = createRouter({
  routeTree,
  context: { queryClient },
  defaultPreload: "intent",
  defaultErrorComponent: ConsoleRouteError,
  // Inside the console shell, which already provides the main landmark.
  defaultNotFoundComponent: NotFoundContent,
});

bindRouter(router);

function ConsoleRouteError({ error }: ErrorComponentProps) {
  return (
    <main id="main" className="mx-auto flex max-w-xl flex-col gap-4 p-6">
      <h1 className="text-2xl font-semibold">Unable to load the console</h1>
      <p role="alert">{error instanceof Error ? error.message : "The request failed."}</p>
      <p>Retry to recheck your session and reload this page.</p>
      <Button onClick={() => window.location.reload()}>Retry</Button>
    </main>
  );
}

declare module "@tanstack/react-router" {
  interface Register {
    router: typeof router;
  }
}
