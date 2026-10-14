// SPDX-License-Identifier: Apache-2.0

import { createRootRouteWithContext, Outlet } from "@tanstack/react-router";
import type { QueryClient } from "@tanstack/react-query";
import { NotFoundContent } from "@/components/layout/not-found";

export const Route = createRootRouteWithContext<{ queryClient: QueryClient }>()({
  component: () => (
    <>
      <a
        className="sr-only fixed top-2 left-2 z-[100] bg-background p-3 text-sm focus:not-sr-only focus:fixed focus:outline-2 focus:outline-ring"
        href="#main"
      >
        Skip to content
      </a>
      <Outlet />
    </>
  ),
  notFoundComponent: () => (
    <main id="main">
      <NotFoundContent />
    </main>
  ),
});
