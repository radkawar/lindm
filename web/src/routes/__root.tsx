import { createRootRouteWithContext, Outlet } from "@tanstack/react-router";
import type { QueryClient } from "@tanstack/react-query";

export const Route = createRootRouteWithContext<{ queryClient: QueryClient }>()({
  component: () => (
    <>
      <a className="sr-only focus:not-sr-only" href="#main">
        Skip to content
      </a>
      <Outlet />
    </>
  ),
});
