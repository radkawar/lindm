import { createRootRouteWithContext, Outlet } from "@tanstack/react-router";
import type { QueryClient } from "@tanstack/react-query";

export const Route = createRootRouteWithContext<{ queryClient: QueryClient }>()({
  component: () => (
    <>
      <a
        className="sr-only fixed top-2 left-2 z-[100] bg-background p-3 text-sm focus:not-sr-only"
        href="#main"
      >
        Skip to content
      </a>
      <Outlet />
    </>
  ),
});
