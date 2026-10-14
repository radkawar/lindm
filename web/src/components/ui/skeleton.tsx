// SPDX-License-Identifier: Apache-2.0
// Project additions: Apache-2.0; shadcn-derived portions: MIT.
// Copyright (c) 2023 shadcn; see web/LICENSE.shadcn for the retained MIT notice.

// Upstream: https://ui.shadcn.com (MIT). Icon placeholders resolved to lucide-react.
import { cn } from "cn";

function Skeleton({ className, ...props }: React.ComponentProps<"div">) {
  return (
    <div
      data-slot="skeleton"
      className={cn("animate-pulse rounded-md bg-muted", className)}
      {...props}
    />
  );
}

export { Skeleton };
