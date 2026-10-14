// SPDX-License-Identifier: Apache-2.0
// Project additions: Apache-2.0; shadcn-derived portions: MIT.
// Copyright (c) 2023 shadcn; see web/LICENSE.shadcn for the retained MIT notice.

// Upstream: https://ui.shadcn.com (MIT). Icon placeholders resolved to lucide-react.
"use client";

import { Separator as SeparatorPrimitive } from "@base-ui/react/separator";
import { cn } from "cn";

function Separator({ className, orientation = "horizontal", ...props }: SeparatorPrimitive.Props) {
  return (
    <SeparatorPrimitive
      data-slot="separator"
      orientation={orientation}
      className={cn(
        "shrink-0 bg-border data-horizontal:h-px data-horizontal:w-full data-vertical:w-px data-vertical:self-stretch",
        className,
      )}
      {...props}
    />
  );
}

export { Separator };
