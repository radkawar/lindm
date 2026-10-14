// SPDX-License-Identifier: Apache-2.0
// Project additions: Apache-2.0; shadcn-derived portions: MIT.
// Copyright (c) 2023 shadcn; see web/LICENSE.shadcn for the retained MIT notice.

import type { ReactNode } from "react";
import { Button } from "./button";

// A page has one Refresh, here, that rereads everything the page shows: pass a
// callback that refetches all of its queries rather than adding "Refresh X"
// buttons to sections (ui-review "single-refresh").
export function PageHeader({
  title,
  description,
  actions,
  onRefresh,
  refreshing = false,
}: {
  title: string;
  description?: string;
  actions?: ReactNode;
  onRefresh?: () => void;
  refreshing?: boolean;
}) {
  return (
    <header className="flex flex-wrap items-start justify-between gap-3">
      <div className="grid min-w-0 gap-1">
        <h1 className="break-words text-xl font-semibold tracking-tight sm:text-2xl">{title}</h1>
        {description ? <p className="text-sm text-muted-foreground">{description}</p> : null}
      </div>
      {actions || onRefresh ? (
        <div className="flex flex-wrap items-center gap-2">
          {onRefresh ? (
            <Button variant="outline" disabled={refreshing} onClick={onRefresh}>
              Refresh
            </Button>
          ) : null}
          {actions}
        </div>
      ) : null}
    </header>
  );
}
