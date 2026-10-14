// SPDX-License-Identifier: Apache-2.0
// Project additions: Apache-2.0; shadcn-derived portions: MIT.
// Copyright (c) 2023 shadcn; see web/LICENSE.shadcn for the retained MIT notice.

// Upstream: https://ui.shadcn.com (MIT). Icon placeholders resolved to lucide-react.
"use client";

import * as React from "react";
import { cn } from "cn";

function Table({ className, ...props }: React.ComponentProps<"table">) {
  const container = React.useRef<HTMLDivElement>(null);
  const [overflow, setOverflow] = React.useState({
    scrollable: false,
    atStart: true,
    atEnd: true,
  });
  React.useEffect(() => {
    const node = container.current;
    if (!node) return;
    const update = () => {
      const scrollable = node.scrollWidth > node.clientWidth + 1;
      const atStart = node.scrollLeft <= 1;
      const atEnd = node.scrollLeft + node.clientWidth >= node.scrollWidth - 1;
      setOverflow((current) =>
        current.scrollable === scrollable && current.atStart === atStart && current.atEnd === atEnd
          ? current
          : { scrollable, atStart, atEnd },
      );
    };
    const observer = new ResizeObserver(update);
    observer.observe(node);
    if (node.firstElementChild) observer.observe(node.firstElementChild);
    node.addEventListener("scroll", update, { passive: true });
    update();
    return () => {
      observer.disconnect();
      node.removeEventListener("scroll", update);
    };
  }, []);
  // lindm: a horizontally scrolling table must be reachable and scrollable by keyboard,
  // and must say so: a hint names the hidden columns and the clipped edge fades.
  return (
    <div data-slot="table-frame" className="grid w-full min-w-0 gap-1">
      {overflow.scrollable ? (
        <p
          data-slot="table-scroll-hint"
          aria-hidden="true"
          className="flex items-center justify-end gap-1 text-xs text-muted-foreground"
        >
          {overflow.atEnd
            ? "Scroll back for the first columns"
            : "Scroll sideways for more columns"}
          <span aria-hidden="true">{overflow.atEnd ? "←" : "→"}</span>
        </p>
      ) : null}
      <div
        ref={container}
        data-slot="table-container"
        tabIndex={overflow.scrollable ? 0 : undefined}
        role={overflow.scrollable ? "region" : undefined}
        aria-label={overflow.scrollable ? (props["aria-label"] ?? "Scrollable table") : undefined}
        className={cn(
          "relative w-full min-w-0 overflow-x-auto focus-visible:outline-2 focus-visible:outline-ring",
          overflow.scrollable && !overflow.atEnd && "mask-r-from-[calc(100%-2.5rem)]",
          overflow.scrollable && !overflow.atStart && "mask-l-from-[calc(100%-2.5rem)]",
        )}
      >
        <table
          data-slot="table"
          className={cn("w-full caption-bottom text-sm", className)}
          {...props}
        />
      </div>
    </div>
  );
}

function TableHeader({ className, ...props }: React.ComponentProps<"thead">) {
  return (
    <thead
      data-slot="table-header"
      className={cn("bg-muted/40 [&_tr]:border-b", className)}
      {...props}
    />
  );
}

function TableBody({ className, ...props }: React.ComponentProps<"tbody">) {
  return (
    <tbody
      data-slot="table-body"
      className={cn("[&_tr:last-child]:border-0", className)}
      {...props}
    />
  );
}

function TableFooter({ className, ...props }: React.ComponentProps<"tfoot">) {
  return (
    <tfoot
      data-slot="table-footer"
      className={cn("border-t bg-muted/50 font-medium [&>tr]:last:border-b-0", className)}
      {...props}
    />
  );
}

function TableRow({ className, ...props }: React.ComponentProps<"tr">) {
  return (
    <tr
      data-slot="table-row"
      className={cn(
        "border-b transition-colors hover:bg-muted/50 has-aria-expanded:bg-muted/50 data-[state=selected]:bg-muted",
        className,
      )}
      {...props}
    />
  );
}

function TableHead({ className, ...props }: React.ComponentProps<"th">) {
  return (
    <th
      data-slot="table-head"
      className={cn(
        "h-11 px-4 text-left align-middle text-xs font-medium whitespace-nowrap text-muted-foreground [&:has([role=checkbox])]:pr-0",
        className,
      )}
      {...props}
    />
  );
}

function TableCell({ className, ...props }: React.ComponentProps<"td">) {
  return (
    <td
      data-slot="table-cell"
      className={cn(
        "px-4 py-3 align-middle whitespace-nowrap [&:has([role=checkbox])]:pr-0",
        className,
      )}
      {...props}
    />
  );
}

function TableCaption({ className, ...props }: React.ComponentProps<"caption">) {
  return (
    <caption
      data-slot="table-caption"
      className={cn("mt-4 text-sm text-muted-foreground", className)}
      {...props}
    />
  );
}

export { Table, TableHeader, TableBody, TableFooter, TableHead, TableRow, TableCell, TableCaption };
