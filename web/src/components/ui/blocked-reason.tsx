// SPDX-License-Identifier: Apache-2.0
// Project additions: Apache-2.0; shadcn-derived portions: MIT.
// Copyright (c) 2023 shadcn; see web/LICENSE.shadcn for the retained MIT notice.

import { Link } from "@tanstack/react-router";
import { cn } from "cn";
import type { BlockedReasonCopy } from "@/lib/errors";

// One plain sentence for a server-recorded reason, with its remedy link. The raw
// reason code is the caller's to show, once, in the row's Details.
export function BlockedReason({
  copy,
  className,
}: {
  copy: BlockedReasonCopy;
  className?: string;
}) {
  return (
    <p className={cn("whitespace-normal break-words", className)}>
      {copy.sentence}
      {copy.localField ? (
        <>
          {" "}
          <code className="font-mono text-xs">{copy.localField}</code>.
        </>
      ) : null}
      {copy.link ? (
        <>
          {" "}
          <Link to={copy.link.to} className="underline underline-offset-4">
            {copy.link.label}
          </Link>
        </>
      ) : null}
    </p>
  );
}
