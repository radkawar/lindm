// SPDX-License-Identifier: Apache-2.0
// Project additions: Apache-2.0; shadcn-derived portions: MIT.
// Copyright (c) 2023 shadcn; see web/LICENSE.shadcn for the retained MIT notice.

import type { DescMessage } from "@bufbuild/protobuf";
import { useState } from "react";

// Expand on demand: recursive message graphs never render an unbounded tree.
export function ProtobufFields({ schema }: { schema: DescMessage }) {
  const [expanded, setExpanded] = useState(false);
  return (
    <details
      className="min-w-0 text-xs text-muted-foreground"
      onToggle={(event) => setExpanded(event.currentTarget.open)}
    >
      <summary className="cursor-pointer py-1">Fields: {schema.typeName}</summary>
      {expanded ? (
        <ul className="grid gap-2 border-l pl-3">
          {schema.fields.map((field) => (
            <li key={field.number} className="min-w-0 break-words">
              <code>{field.jsonName}</code>
              {field.oneof ? `: choose one ${field.oneof.name} field` : ""}
              {field.fieldKind === "list" ? ": array" : ""}
              {field.fieldKind === "enum"
                ? `: ${field.enum.values.map((value) => value.name).join(" | ")}`
                : ""}
              {field.fieldKind === "message" ? <ProtobufFields schema={field.message} /> : null}
              {field.fieldKind === "list" && field.listKind === "message" ? (
                <ProtobufFields schema={field.message} />
              ) : null}
              {field.fieldKind === "list" && field.listKind === "enum"
                ? `: ${field.enum.values.map((value) => value.name).join(" | ")}`
                : ""}
            </li>
          ))}
        </ul>
      ) : null}
    </details>
  );
}
