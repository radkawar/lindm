import type { ReactNode } from "react";
import { cn } from "cn";

// Collapsed support-facing identifiers and diagnostics. Primary UI text stays in
// admin language; IDs and internal terms belong here only.
export function TechnicalDetails({
  items,
  summary = "Details",
  className,
  children,
}: {
  items: readonly { label: string; value: ReactNode }[];
  summary?: string;
  className?: string;
  children?: ReactNode;
}) {
  const shown = items.filter((item) => item.value !== undefined && item.value !== "");
  if (shown.length === 0 && !children) return null;
  return (
    <details className={cn("text-xs text-muted-foreground", className)}>
      <summary className="w-fit cursor-pointer py-1">{summary}</summary>
      <dl className="mt-2 grid gap-1 break-all">
        {shown.map((item) => (
          <div key={item.label}>
            <dt className="inline font-medium">{item.label}: </dt>
            <dd className="inline font-mono">{item.value}</dd>
          </div>
        ))}
      </dl>
      {children}
    </details>
  );
}
