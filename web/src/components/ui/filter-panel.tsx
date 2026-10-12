import { SlidersHorizontalIcon } from "lucide-react";
import { useId, useState, type ReactNode } from "react";
import { cn } from "cn";
import { Button } from "./button";

// List filters. On narrow screens they fold behind one toggle so the first rows
// of the list are on the first screen (ui-review "mobile-first-screen"); the
// toggle names how many filters are active so a filtered list is never mistaken
// for the whole fleet. From the md breakpoint up the filters are always shown.
export function FilterPanel({
  activeCount,
  label = "Filters",
  className,
  children,
}: {
  activeCount: number;
  label?: string;
  className?: string;
  children: ReactNode;
}) {
  const id = useId();
  const [open, setOpen] = useState(false);
  return (
    <div data-slot="filter-panel" className={cn("grid min-w-0 gap-3", className)}>
      <Button
        variant="outline"
        className="w-fit md:hidden"
        aria-expanded={open}
        aria-controls={id}
        onClick={() => setOpen(!open)}
      >
        <SlidersHorizontalIcon aria-hidden="true" />
        {label}
        {activeCount > 0 ? ` · ${activeCount} active` : ""}
      </Button>
      <div id={id} className={cn("min-w-0 gap-3 md:grid", open ? "grid" : "hidden")}>
        {children}
      </div>
    </div>
  );
}
