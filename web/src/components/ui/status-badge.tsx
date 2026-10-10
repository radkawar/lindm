import type { ComponentProps, ReactNode } from "react";
import { cn } from "cn";
import { Badge } from "@/components/ui/badge";

export type StatusTone = "success" | "warning" | "destructive" | "neutral" | "info";

const statusClasses: Record<StatusTone, string> = {
  success: "border-success/25 bg-success/10 text-success",
  warning: "border-warning/25 bg-warning/10 text-warning",
  destructive: "border-destructive/25 bg-destructive/10 text-destructive",
  neutral: "border-neutral/25 bg-neutral/10 text-neutral",
  info: "border-info/25 bg-info/10 text-info",
};

export function StatusBadge({
  status,
  children,
  className,
  dot = false,
  ...props
}: {
  status: StatusTone;
  children?: ReactNode;
  className?: string;
  dot?: boolean;
} & Omit<ComponentProps<typeof Badge>, "variant" | "children">) {
  return (
    <Badge {...props} variant="outline" className={cn(statusClasses[status], className)}>
      {dot ? (
        <span aria-hidden="true" className="size-1.5 shrink-0 rounded-full bg-current" />
      ) : null}
      {children}
    </Badge>
  );
}
