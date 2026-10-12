import { Link, useLocation } from "@tanstack/react-router";
import { Button } from "@/components/ui/button";

// Unknown console addresses, including mistyped or outdated links.
export function NotFoundContent() {
  const pathname = useLocation({ select: (location) => location.pathname });
  return (
    <div className="mx-auto flex max-w-xl flex-col gap-4 p-6">
      <h1 className="text-2xl font-semibold">Page not found</h1>
      <p className="text-sm text-muted-foreground">
        No console page matches{" "}
        <span className="font-mono break-all text-foreground">{pathname}</span>. The link may be
        mistyped or from an older console version.
      </p>
      <div className="flex flex-wrap gap-2">
        <Button render={<Link to="/dashboard" />}>Go to dashboard</Button>
        <Button variant="outline" render={<Link to="/devices" />}>
          Find a device
        </Button>
      </div>
    </div>
  );
}
