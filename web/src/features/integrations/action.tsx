import { useRef, useState, type ReactNode } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "@tanstack/react-router";
import { toast } from "sonner";
import { RpcError } from "@/components/ui/rpc-error";
import { Button } from "@/components/ui/button";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
import { synchronizeAuthLifetime } from "@/lib/auth-lifetime";
import { classifyRpcFailure, toRpcFailure, type RpcFailure } from "@/lib/errors";
import { clearCsrfToken } from "@/lib/rpc";

export type IntegrationAction = {
  perform: (operation: () => Promise<unknown>) => void;
  /** Busy, or an ambiguous outcome that must be retried before another change. */
  blocked: boolean;
  feedback: ReactNode;
};

// Pending requests (including write-only keys) stay only in component memory.
// Ambiguous mutations retain the exact request closure for an explicit retry.
export function useIntegrationAction(): IntegrationAction {
  const lifetime = useAuthLifetime();
  const client = useQueryClient();
  const navigate = useNavigate();
  const pending = useRef<(() => Promise<unknown>) | null>(null);
  const running = useRef(false);
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState<RpcFailure | null>(null);

  async function execute() {
    if (running.current || !pending.current || lifetime.signal.aborted) return;
    running.current = true;
    setBusy(true);
    setFailure(null);
    try {
      await pending.current();
      lifetime.signal.throwIfAborted();
      toast.success("Saved");
      pending.current = null;
      await client.invalidateQueries({ queryKey: ["integrations", lifetime.generation] });
    } catch (error) {
      if (!lifetime.signal.aborted) {
        const next = toRpcFailure(error);
        if (next.unauthenticated) {
          pending.current = null;
          synchronizeAuthLifetime(null);
          clearCsrfToken();
          client.clear();
          await navigate({ to: "/" });
          return;
        }
        if (!next.ambiguous) pending.current = null;
        setFailure(next);
        const { tone, title } = classifyRpcFailure(next);
        toast[tone === "destructive" ? "error" : tone === "warning" ? "warning" : "message"](
          title,
          {
            description: "Refresh before making another change.",
          },
        );
      }
    } finally {
      running.current = false;
      if (!lifetime.signal.aborted) setBusy(false);
    }
  }

  function perform(operation: () => Promise<unknown>) {
    if (running.current || pending.current || lifetime.signal.aborted) return;
    pending.current = operation;
    void execute();
  }

  return {
    perform,
    blocked: busy || failure?.ambiguous === true,
    feedback: failure ? (
      <RpcError failure={failure}>
        <div className="grid gap-3">
          {failure.ambiguous ? (
            <>
              <p>
                This may have gone through. Try again before making another change; leaving this
                page cancels the retry.
              </p>
              <Button
                className="w-fit"
                variant="outline"
                disabled={busy}
                onClick={() => void execute()}
              >
                Try again
              </Button>
            </>
          ) : null}
        </div>
      </RpcError>
    ) : busy ? (
      <p role="status" className="border bg-muted/30 p-3 text-sm text-muted-foreground">
        Working…
      </p>
    ) : null,
  };
}
