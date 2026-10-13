import { create } from "@bufbuild/protobuf";
import { useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import {
  RevokeMCPTokenRequestSchema,
  type MCPToken,
  type RevokeMCPTokenRequest,
} from "../../../gen/lindm/auth/v1/mcp_pb";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { RpcError } from "@/components/ui/rpc-error";
import { StatusBadge } from "@/components/ui/status-badge";
import { TechnicalDetails } from "@/components/ui/technical-details";
import { Timestamp } from "@/components/ui/timestamp";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
import { useExactRequest } from "@/hooks/use-exact-request";
import { usePrincipal } from "@/hooks/use-permissions";
import { revokeMCPToken } from "./mcp-api";

export function MCPTokenRow({ token, enabled }: { token: MCPToken; enabled: boolean }) {
  const lifetime = useAuthLifetime();
  const principal = usePrincipal();
  const client = useQueryClient();
  const revoke = useExactRequest<RevokeMCPTokenRequest>();
  const [open, setOpen] = useState(false);
  return (
    <li className="grid min-w-0 gap-3 border p-4" data-mcp-token-row>
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="grid min-w-0 gap-1">
          <h3 className="break-words font-medium">{token.label || "Unnamed assistant token"}</h3>
          <p className="text-sm">
            {token.proposalsAllowed ? "Read and request human review" : "Read only"}
          </p>
        </div>
        <p>
          <StatusBadge status={enabled ? "info" : "neutral"}>
            {enabled ? "Available" : "Access paused"}
          </StatusBadge>
        </p>
      </div>
      <dl className="grid gap-x-6 gap-y-2 text-sm sm:grid-cols-2">
        <div>
          <dt className="text-muted-foreground">Created</dt>
          <dd>
            <Timestamp value={token.createdAt} />
          </dd>
        </div>
        <div>
          <dt className="text-muted-foreground">Expires</dt>
          <dd>
            <Timestamp value={token.expiresAt} />
          </dd>
        </div>
      </dl>
      <div className="flex flex-wrap items-center justify-between gap-3">
        <TechnicalDetails items={[{ label: "Token ID", value: token.id }]} />
        <Dialog open={open} onOpenChange={setOpen}>
          <DialogTrigger render={<Button variant="outline" size="sm" />}>
            {revoke.ambiguous ? "Review uncertain revocation" : "Revoke token"}
          </DialogTrigger>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Revoke assistant token?</DialogTitle>
              <DialogDescription className="break-words">
                {token.label || "Unnamed assistant token"}
              </DialogDescription>
            </DialogHeader>
            <p>
              This stops new connections using this token. It does not revoke other tokens or cancel
              existing review requests.
            </p>
            <p>You cannot restore this token. Create another if you need access again.</p>
            {revoke.failure ? <RpcError failure={revoke.failure} /> : null}
            <DialogFooter>
              <Button variant="outline" onClick={() => setOpen(false)}>
                Cancel
              </Button>
              <Button
                variant="destructive"
                className="text-foreground"
                disabled={revoke.busy}
                onClick={() =>
                  void revoke.submit({
                    capture: () => create(RevokeMCPTokenRequestSchema, { tokenId: token.id }),
                    send: (request, { signal }) =>
                      revokeMCPToken(request, principal.csrfToken, signal),
                    failureTitle: "Couldn't confirm the revocation",
                    onSuccess: () => {
                      setOpen(false);
                      void client.invalidateQueries({
                        queryKey: ["mcp-settings", lifetime.generation],
                      });
                    },
                  })
                }
              >
                {revoke.busy
                  ? "Revoking…"
                  : revoke.ambiguous
                    ? "Retry same revocation"
                    : "Revoke token"}
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      </div>
      {revoke.failure && !open ? <RpcError failure={revoke.failure} /> : null}
    </li>
  );
}
