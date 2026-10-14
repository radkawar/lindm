// SPDX-License-Identifier: Apache-2.0

import { create } from "@bufbuild/protobuf";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { useEffect, useRef, useState } from "react";
import { toast } from "sonner";
import {
  IssueMCPTokenRequestSchema,
  UpdateMCPSettingsRequestSchema,
  type IssueMCPTokenRequest,
  type IssueMCPTokenResponse,
  type UpdateMCPSettingsRequest,
} from "../../../gen/lindm/auth/v1/mcp_pb";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
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
import { EmptyState } from "@/components/ui/empty-state";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { PageHeader } from "@/components/ui/page-header";
import { RpcError } from "@/components/ui/rpc-error";
import { SelectField } from "@/components/ui/select-field";
import { StatusBadge } from "@/components/ui/status-badge";
import { Timestamp } from "@/components/ui/timestamp";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
import { useExactRequest } from "@/hooks/use-exact-request";
import { usePrincipal } from "@/hooks/use-permissions";
import { toRpcFailure } from "@/lib/errors";
import { formatShortDateTime } from "@/lib/time";
import { issueMCPToken, mcpSettingsQueryOptions, updateMCPSettings } from "./mcp-api";
import { MCPTokenRow } from "./mcp-token-row";

export function MCPAccessSettingsSection() {
  return (
    <section className="grid gap-3 border p-4 sm:p-6" aria-labelledby="assistant-access-heading">
      <h2 id="assistant-access-heading" className="text-base font-semibold">
        Assistant access
      </h2>
      <p className="text-sm text-muted-foreground">
        Let an assistant read fleet evidence or prepare requests for human review.
      </p>
      <Button variant="outline" className="w-fit" render={<Link to="/settings/assistant-access" />}>
        Configure assistant access
      </Button>
    </section>
  );
}

export function MCPAccessView() {
  const lifetime = useAuthLifetime();
  const principal = usePrincipal();
  const client = useQueryClient();
  const query = useQuery(mcpSettingsQueryOptions(lifetime));
  const settings = query.isError ? undefined : query.data;
  const toggle = useExactRequest<UpdateMCPSettingsRequest>();
  const issue = useExactRequest<IssueMCPTokenRequest>();
  const [toggleOpen, setToggleOpen] = useState(false);
  const [enableTarget, setEnableTarget] = useState(false);
  const [issueOpen, setIssueOpen] = useState(false);
  const [label, setLabel] = useState("");
  const [capability, setCapability] = useState("read");
  const [lifetimeSeconds, setLifetimeSeconds] = useState("604800");
  // Neither issuance responses nor their secrets enter a query/mutation cache.
  const [shownOnce, setShownOnce] = useState<IssueMCPTokenResponse | null>(null);
  const issueLabel = useRef("");
  const beforeIssue = useRef(new Set<string>());
  const [issueChecked, setIssueChecked] = useState(false);
  const origin = window.location.origin;
  const connection = JSON.stringify(
    {
      mcpServers: {
        lindm: { url: `${origin}/mcp`, headers: { Authorization: "Bearer <YOUR_TOKEN>" } },
      },
    },
    null,
    2,
  );

  useEffect(() => {
    if (!shownOnce) return;
    const hide = () => setShownOnce(null);
    const timer = window.setTimeout(hide, 5 * 60_000);
    lifetime.signal.addEventListener("abort", hide, { once: true });
    return () => {
      window.clearTimeout(timer);
      lifetime.signal.removeEventListener("abort", hide);
    };
  }, [shownOnce, lifetime.signal]);

  const unusedCandidates =
    settings?.tokens.filter(
      (token) => token.label === issueLabel.current && !beforeIssue.current.has(token.id),
    ) ?? [];
  const canCreate = settings?.enabled && !principal.breakGlass && !toggle.busy;

  async function checkTokens() {
    const result = await query.refetch();
    if (!lifetime.signal.aborted && result.isSuccess) setIssueChecked(true);
  }

  function submitIssue() {
    // Issuance has no replayable plaintext. An uncertain issuance must be checked
    // and its unused token revoked, not resubmitted even with identical fields.
    if (!canCreate || issue.ambiguous || !settings) return;
    void issue.submit({
      capture: () => {
        issueLabel.current = label.trim();
        beforeIssue.current = new Set(settings.tokens.map((token) => token.id));
        setIssueChecked(false);
        return create(IssueMCPTokenRequestSchema, {
          label: issueLabel.current,
          proposalsAllowed: capability === "propose",
          lifetimeSeconds: Number(lifetimeSeconds),
        });
      },
      send: (request, { signal }) => issueMCPToken(request, principal.csrfToken, signal),
      failureTitle: "Couldn't confirm the token",
      onSuccess: (result) => {
        setShownOnce(result);
        setIssueOpen(false);
        setLabel("");
        void client.invalidateQueries({ queryKey: ["mcp-settings", lifetime.generation] });
      },
    });
  }

  return (
    <div className="grid min-w-0 gap-6" data-console-page="assistant-access">
      <PageHeader
        title="Assistant access"
        description="Choose whether assistants can read fleet evidence and prepare requests for human review."
        onRefresh={() => void query.refetch()}
        refreshing={query.isFetching}
      />
      <Alert>
        <AlertTitle>People decide what runs</AlertTitle>
        <AlertDescription>
          <p>
            Assistants can request restarts or rollouts for human review. They cannot run changes,
            wipe devices, or reveal secrets.
          </p>
        </AlertDescription>
      </Alert>
      {query.isPending ? <p role="status">Loading assistant access…</p> : null}
      {query.isError ? (
        <RpcError failure={toRpcFailure(query.error)}>
          <Button variant="outline" onClick={() => void query.refetch()}>
            Retry access check
          </Button>
        </RpcError>
      ) : null}
      {toggle.failure && !toggleOpen ? <RpcError failure={toggle.failure} /> : null}
      {toggle.busy ? (
        <p role="status">Saving the access change. Wait for the result before creating a token.</p>
      ) : null}
      {settings ? (
        <>
          <section
            className="grid gap-3 border p-4 sm:p-6"
            aria-labelledby="deployment-access-heading"
          >
            <div className="flex flex-wrap items-center justify-between gap-3">
              <h2 id="deployment-access-heading" className="text-base font-semibold">
                Access on this server
              </h2>
              <StatusBadge status={settings.enabled ? "info" : "neutral"}>
                {settings.enabled ? "Enabled" : "Disabled"}
              </StatusBadge>
            </div>
            <p className="break-all text-sm text-muted-foreground">{origin}</p>
            <p className="text-xs text-muted-foreground">
              Last checked{" "}
              <time dateTime={new Date(query.dataUpdatedAt).toISOString()}>
                {formatShortDateTime(new Date(query.dataUpdatedAt), new Date())}
              </time>
            </p>
            <p className="text-sm">
              {settings.enabled
                ? "Assistants can connect with a token or an authorized browser session. Your current permissions and device scope still apply."
                : "This server refuses all assistant connections. Turning access on does not add permissions to any account."}
            </p>
            <Dialog open={toggleOpen} onOpenChange={setToggleOpen}>
              <DialogTrigger
                render={
                  <Button variant={settings.enabled ? "outline" : "default"} className="w-fit" />
                }
                onClick={() => {
                  if (!toggle.ambiguous) setEnableTarget(!settings.enabled);
                }}
              >
                {toggle.ambiguous
                  ? "Review uncertain change"
                  : settings.enabled
                    ? "Disable access"
                    : "Enable access"}
              </DialogTrigger>
              <DialogContent>
                <DialogHeader>
                  <DialogTitle>
                    {enableTarget ? "Enable assistant access?" : "Disable assistant access?"}
                  </DialogTitle>
                  <DialogDescription className="break-all">{origin}</DialogDescription>
                </DialogHeader>
                <p>
                  {enableTarget
                    ? "This affects the whole server. Assistants can read permitted evidence and prepare requests, but people must review them."
                    : "This stops all assistant connections, including tokens and browser sessions. Existing tokens remain until you revoke them or they expire."}
                </p>
                {toggle.failure ? <RpcError failure={toggle.failure} /> : null}
                <DialogFooter>
                  <Button variant="outline" onClick={() => setToggleOpen(false)}>
                    Cancel
                  </Button>
                  <Button
                    disabled={toggle.busy || issue.busy}
                    onClick={() =>
                      void toggle.submit({
                        capture: () =>
                          create(UpdateMCPSettingsRequestSchema, { enabled: enableTarget }),
                        send: (request, { signal }) =>
                          updateMCPSettings(request, principal.csrfToken, signal),
                        failureTitle: "Couldn't confirm the access change",
                        onSuccess: (result) => {
                          client.setQueryData(mcpSettingsQueryOptions(lifetime).queryKey, result);
                          setToggleOpen(false);
                          toast.success(
                            result.enabled
                              ? "Assistant access enabled"
                              : "Assistant access disabled",
                          );
                        },
                      })
                    }
                  >
                    {toggle.busy
                      ? "Saving…"
                      : toggle.ambiguous
                        ? "Retry same change"
                        : enableTarget
                          ? "Enable access"
                          : "Disable access"}
                  </Button>
                </DialogFooter>
              </DialogContent>
            </Dialog>
          </section>
          <section className="grid gap-4" aria-labelledby="your-assistant-tokens-heading">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <h2 id="your-assistant-tokens-heading" className="text-base font-semibold">
                Your tokens
              </h2>
              <Dialog open={issueOpen} onOpenChange={setIssueOpen}>
                <DialogTrigger
                  render={<Button disabled={!canCreate || issue.busy || issue.ambiguous} />}
                >
                  Create token
                </DialogTrigger>
                <DialogContent className="max-h-[calc(100dvh-2rem)] overflow-y-auto sm:max-w-lg">
                  <form
                    className="grid gap-4"
                    onSubmit={(event) => {
                      event.preventDefault();
                      submitIssue();
                    }}
                  >
                    <DialogHeader>
                      <DialogTitle>Create an assistant token</DialogTitle>
                      <DialogDescription>
                        Your current permissions and device scope limit this token. It cannot grant
                        additional access.
                      </DialogDescription>
                    </DialogHeader>
                    <fieldset className="grid gap-4" disabled={issue.busy || issue.ambiguous}>
                      <div className="grid gap-2">
                        <Label htmlFor="mcp-token-label">New token name</Label>
                        <Input
                          id="mcp-token-label"
                          data-freeform="A new name for this assistant connection"
                          required
                          value={label}
                          onChange={(event) => setLabel(event.target.value)}
                        />
                      </div>
                      <div className="grid gap-2">
                        <Label htmlFor="mcp-token-access">Access</Label>
                        <SelectField
                          id="mcp-token-access"
                          value={capability}
                          onValueChange={setCapability}
                          options={[
                            { value: "read", label: "Read only" },
                            { value: "propose", label: "Read and request human review" },
                          ]}
                        />
                        <p className="text-sm text-muted-foreground">
                          Review requests never run changes or approve themselves.
                        </p>
                      </div>
                      <div className="grid gap-2">
                        <Label htmlFor="mcp-token-lifetime">Expires after</Label>
                        <SelectField
                          id="mcp-token-lifetime"
                          value={lifetimeSeconds}
                          onValueChange={setLifetimeSeconds}
                          options={[
                            { value: "86400", label: "1 day" },
                            { value: "604800", label: "7 days" },
                            { value: "2592000", label: "30 days" },
                          ]}
                        />
                      </div>
                    </fieldset>
                    {issue.failure ? <RpcError failure={issue.failure} /> : null}
                    <DialogFooter>
                      <Button type="button" variant="outline" onClick={() => setIssueOpen(false)}>
                        Cancel
                      </Button>
                      <Button type="submit" disabled={!canCreate || issue.busy || issue.ambiguous}>
                        {issue.busy ? "Creating…" : "Create token"}
                      </Button>
                    </DialogFooter>
                  </form>
                </DialogContent>
              </Dialog>
            </div>
            <p className="text-sm text-muted-foreground">
              Only your active tokens appear here. Each token expires within 30 days.
            </p>
            {issue.busy ? (
              <p role="status">Creating a token. Wait for the result before creating another.</p>
            ) : null}
            {principal.breakGlass ? (
              <p className="text-sm">
                Emergency sessions cannot create or use assistant tokens. Use your regular account.
              </p>
            ) : !settings.enabled ? (
              <p className="text-sm">
                Enable access before creating a token. Existing tokens cannot connect while access
                remains off.
              </p>
            ) : null}
            {issue.failure && !issueOpen ? <RpcError failure={issue.failure} /> : null}
            {issue.ambiguous ? (
              <Alert className="border-warning/25 bg-warning/10">
                <AlertTitle>Check the token before creating another</AlertTitle>
                <AlertDescription className="text-foreground">
                  <p>
                    We could not confirm “{issueLabel.current}”. We cannot retrieve its secret
                    again.
                  </p>
                  <p>
                    Refresh your tokens. Revoke any new, unused token with this name before creating
                    another.
                  </p>
                  <div className="flex flex-wrap gap-2">
                    <Button
                      variant="outline"
                      disabled={query.isFetching}
                      onClick={() => void checkTokens()}
                    >
                      Refresh tokens
                    </Button>
                    <Button
                      variant="outline"
                      disabled={!issueChecked || query.isFetching || unusedCandidates.length > 0}
                      onClick={() => {
                        issue.reset();
                        setIssueChecked(false);
                        setIssueOpen(false);
                      }}
                    >
                      I checked unused tokens
                    </Button>
                  </div>
                </AlertDescription>
              </Alert>
            ) : null}
            {!settings.tokens.length ? (
              <EmptyState
                title="No active assistant tokens"
                description="Create a token when you are ready to connect an assistant."
              />
            ) : null}
            <ul className="grid gap-3" aria-label="Your assistant tokens">
              {settings.tokens.map((token) => (
                <MCPTokenRow key={token.id} token={token} enabled={settings.enabled} />
              ))}
            </ul>
          </section>
          <section
            className="grid min-w-0 gap-3 border p-4 sm:p-6"
            aria-labelledby="assistant-connection-heading"
          >
            <h2 id="assistant-connection-heading" className="text-base font-semibold">
              Connection settings
            </h2>
            <p className="text-sm text-muted-foreground">
              Paste these settings into your assistant client. Replace the token placeholder in that
              client, not in this console.
            </p>
            <pre
              className="max-w-full overflow-x-auto border bg-muted p-3 text-xs outline-none focus-visible:ring-2 focus-visible:ring-ring"
              aria-label="Assistant connection settings"
              role="region"
              tabIndex={0}
            >
              <code>{connection}</code>
            </pre>
            <Button
              variant="outline"
              className="w-fit"
              onClick={() => {
                navigator.clipboard.writeText(connection).then(
                  () => toast.success("Connection settings copied"),
                  () => toast.error("Couldn't copy. Select the settings and copy them instead."),
                );
              }}
            >
              Copy connection settings
            </Button>
          </section>
        </>
      ) : null}
      <Dialog
        open={shownOnce !== null}
        onOpenChange={(open) => {
          if (!open) setShownOnce(null);
        }}
      >
        <DialogContent className="max-h-[calc(100dvh-2rem)] overflow-y-auto sm:max-w-lg">
          <DialogHeader>
            <DialogTitle>Copy your token now</DialogTitle>
            <DialogDescription>
              We show this token once. Closing this dialog hides it; the console does not store it.
            </DialogDescription>
          </DialogHeader>
          {shownOnce ? (
            <div className="grid min-w-0 gap-3" data-revealed-secret>
              <p className="break-words font-medium">{shownOnce.token?.label}</p>
              <p className="text-sm">
                Expires <Timestamp value={shownOnce.token?.expiresAt} />. Hides automatically in
                five minutes.
              </p>
              <Input
                aria-label="Assistant token"
                data-sensitive="true"
                readOnly
                value={shownOnce.bearerToken}
                className="font-mono"
              />
              <p className="text-sm">
                Keep it in your assistant client's secure credential settings. Anyone with this
                token can use its selected access within your current permissions.
              </p>
              <DialogFooter>
                <Button variant="outline" onClick={() => setShownOnce(null)}>
                  Hide token
                </Button>
                <Button
                  onClick={() => {
                    navigator.clipboard.writeText(shownOnce.bearerToken).then(
                      () => toast.success("Assistant token copied"),
                      () => toast.error("Couldn't copy. Select the token and copy it instead."),
                    );
                  }}
                >
                  Copy token
                </Button>
              </DialogFooter>
            </div>
          ) : null}
        </DialogContent>
      </Dialog>
    </div>
  );
}
