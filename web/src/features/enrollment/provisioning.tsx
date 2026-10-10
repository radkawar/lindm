import { create, fromJsonString, toJsonString } from "@bufbuild/protobuf";
import { timestampDate } from "@bufbuild/protobuf/wkt";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useRef, useState } from "react";
import {
  CreateProvisioningTokenRequestSchema,
  RevokeProvisioningTokenRequestSchema,
  type CreateProvisioningTokenRequest,
  type CreateProvisioningTokenResponse,
  type ProvisioningToken,
  type RevokeProvisioningTokenRequest,
} from "../../../gen/lindm/admin/v1/provisioning_pb";
import { DeviceMetadataSchema } from "../../../gen/lindm/admin/v1/inventory_management_pb";
import { EmptyState } from "@/components/ui/empty-state";
import { RpcError } from "@/components/ui/rpc-error";
import { StatusBadge } from "@/components/ui/status-badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { SelectField } from "@/components/ui/select-field";
import { Textarea } from "@/components/ui/textarea";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
import { toRpcFailure, type RpcFailure } from "@/lib/errors";
import { newRequestId } from "@/lib/ids";
import { adminClient } from "@/lib/rpc";
import { formatTimestamp } from "@/lib/time";
import { provisioningTokensQueryOptions } from "./queries";
import { enrollmentFailure, validateEnrollment } from "./validation";

export function ProvisioningTokens() {
  const lifetime = useAuthLifetime();
  const [pageToken, setPageToken] = useState("");
  const list = useQuery(provisioningTokensQueryOptions(lifetime, pageToken));
  return (
    <section className="grid gap-4" aria-label="Provisioning tokens">
      <Card>
        <CardHeader>
          <CardTitle>Provisioning tokens</CardTitle>
        </CardHeader>
        <CardContent className="grid gap-4">
          <p className="text-sm text-muted-foreground">
            Current server-visible scope only. Assignments are fixed at issuance; expiry and use
            limits bound new enrollments. Revocation stops further redemption, not already enrolled
            devices.
          </p>
          <Button
            className="w-fit"
            variant="outline"
            disabled={list.isFetching}
            onClick={() => void list.refetch()}
          >
            Refresh tokens
          </Button>
          {list.isPending ? <p role="status">Loading tokens…</p> : null}
          {list.error ? <RpcError failure={toRpcFailure(list.error)} /> : null}
          {!list.error && list.data?.tokens.length === 0 ? (
            <EmptyState title="No provisioning tokens in your scope" />
          ) : null}
          {list.error && list.data ? (
            <p className="text-sm text-muted-foreground">
              Showing the last loaded tokens. Refresh to get their current status.
            </p>
          ) : null}
          {list.data?.tokens.map((token) => (
            <TokenRow key={token.tokenId} token={token} />
          ))}
          <div className="flex gap-2">
            <Button
              variant="outline"
              disabled={!pageToken || list.isFetching}
              onClick={() => setPageToken("")}
            >
              First page
            </Button>
            <Button
              variant="outline"
              disabled={!list.data?.nextPageToken || list.isFetching}
              onClick={() => setPageToken(list.data?.nextPageToken ?? "")}
            >
              Next page
            </Button>
          </div>
        </CardContent>
      </Card>
    </section>
  );
}

export function IssueProvisioningToken({
  onIssued,
  onCancel,
}: {
  onIssued: (result: CreateProvisioningTokenResponse) => void;
  onCancel?: () => void;
}) {
  const lifetime = useAuthLifetime();
  const client = useQueryClient();
  const inFlight = useRef(false);
  const [captured, setCaptured] = useState<CreateProvisioningTokenRequest | null>(null);
  const [busy, setBusy] = useState(false);
  const [completed, setCompleted] = useState(false);
  const [ownerKind, setOwnerKind] = useState("");
  const [failure, setFailure] = useState<RpcFailure | null>(null);

  async function issue(data: FormData) {
    if (inFlight.current || lifetime.signal.aborted || completed) return;
    inFlight.current = true;
    setBusy(true);
    setFailure(null);
    let submitted = false;
    try {
      let request = captured;
      if (!request) {
        const metadata = fromJsonString(DeviceMetadataSchema, String(data.get("metadata") || "{}"));
        metadata.labels = String(data.get("labels") ?? "")
          .split(/\s+/)
          .filter(Boolean);
        const owner = String(data.get("owner") ?? "").trim();
        metadata.owner =
          ownerKind === "ownerPrincipalId"
            ? { case: "ownerPrincipalId", value: owner }
            : ownerKind === "ownerText"
              ? { case: "ownerText", value: owner }
              : { case: undefined };
        request = create(CreateProvisioningTokenRequestSchema, {
          requestId: newRequestId(),
          lifetimeSeconds: Number(data.get("lifetime")),
          maxUses: Number(data.get("maxUses")),
          approvalRequired: data.get("approval") === "on",
          reason: String(data.get("reason") ?? "").trim(),
          metadata,
          groupIds: String(data.get("groups") ?? "")
            .split(/\s+/)
            .filter(Boolean),
          profileRevisionIds: String(data.get("profile") ?? "")
            .split(/\s+/)
            .filter(Boolean),
        });
        validateEnrollment(CreateProvisioningTokenRequestSchema, request);
        setCaptured(request);
      }
      submitted = true;
      const result = await adminClient.createProvisioningToken(request, {
        signal: lifetime.signal,
        timeoutMs: 30_000,
      });
      lifetime.signal.throwIfAborted();
      if (!result.tokenId)
        throw new Error(
          "The server returned no token ID. Inspect the list and retry this exact request; do not assume issuance failed.",
        );
      onIssued(result);
      setCompleted(true);
      void client.invalidateQueries({ queryKey: ["provisioning-tokens", lifetime.generation] });
    } catch (error) {
      if (!lifetime.signal.aborted) {
        const next = enrollmentFailure(error, submitted);
        setFailure(next);
        if (!next.ambiguous) setCaptured(null);
      }
    } finally {
      inFlight.current = false;
      if (!lifetime.signal.aborted) setBusy(false);
    }
  }

  return (
    <form
      className="grid gap-4"
      onSubmit={(event) => {
        event.preventDefault();
        void issue(new FormData(event.currentTarget));
      }}
    >
      <DialogHeader>
        <DialogTitle>Automatic enrollment (provisioning token)</DialogTitle>
        <DialogDescription>
          Enroll a fleet during installation with a reusable token bounded by expiry and use limit.
        </DialogDescription>
      </DialogHeader>
      <fieldset className="grid gap-4" disabled={busy || captured !== null || completed}>
        <label className="grid gap-1.5 text-sm font-medium">
          Purpose / audit reason
          <Textarea name="reason" placeholder="For example, October laptop deployment" required />
        </label>
        <div className="grid gap-3 sm:grid-cols-2">
          <div className="grid gap-1.5">
            <Label htmlFor="token-lifetime">Expires after</Label>
            <SelectField
              id="token-lifetime"
              name="lifetime"
              defaultValue="86400"
              disabled={busy || captured !== null || completed}
              required
              options={[
                { value: "3600", label: "1 hour" },
                { value: "14400", label: "4 hours" },
                { value: "43200", label: "12 hours" },
                { value: "86400", label: "24 hours" },
              ]}
            />
          </div>
          <label className="grid gap-1.5 text-sm font-medium">
            Maximum uses
            <Input name="maxUses" type="number" defaultValue="100" required />
          </label>
        </div>
        <label className="flex items-start gap-2 text-sm">
          <input name="approval" type="checkbox" defaultChecked />
          Require independent approval before device credentials are issued
        </label>
        <details className="border p-3">
          <summary className="cursor-pointer text-sm font-medium">Advanced assignments</summary>
          <div className="mt-3 grid gap-3">
            <p className="text-sm text-muted-foreground">
              Assignments are fixed at issuance. Choose only labels, groups and profiles you are
              authorized to manage.
            </p>
            <label className="grid gap-1.5 text-sm font-medium">
              Labels (space separated)
              <Input name="labels" />
            </label>
            <Label htmlFor="token-owner-kind">Assign owner</Label>
            <SelectField
              id="token-owner-kind"
              value={ownerKind}
              disabled={busy || captured !== null || completed}
              onValueChange={setOwnerKind}
              options={[
                { value: "", label: "Unassigned" },
                { value: "ownerText", label: "Owner name" },
                { value: "ownerPrincipalId", label: "Owner principal UUID" },
              ]}
            />
            {ownerKind ? (
              <label className="grid gap-1.5 text-sm font-medium">
                Owner
                <Input name="owner" required />
              </label>
            ) : null}
            <label className="grid gap-1.5 text-sm font-medium">
              Static group UUIDs (space separated)
              <Textarea name="groups" spellCheck={false} />
            </label>
            <label className="grid gap-1.5 text-sm font-medium">
              Service profile revision ID
              <Input name="profile" spellCheck={false} />
            </label>
            <label className="grid gap-1.5 text-sm font-medium">
              Custom attributes (protobuf JSON)
              <Textarea
                name="metadata"
                defaultValue={'{"attributes":{}}'}
                spellCheck={false}
                className="font-mono text-xs"
              />
            </label>
            <p className="text-sm text-muted-foreground">
              Use existing attribute definitions. Example:{" "}
              {`{"attributes":{"site":{"stringValue":"east"}}}`}. Labels and owner come from the
              fields above.
            </p>
          </div>
        </details>
      </fieldset>
      {captured ? (
        <details className="text-xs text-muted-foreground">
          <summary className="cursor-pointer">Request details</summary>
          <p className="mt-2 break-all">
            Request {captured.requestId}. Retries retain this exact scope and assignments.
          </p>
        </details>
      ) : null}
      {failure ? <RpcError failure={failure} /> : null}
      {failure?.ambiguous ? (
        <p className="text-sm text-muted-foreground">
          The token may have been created. Retry this exact request to resolve its status; a retry
          cannot recover its secret.
        </p>
      ) : null}
      <div className="flex flex-wrap gap-2">
        <Button type="submit" disabled={busy || completed}>
          {busy ? "Creating…" : captured ? "Retry exact request" : "Create provisioning token"}
        </Button>
        {onCancel ? (
          <Button
            type="button"
            variant="outline"
            disabled={busy || (captured !== null && !completed)}
            onClick={onCancel}
          >
            Cancel
          </Button>
        ) : null}
      </div>
    </form>
  );
}

function TokenRow({ token }: { token: ProvisioningToken }) {
  const lifetime = useAuthLifetime();
  const client = useQueryClient();
  const inFlight = useRef(false);
  const [captured, setCaptured] = useState<RevokeProvisioningTokenRequest | null>(null);
  const [busy, setBusy] = useState(false);
  const [revoked, setRevoked] = useState(false);
  const [open, setOpen] = useState(false);
  const [failure, setFailure] = useState<RpcFailure | null>(null);
  const expired = !token.expiresAt || timestampDate(token.expiresAt).getTime() <= Date.now();
  const state =
    token.revokedAt || revoked
      ? "Revoked"
      : expired
        ? "Expired"
        : token.usedCount >= token.maxUses
          ? "Used"
          : "Active";
  async function revoke(data: FormData) {
    if (inFlight.current || lifetime.signal.aborted) return;
    inFlight.current = true;
    setBusy(true);
    setFailure(null);
    let submitted = false;
    try {
      const request =
        captured ??
        create(RevokeProvisioningTokenRequestSchema, {
          requestId: newRequestId(),
          tokenId: token.tokenId,
          reason: String(data.get("reason") ?? "").trim(),
        });
      validateEnrollment(RevokeProvisioningTokenRequestSchema, request);
      setCaptured(request);
      submitted = true;
      await adminClient.revokeProvisioningToken(request, {
        signal: lifetime.signal,
        timeoutMs: 30_000,
      });
      lifetime.signal.throwIfAborted();
      setRevoked(true);
      setOpen(false);
      void client.invalidateQueries({ queryKey: ["provisioning-tokens", lifetime.generation] });
      void client.invalidateQueries({ queryKey: ["pending-enrollments", lifetime.generation] });
    } catch (error) {
      if (!lifetime.signal.aborted) {
        const next = enrollmentFailure(error, submitted);
        setFailure(next);
        if (!next.ambiguous) setCaptured(null);
      }
    } finally {
      inFlight.current = false;
      if (!lifetime.signal.aborted) setBusy(false);
    }
  }
  return (
    <article className="grid gap-3 border p-4">
      <div className="flex flex-wrap justify-between gap-2">
        <h3 className="min-w-0 break-words text-sm font-medium">
          {token.reason || "Provisioning token"}
        </h3>
        <StatusBadge
          status={state === "Active" ? "success" : state === "Revoked" ? "destructive" : "neutral"}
        >
          {state}
        </StatusBadge>
      </div>
      <p className="text-sm">
        {token.usedCount} / {token.maxUses} uses · Expires {formatTimestamp(token.expiresAt).local}
      </p>
      <p className="text-sm text-muted-foreground">
        Created by {token.creatorDisplayName || "unavailable"} ·{" "}
        {token.approvalRequired ? "Independent approval required" : "No independent approval"}
      </p>
      <details>
        <summary className="cursor-pointer text-sm">Details</summary>
        <dl className="mt-3 grid gap-1 break-all text-sm">
          <dt className="text-muted-foreground">Credential type</dt>
          <dd>Reusable provisioning token</dd>
          <dt className="text-muted-foreground">Token ID</dt>
          <dd className="font-mono text-xs">{token.tokenId}</dd>
          <dt className="text-muted-foreground">Creator principal ID</dt>
          <dd className="font-mono text-xs">{token.createdBy || "Unavailable"}</dd>
          <dt className="text-muted-foreground">Created</dt>
          <dd>{formatTimestamp(token.createdAt).local}</dd>
          {token.revokedAt ? (
            <>
              <dt className="text-muted-foreground">Revoked</dt>
              <dd>{formatTimestamp(token.revokedAt).local}</dd>
            </>
          ) : null}
          <dt className="text-muted-foreground">Group IDs</dt>
          <dd>{token.groupIds.join(", ") || "None"}</dd>
          <dt className="text-muted-foreground">Profile revision IDs</dt>
          <dd>{token.profileRevisionIds.join(", ") || "None"}</dd>
          <dt className="text-muted-foreground">Assigned metadata</dt>
          <dd>
            {token.metadata ? (
              <pre className="overflow-auto whitespace-pre-wrap break-all text-xs">
                {toJsonString(DeviceMetadataSchema, token.metadata, { prettySpaces: 2 })}
              </pre>
            ) : (
              "None"
            )}
          </dd>
        </dl>
      </details>
      <Dialog
        open={open}
        onOpenChange={(next) => {
          if (!next && (busy || (captured !== null && !revoked))) return;
          setOpen(next);
        }}
      >
        {!token.revokedAt && !revoked ? (
          <DialogTrigger render={<Button className="w-fit" variant="outline" />}>
            Revoke provisioning token
          </DialogTrigger>
        ) : null}
        <DialogContent
          keepMounted
          showCloseButton={!busy && (captured === null || revoked)}
          className="sm:max-w-lg"
        >
          <DialogHeader>
            <DialogTitle>Revoke provisioning token?</DialogTitle>
            <DialogDescription>
              Stop new enrollments using this reusable provisioning token. Already enrolled devices
              are not revoked.
            </DialogDescription>
          </DialogHeader>
          <p className="break-words text-sm font-medium">{token.reason || "Provisioning token"}</p>
          <form
            className="grid gap-3"
            onSubmit={(event) => {
              event.preventDefault();
              void revoke(new FormData(event.currentTarget));
            }}
          >
            <fieldset className="grid gap-3" disabled={busy || captured !== null || revoked}>
              <label className="grid gap-1.5 text-sm">
                Revocation reason
                <Textarea name="reason" required />
              </label>
            </fieldset>
            {captured ? (
              <details className="text-xs text-muted-foreground">
                <summary className="cursor-pointer">Request details</summary>
                <p className="mt-2 break-all">
                  Request {captured.requestId}. Token {captured.tokenId}.
                </p>
              </details>
            ) : null}
            {failure ? <RpcError failure={failure} /> : null}
            {failure?.ambiguous ? (
              <p className="text-sm text-muted-foreground">
                Revocation may have succeeded. Retry the exact request to resolve its status.
              </p>
            ) : null}
            <div className="flex flex-wrap gap-2">
              <Button type="submit" variant="destructive" disabled={busy || revoked}>
                {busy
                  ? "Revoking…"
                  : captured
                    ? "Retry exact revocation"
                    : "Revoke provisioning token"}
              </Button>
              <Button
                type="button"
                variant="outline"
                disabled={busy || (captured !== null && !revoked)}
                onClick={() => setOpen(false)}
              >
                Cancel
              </Button>
            </div>
          </form>
        </DialogContent>
      </Dialog>
    </article>
  );
}
