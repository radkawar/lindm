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
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
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
import { ProvisioningTokenResult } from "./token-result";
import { enrollmentFailure, validateEnrollment } from "./validation";

export function ProvisioningTokens() {
  const lifetime = useAuthLifetime();
  const [pageToken, setPageToken] = useState("");
  // Neither the credential nor its response enters a Query/mutation cache.
  const [issued, setIssued] = useState<CreateProvisioningTokenResponse | null>(null);
  const list = useQuery(provisioningTokensQueryOptions(lifetime, pageToken));
  return (
    <section className="grid gap-4" aria-label="Unattended provisioning">
      <IssueProvisioningToken onIssued={setIssued} />
      {issued ? (
        <ProvisioningTokenResult
          key={issued.tokenId}
          result={issued}
          onDismiss={() => setIssued(null)}
        />
      ) : null}
      <Card>
        <CardHeader>
          <CardTitle>Scoped provisioning tokens</CardTitle>
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
          {list.error ? <EnrollmentFailure failure={toRpcFailure(list.error)} /> : null}
          {!list.error && list.data?.tokens.length === 0 ? (
            <p>No tokens in the current scope.</p>
          ) : null}
          {!list.error &&
            list.data?.tokens.map((token) => (
              <TokenRow
                key={token.tokenId}
                token={token}
                onRevoked={() => {
                  if (issued?.tokenId === token.tokenId) setIssued(null);
                }}
              />
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

function IssueProvisioningToken({
  onIssued,
}: {
  onIssued: (result: CreateProvisioningTokenResponse) => void;
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
    <Card>
      <CardHeader>
        <CardTitle>Create unattended provisioning token</CardTitle>
      </CardHeader>
      <CardContent>
        <form
          className="grid gap-4"
          onSubmit={(event) => {
            event.preventDefault();
            void issue(new FormData(event.currentTarget));
          }}
        >
          <p className="text-sm text-muted-foreground">
            Boot-injected, bounded, reusable only within the fixed scope below. The server rechecks
            your current authority for labels, groups and profile assignment; entering an ID grants
            no authority.
          </p>
          <fieldset className="grid gap-3" disabled={busy || captured !== null || completed}>
            <div className="grid gap-3 sm:grid-cols-2">
              <label className="grid gap-1.5 text-sm font-medium">
                Lifetime (seconds)
                <Input name="lifetime" type="number" defaultValue="3600" required />
              </label>
              <label className="grid gap-1.5 text-sm font-medium">
                Maximum uses
                <Input name="maxUses" type="number" defaultValue="1" required />
              </label>
            </div>
            <label className="flex items-start gap-2 text-sm">
              <input name="approval" type="checkbox" defaultChecked />
              Require independent approval before device credentials are issued
            </label>
            <label className="grid gap-1.5 text-sm font-medium">
              Labels (space separated)
              <Input name="labels" />
            </label>
            <Label htmlFor="token-owner-kind">Owner preassignment</Label>
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
              Immutable service profile revision UUID
              <Input name="profile" spellCheck={false} />
            </label>
            <details className="grid gap-2 border p-3">
              <summary className="cursor-pointer text-sm font-medium">
                Typed custom attributes
              </summary>
              <p className="my-2 text-sm text-muted-foreground">
                Protobuf JSON metadata attributes, using existing attribute definitions. Example:{" "}
                {`{"attributes":{"site":{"stringValue":"east"}}}`}. Labels and owner are set by the
                fields above.
              </p>
              <Textarea
                name="metadata"
                aria-label="Typed metadata JSON"
                defaultValue={'{"attributes":{}}'}
                spellCheck={false}
                className="font-mono text-xs"
              />
            </details>
            <label className="grid gap-1.5 text-sm font-medium">
              Audit reason
              <Textarea name="reason" required />
            </label>
          </fieldset>
          {captured ? (
            <p className="break-all text-xs text-muted-foreground">
              Request {captured.requestId}. Retries retain this exact scope and assignments.
            </p>
          ) : null}
          {failure ? <EnrollmentFailure failure={failure} /> : null}
          <div className="flex flex-wrap gap-2">
            <Button type="submit" disabled={busy || completed}>
              {busy ? "Creating…" : captured ? "Retry exact request" : "Create provisioning token"}
            </Button>
            {completed ? (
              <Button
                type="button"
                variant="outline"
                onClick={() => {
                  setCaptured(null);
                  setCompleted(false);
                }}
              >
                Prepare another token
              </Button>
            ) : null}
            {failure?.ambiguous ? (
              <p className="text-sm text-muted-foreground">
                Inspect the token list before replacing this request. A retry can identify the
                token, but cannot recover its secret.
              </p>
            ) : null}
          </div>
        </form>
      </CardContent>
    </Card>
  );
}

function TokenRow({ token, onRevoked }: { token: ProvisioningToken; onRevoked: () => void }) {
  const lifetime = useAuthLifetime();
  const client = useQueryClient();
  const inFlight = useRef(false);
  const [captured, setCaptured] = useState<RevokeProvisioningTokenRequest | null>(null);
  const [busy, setBusy] = useState(false);
  const [revoked, setRevoked] = useState(false);
  const [failure, setFailure] = useState<RpcFailure | null>(null);
  const expired = !token.expiresAt || timestampDate(token.expiresAt).getTime() <= Date.now();
  const state =
    token.revokedAt || revoked
      ? "Revoked"
      : expired
        ? "Expired"
        : token.usedCount >= token.maxUses
          ? "Exhausted"
          : "Available";
  async function revoke(data: FormData) {
    if (inFlight.current || lifetime.signal.aborted) return;
    inFlight.current = true;
    setBusy(true);
    setFailure(null);
    let submitted = false;
    try {
      if (!captured && String(data.get("confirmation") ?? "").trim() !== token.tokenId)
        throw new Error("Retype the exact token ID to confirm revocation.");
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
      onRevoked();
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
        <h3 className="break-all font-mono text-sm">{token.tokenId}</h3>
        <Badge variant="outline">{state}</Badge>
      </div>
      <p className="text-sm">
        {token.usedCount} / {token.maxUses} uses ·{" "}
        {token.approvalRequired ? "Approval required" : "Automatic issuance"} · Expires{" "}
        {formatTimestamp(token.expiresAt).local}
      </p>
      <dl className="grid gap-1 break-all text-sm">
        <dt className="text-muted-foreground">Issued by</dt>
        <dd>{token.createdBy}</dd>
        <dt className="text-muted-foreground">Reason</dt>
        <dd>{token.reason}</dd>
        <dt className="text-muted-foreground">Groups</dt>
        <dd>{token.groupIds.join(", ") || "None"}</dd>
        <dt className="text-muted-foreground">Profile revisions</dt>
        <dd>{token.profileRevisionIds.join(", ") || "None"}</dd>
      </dl>
      {token.metadata ? (
        <details>
          <summary className="cursor-pointer text-sm">Preassigned metadata</summary>
          <pre className="overflow-auto whitespace-pre-wrap break-all text-xs">
            {toJsonString(DeviceMetadataSchema, token.metadata, { prettySpaces: 2 })}
          </pre>
        </details>
      ) : null}
      {!token.revokedAt && !revoked ? (
        <details>
          <summary className="cursor-pointer text-sm font-medium text-destructive">
            Revoke token
          </summary>
          <form
            className="mt-3 grid gap-3"
            onSubmit={(event) => {
              event.preventDefault();
              void revoke(new FormData(event.currentTarget));
            }}
          >
            <fieldset className="grid gap-3" disabled={busy || captured !== null}>
              <label className="grid gap-1.5 text-sm">
                Retype token ID
                <Input name="confirmation" required autoComplete="off" />
              </label>
              <label className="grid gap-1.5 text-sm">
                Revocation reason
                <Textarea name="reason" required />
              </label>
            </fieldset>
            {failure ? <EnrollmentFailure failure={failure} /> : null}
            <Button type="submit" className="w-fit" variant="destructive" disabled={busy}>
              {busy ? "Revoking…" : captured ? "Retry exact revocation" : "Revoke token"}
            </Button>
          </form>
        </details>
      ) : null}
    </article>
  );
}

export function EnrollmentFailure({ failure }: { failure: RpcFailure }) {
  return (
    <Alert variant="destructive">
      <AlertTitle>
        {failure.denied
          ? "Not authorized in current scope"
          : failure.ambiguous
            ? "Outcome unknown"
            : "Request failed"}
      </AlertTitle>
      <AlertDescription>
        {failure.codeName}: {failure.message}
        {failure.ambiguous ? " Retry the same request; do not assume it failed." : ""}
      </AlertDescription>
    </Alert>
  );
}
