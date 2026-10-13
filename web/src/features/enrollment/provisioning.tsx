import { create, toJsonString } from "@bufbuild/protobuf";
import { timestampDate } from "@bufbuild/protobuf/wkt";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useRef, useState, type ReactNode } from "react";
import {
  CreateProvisioningTokenRequestSchema,
  RevokeProvisioningTokenRequestSchema,
  type CreateProvisioningTokenRequest,
  type CreateProvisioningTokenResponse,
  type ProvisioningToken,
  type RevokeProvisioningTokenRequest,
} from "../../../gen/lindm/admin/v1/provisioning_pb";
import {
  DeviceMetadataSchema,
  type AttributeValue,
} from "../../../gen/lindm/admin/v1/inventory_management_pb";
import { SuggestionField } from "../../../gen/lindm/admin/v1/suggestions_pb";
import { EmptyState } from "@/components/ui/empty-state";
import { RpcError } from "@/components/ui/rpc-error";
import { StatusBadge } from "@/components/ui/status-badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { SelectField } from "@/components/ui/select-field";
import { ListPagination } from "@/components/ui/list-pagination";
import { MultiPicker, type PickerProps, type PickerSlot } from "@/components/ui/search-picker";
import { SuggestionPicker } from "@/components/ui/suggestion-picker";
import { TechnicalDetails } from "@/components/ui/technical-details";
import { Textarea } from "@/components/ui/textarea";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
import { toRpcFailure, type RpcFailure } from "@/lib/errors";
import { newRequestId } from "@/lib/ids";
import { adminClient } from "@/lib/rpc";
import { formatTimestamp } from "@/lib/time";
import { provisioningTokensQueryOptions } from "./queries";
import { enrollmentFailure } from "./validation";
import { validateRequest } from "@/lib/validation";

// Device-attribute editing is owned by the devices feature; routes compose it in.
export type AttributeFieldsSlot = (props: {
  attributes: Record<string, AttributeValue>;
  onChange: (attributes: Record<string, AttributeValue>) => void;
  disabled?: boolean;
  legend?: string;
}) => ReactNode;
export type AttributeReader = (
  data: FormData,
  attributes: Record<string, AttributeValue>,
) => Record<string, AttributeValue>;

// Labels devices report today, or a new label for the devices this token enrolls.
function DeviceLabelPicker(props: PickerProps) {
  return (
    <SuggestionPicker
      {...props}
      field={SuggestionField.DEVICE_LABEL}
      allowTyped
      typedDescription="New label; no device has it yet"
    />
  );
}

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
            Reusable tokens for enrolling many devices. Revoking a token stops new enrollments only.
          </p>
          {list.isPending ? <p role="status">Loading tokens…</p> : null}
          {list.error ? <RpcError failure={toRpcFailure(list.error)} /> : null}
          {!list.error && list.data?.tokens.length === 0 ? (
            <EmptyState title="No provisioning tokens yet" />
          ) : null}
          {list.error && list.data ? (
            <p className="text-sm text-muted-foreground">
              Showing the last loaded tokens. Refresh to get their current status.
            </p>
          ) : null}
          {list.data?.tokens.map((token) => (
            <TokenRow key={token.tokenId} token={token} />
          ))}
          <ListPagination
            label="Provisioning token pages"
            busy={list.isFetching}
            onPrevious={pageToken ? () => setPageToken("") : undefined}
            onNext={
              list.data?.nextPageToken
                ? () => setPageToken(list.data?.nextPageToken ?? "")
                : undefined
            }
          />
        </CardContent>
      </Card>
    </section>
  );
}

export function IssueProvisioningToken({
  onIssued,
  onCancel,
  accountPicker: AccountPicker,
  groupPicker,
  profileRevisionPicker,
  attributeFields: AttributeFields,
  readAttributes,
}: {
  onIssued: (result: CreateProvisioningTokenResponse) => void;
  onCancel?: () => void;
  accountPicker: PickerSlot;
  groupPicker: PickerSlot;
  profileRevisionPicker: PickerSlot;
  attributeFields: AttributeFieldsSlot;
  readAttributes: AttributeReader;
}) {
  const lifetime = useAuthLifetime();
  const client = useQueryClient();
  const inFlight = useRef(false);
  const [captured, setCaptured] = useState<CreateProvisioningTokenRequest | null>(null);
  const [busy, setBusy] = useState(false);
  const [completed, setCompleted] = useState(false);
  const [ownerKind, setOwnerKind] = useState("");
  const [ownerAccount, setOwnerAccount] = useState("");
  const [labels, setLabels] = useState<string[]>([]);
  const [groupIds, setGroupIds] = useState<string[]>([]);
  const [profileRevisionIds, setProfileRevisionIds] = useState<string[]>([]);
  const [attributes, setAttributes] = useState<Record<string, AttributeValue>>({});
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
        const metadata = create(DeviceMetadataSchema, {
          labels: labels.filter(Boolean),
          attributes: readAttributes(data, attributes),
        });
        const owner = String(data.get("owner") ?? "").trim();
        metadata.owner =
          ownerKind === "ownerPrincipalId"
            ? { case: "ownerPrincipalId", value: ownerAccount }
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
          groupIds: groupIds.filter(Boolean),
          profileRevisionIds: profileRevisionIds.filter(Boolean),
        });
        validateRequest(CreateProvisioningTokenRequestSchema, request);
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
          "The server did not confirm token creation. Check the list before you retry.",
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
    // The body scrolls; the header and the Create/Cancel footer stay in view.
    <form
      className="flex min-h-0 flex-1 flex-col"
      onSubmit={(event) => {
        event.preventDefault();
        void issue(new FormData(event.currentTarget));
      }}
    >
      <DialogHeader className="p-4 pr-12">
        <DialogTitle>Create a provisioning token</DialogTitle>
        <DialogDescription>
          This reusable token enrolls devices during installation. It stops working when it expires
          or reaches its use limit.
        </DialogDescription>
      </DialogHeader>
      <div className="grid min-h-0 flex-1 gap-4 overflow-y-auto px-4 pb-4">
        <fieldset className="grid gap-4" disabled={busy || captured !== null || completed}>
          <label className="grid gap-1.5 text-sm font-medium">
            Purpose / audit reason
            <Textarea
              name="reason"
              data-freeform="audit reason describing the deployment"
              placeholder="For example, October laptop deployment"
              required
            />
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
              <Input
                name="maxUses"
                type="number"
                data-freeform="numeric use limit (1 to 10,000)"
                min={1}
                max={10000}
                defaultValue="100"
                required
              />
            </label>
          </div>
          <label className="flex items-start gap-2 text-sm">
            <input name="approval" type="checkbox" defaultChecked />
            Require another admin to approve each device
          </label>
          <details className="border p-3">
            <summary className="cursor-pointer text-sm font-medium">
              Settings for enrolled devices (optional)
            </summary>
            <div className="mt-3 grid gap-3">
              <p className="text-sm text-muted-foreground">
                Applied to every device enrolled with this token. These can't be changed later.
              </p>
              <MultiPicker
                label="Labels"
                values={labels}
                onChange={setLabels}
                picker={DeviceLabelPicker}
                disabled={busy || captured !== null || completed}
              />
              <Label htmlFor="token-owner-kind">Assign owner</Label>
              <SelectField
                id="token-owner-kind"
                value={ownerKind}
                disabled={busy || captured !== null || completed}
                onValueChange={setOwnerKind}
                options={[
                  { value: "", label: "Unassigned" },
                  { value: "ownerText", label: "Owner name" },
                  { value: "ownerPrincipalId", label: "Owner account" },
                ]}
              />
              {ownerKind === "ownerPrincipalId" ? (
                <AccountPicker
                  label="Owner account"
                  value={ownerAccount}
                  onChange={setOwnerAccount}
                  disabled={busy || captured !== null || completed}
                />
              ) : ownerKind === "ownerText" ? (
                <label className="grid gap-1.5 text-sm font-medium">
                  Owner name
                  <Input
                    name="owner"
                    data-freeform="owner name not tied to a console account"
                    required
                  />
                </label>
              ) : null}
              <MultiPicker
                label="Groups"
                values={groupIds}
                onChange={setGroupIds}
                picker={groupPicker}
                disabled={busy || captured !== null || completed}
              />
              <MultiPicker
                label="Profile versions"
                values={profileRevisionIds}
                onChange={setProfileRevisionIds}
                picker={profileRevisionPicker}
                disabled={busy || captured !== null || completed}
              />
              <AttributeFields
                legend="Custom attributes"
                attributes={attributes}
                onChange={setAttributes}
                disabled={busy || captured !== null || completed}
              />
            </div>
          </details>
        </fieldset>
        {captured ? (
          <TechnicalDetails items={[{ label: "Request ID", value: captured.requestId }]} />
        ) : null}
        {failure ? <RpcError failure={failure} /> : null}
        {failure?.ambiguous ? (
          <p className="text-sm text-muted-foreground">
            The token may have been created. Try again to check. The secret can't be shown twice.
          </p>
        ) : null}
      </div>
      <DialogFooter className="m-0">
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
        <Button type="submit" disabled={busy || completed}>
          {busy ? "Creating…" : captured ? "Try again" : "Create provisioning token"}
        </Button>
      </DialogFooter>
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
      validateRequest(RevokeProvisioningTokenRequestSchema, request);
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
        Created by {token.creatorDisplayName || "unknown"} ·{" "}
        {token.approvalRequired ? "Each device needs approval" : "No approval needed"}
      </p>
      <details>
        <summary className="cursor-pointer text-sm">Details</summary>
        <dl className="mt-3 grid gap-1 break-all text-sm">
          <dt className="text-muted-foreground">Token ID</dt>
          <dd className="font-mono text-xs">{token.tokenId}</dd>
          <dt className="text-muted-foreground">Created by (ID)</dt>
          <dd className="font-mono text-xs">{token.createdBy || "Unknown"}</dd>
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
          <dt className="text-muted-foreground">Profile version IDs</dt>
          <dd>{token.profileRevisionIds.join(", ") || "None"}</dd>
          <dt className="text-muted-foreground">Device settings</dt>
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
              New devices can no longer enroll with it. Devices already enrolled are not affected.
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
                Reason
                <Textarea name="reason" data-freeform="audit reason" required />
              </label>
            </fieldset>
            {captured ? (
              <TechnicalDetails
                items={[
                  { label: "Request ID", value: captured.requestId },
                  { label: "Token ID", value: captured.tokenId },
                ]}
              />
            ) : null}
            {failure ? <RpcError failure={failure} /> : null}
            {failure?.ambiguous ? (
              <p className="text-sm text-muted-foreground">
                The token may already be revoked. Try again to check.
              </p>
            ) : null}
            <div className="flex flex-wrap gap-2">
              <Button type="submit" variant="destructive" disabled={busy || revoked}>
                {busy ? "Revoking…" : captured ? "Try again" : "Revoke provisioning token"}
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
