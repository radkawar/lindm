import { useMutation } from "@tanstack/react-query";
import { useRef, useState } from "react";
import { toast } from "sonner";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { PageHeader } from "@/components/ui/page-header";
import { RpcError } from "@/components/ui/rpc-error";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { canonicalUuid, newRequestId } from "@/lib/ids";
import { classifyRpcFailure, toRpcFailure, type RpcFailure } from "@/lib/errors";
import { reasonError } from "@/lib/reason";
import { adminClient } from "@/lib/rpc";
import { formatTimestamp } from "@/lib/time";
import type { IssuedGrant } from "./issued";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
import { ProvisioningTokens } from "./provisioning";
import { PendingEnrollments } from "./pending";
import { OfflineEnrollment } from "./offline";

const LIFETIME_MIN = 60;
const LIFETIME_MAX = 900;

type GrantPayload = {
  requestId: string;
  lifetimeSeconds: number;
  reason: string;
};

export function EnrollmentView() {
  const lifetime = useAuthLifetime();
  const [issued, setIssued] = useState<IssuedGrant | null>(null);
  const [revokeGrantId, setRevokeGrantId] = useState(issued?.grantId ?? "");

  return (
    <section className="flex min-w-0 max-w-4xl flex-col gap-6">
      <PageHeader
        title="Device enrollment"
        description="Use a one-time grant for a device, provisioning tokens for unattended installs, or signed files for offline sites."
      />
      <p className="text-sm text-muted-foreground">
        Grants are short-lived and single-use. Never store a grant in a golden image.
      </p>
      <IssueGrant
        onIssued={(grant) => {
          if (!lifetime.signal.aborted) setIssued(grant);
          setRevokeGrantId(grant.grantId);
        }}
      />
      {issued ? (
        <GrantResult
          key={issued.requestId}
          grant={issued}
          onHide={() => setIssued({ ...issued, secret: null, hidden: true })}
        />
      ) : null}
      <RevokeGrant grantId={revokeGrantId} onGrantId={setRevokeGrantId} />
      <ProvisioningTokens />
      <PendingEnrollments />
      <OfflineEnrollment />
    </section>
  );
}

function IssueGrant({ onIssued }: { onIssued: (grant: IssuedGrant) => void }) {
  const authLifetime = useAuthLifetime();
  const inFlight = useRef(false);
  const submitted = useRef<GrantPayload | null>(null);
  const [lifetime, setLifetime] = useState("300");
  const [reason, setReason] = useState("");
  const [requestId, setRequestId] = useState(newRequestId);
  const [fieldError, setFieldError] = useState("");
  const [failure, setFailure] = useState<RpcFailure | null>(null);
  const [armed, setArmed] = useState(true);
  const frozen = submitted.current !== null;
  const issue = useMutation({
    retry: false,
    meta: { authGeneration: authLifetime.generation },
    gcTime: 0,
    mutationFn: async (payload: GrantPayload) => {
      const response = await adminClient.createEnrollmentGrant(
        {
          requestId: payload.requestId,
          lifetimeSeconds: payload.lifetimeSeconds,
          reason: payload.reason,
        },
        { signal: authLifetime.signal },
      );
      authLifetime.signal.throwIfAborted();
      if (response.grantId.trim() === "") {
        throw new Error("The server did not return a grant ID.");
      }
      const deliveryUnknown = response.secretDeliveryUnknown || response.secret === "";
      onIssued({
        requestId: payload.requestId,
        grantId: response.grantId,
        expiresAt: response.expiresAt,
        secret: deliveryUnknown ? null : response.secret,
        deliveryUnknown,
        hidden: false,
      });
      return { grantId: response.grantId, deliveryUnknown };
    },
    onSuccess: (result) => {
      submitted.current = null;
      setArmed(false);
      setRequestId(newRequestId());
      setFailure(null);
      if (!authLifetime.signal.aborted) {
        if (result.deliveryUnknown) {
          toast.error("Grant secret was not delivered", {
            description: "Revoke the grant and issue a replacement.",
          });
        } else {
          toast.success("Enrollment grant issued", {
            description: "Secure the one-time secret shown on this page.",
          });
        }
      }
    },
    onError: (error) => {
      const next = toRpcFailure(error);
      setFailure(next);
      if (!authLifetime.signal.aborted) {
        const feedback = classifyRpcFailure(next);
        const notify = feedback.tone === "destructive" ? toast.error : toast;
        notify(feedback.title, { description: feedback.action });
      }
    },
    onSettled: () => {
      inFlight.current = false;
    },
  });

  return (
    <Card>
      <CardHeader>
        <CardTitle>Issue a one-time grant</CardTitle>
      </CardHeader>
      <CardContent>
        <form
          className="grid gap-3"
          onSubmit={(event) => {
            event.preventDefault();
            if (inFlight.current) return;
            if (submitted.current) {
              inFlight.current = true;
              issue.mutate(submitted.current);
              return;
            }
            if (!armed && failure?.ambiguous !== true) return;
            const seconds = Number(lifetime);
            if (!Number.isInteger(seconds) || seconds < LIFETIME_MIN || seconds > LIFETIME_MAX) {
              setFieldError(
                `Lifetime must be between ${LIFETIME_MIN} and ${LIFETIME_MAX} seconds.`,
              );
              return;
            }
            const nextReason = reasonError(reason);
            if (nextReason !== "") {
              setFieldError(nextReason);
              return;
            }
            setFieldError("");
            submitted.current = { requestId, lifetimeSeconds: seconds, reason: reason.trim() };
            inFlight.current = true;
            issue.mutate(submitted.current);
          }}
        >
          <div className="grid max-w-xs gap-1.5">
            <Label htmlFor="grant-lifetime">Lifetime in seconds</Label>
            <Input
              id="grant-lifetime"
              inputMode="numeric"
              min={LIFETIME_MIN}
              max={LIFETIME_MAX}
              value={lifetime}
              readOnly={issue.isPending || frozen}
              onChange={(event) => setLifetime(event.target.value)}
            />
          </div>
          <div className="grid gap-1.5">
            <Label htmlFor="grant-reason">Reason</Label>
            <Textarea
              id="grant-reason"
              required
              maxLength={512}
              value={reason}
              readOnly={issue.isPending || frozen}
              onChange={(event) => setReason(event.target.value)}
            />
          </div>
          <p className="break-all font-mono text-xs text-muted-foreground">
            Request ID {requestId}
          </p>
          {fieldError !== "" ? (
            <p role="alert" className="text-sm text-destructive">
              {fieldError}
            </p>
          ) : null}
          {failure ? (
            <RpcError failure={failure}>
              {failure.ambiguous ? (
                <p>Retry the same request ID. A retry cannot recover a withheld secret.</p>
              ) : null}
            </RpcError>
          ) : null}
          <div className="flex flex-wrap gap-2">
            <Button
              type="submit"
              disabled={issue.isPending || (!armed && failure?.ambiguous !== true)}
            >
              {issue.isPending ? "Issuing grant…" : failure ? "Retry same request" : "Issue grant"}
            </Button>
            {!armed && failure === null ? (
              <Button type="button" variant="outline" onClick={() => setArmed(true)}>
                Prepare another grant
              </Button>
            ) : null}
            {failure ? (
              <Button
                type="button"
                variant="outline"
                disabled={issue.isPending}
                onClick={() => {
                  if (inFlight.current) return;
                  submitted.current = null;
                  setRequestId(newRequestId());
                  setFailure(null);
                  setArmed(true);
                }}
              >
                Start a different request
              </Button>
            ) : null}
          </div>
        </form>
      </CardContent>
    </Card>
  );
}

function GrantResult({ grant, onHide }: { grant: IssuedGrant; onHide: () => void }) {
  const [acknowledged, setAcknowledged] = useState(false);
  const [copyStatus, setCopyStatus] = useState("");
  const expires = formatTimestamp(grant.expiresAt);
  const secret = grant.secret;

  return (
    <Card>
      <CardHeader>
        <CardTitle className="break-all font-mono text-base">Grant {grant.grantId}</CardTitle>
      </CardHeader>
      <CardContent className="grid gap-3">
        <p className="break-words text-sm">
          Expires {expires.local}. Request ID {grant.requestId}.
        </p>
        {grant.hidden ? (
          <p role="status">The secret has been hidden and cannot be displayed again.</p>
        ) : grant.deliveryUnknown || secret === null ? (
          <Alert variant="destructive">
            <AlertTitle>Secret was not delivered</AlertTitle>
            <AlertDescription>
              The server did not return the secret. It cannot be recovered. Revoke this grant and
              issue a replacement with a new request ID.
            </AlertDescription>
          </Alert>
        ) : (
          <>
            <Alert>
              <AlertTitle>Shown once</AlertTitle>
              <AlertDescription>
                The server will not return this secret again. It is not saved in browser storage.
              </AlertDescription>
            </Alert>
            <div className="grid gap-1.5">
              <Label htmlFor="grant-secret">Enrollment grant secret</Label>
              <Input
                id="grant-secret"
                readOnly
                value={secret}
                autoComplete="off"
                spellCheck={false}
              />
            </div>
            <Button
              type="button"
              onClick={() => {
                const clipboard = navigator.clipboard;
                if (clipboard === undefined) {
                  setCopyStatus(
                    "Clipboard is unavailable. Select the secret and copy it manually.",
                  );
                  return;
                }
                void clipboard.writeText(secret).then(
                  () => setCopyStatus("Copied to the clipboard."),
                  () => setCopyStatus("Clipboard write was denied. Select the secret manually."),
                );
              }}
            >
              Copy secret
            </Button>
            {copyStatus !== "" ? <p role="status">{copyStatus}</p> : null}
            <label className="flex items-start gap-2 text-sm">
              <input
                type="checkbox"
                checked={acknowledged}
                onChange={(event) => setAcknowledged(event.target.checked)}
              />
              I have copied this secret and understand it cannot be displayed again.
            </label>
            <Button type="button" variant="outline" disabled={!acknowledged} onClick={onHide}>
              Hide secret
            </Button>
          </>
        )}
      </CardContent>
    </Card>
  );
}

function RevokeGrant({
  grantId,
  onGrantId,
}: {
  grantId: string;
  onGrantId: (value: string) => void;
}) {
  const lifetime = useAuthLifetime();
  const inFlight = useRef(false);
  const submitted = useRef<{ requestId: string; grantId: string; reason: string } | null>(null);
  const [reason, setReason] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [requestId, setRequestId] = useState(newRequestId);
  const [fieldError, setFieldError] = useState("");
  const [failure, setFailure] = useState<RpcFailure | null>(null);
  const [accepted, setAccepted] = useState("");
  const revoke = useMutation({
    retry: false,
    meta: { authGeneration: lifetime.generation },
    mutationFn: async (payload: { requestId: string; grantId: string; reason: string }) => {
      await adminClient.revokeEnrollmentGrant(payload, { signal: lifetime.signal });
      lifetime.signal.throwIfAborted();
      return payload;
    },
    onSuccess: (payload) => {
      submitted.current = null;
      setAccepted(`Revoke request ${payload.requestId} was accepted for grant ${payload.grantId}.`);
      setRequestId(newRequestId());
      setReason("");
      setConfirmation("");
      setFailure(null);
      if (!lifetime.signal.aborted) toast.success("Grant revocation request accepted");
    },
    onError: (error) => {
      const next = toRpcFailure(error);
      setFailure(next);
      if (!lifetime.signal.aborted) {
        const feedback = classifyRpcFailure(next);
        const notify = feedback.tone === "destructive" ? toast.error : toast;
        notify(feedback.title, { description: feedback.action });
      }
    },
    onSettled: () => {
      inFlight.current = false;
    },
  });

  return (
    <Card>
      <CardHeader>
        <CardTitle>Revoke a grant</CardTitle>
      </CardHeader>
      <CardContent>
        <form
          className="grid gap-3"
          onSubmit={(event) => {
            event.preventDefault();
            if (inFlight.current) return;
            if (submitted.current) {
              inFlight.current = true;
              revoke.mutate(submitted.current);
              return;
            }
            const parsed = canonicalUuid(grantId);
            const confirmed = canonicalUuid(confirmation);
            const nextReason = reasonError(reason);
            if (parsed === null || confirmed !== parsed || nextReason !== "") {
              setFieldError(nextReason || "Enter and retype the grant UUID.");
              return;
            }
            setFieldError("");
            submitted.current = { requestId, grantId: parsed, reason: reason.trim() };
            inFlight.current = true;
            revoke.mutate(submitted.current);
          }}
        >
          <p className="text-sm text-muted-foreground">
            This stops an unused grant from being redeemed. A device that already enrolled is
            unchanged.
          </p>
          <div className="grid gap-1.5">
            <Label htmlFor="revoke-grant-id">Grant ID</Label>
            <Input
              id="revoke-grant-id"
              value={submitted.current?.grantId ?? grantId}
              readOnly={revoke.isPending || submitted.current !== null}
              autoComplete="off"
              spellCheck={false}
              onChange={(event) => onGrantId(event.target.value)}
            />
          </div>
          <div className="grid gap-1.5">
            <Label htmlFor="revoke-grant-reason">Reason</Label>
            <Textarea
              id="revoke-grant-reason"
              required
              maxLength={512}
              value={reason}
              readOnly={revoke.isPending || submitted.current !== null}
              onChange={(event) => setReason(event.target.value)}
            />
          </div>
          <div className="grid gap-1.5">
            <Label htmlFor="revoke-grant-confirm">Type the grant ID to confirm</Label>
            <Input
              id="revoke-grant-confirm"
              required
              autoComplete="off"
              value={confirmation}
              readOnly={revoke.isPending || submitted.current !== null}
              onChange={(event) => setConfirmation(event.target.value)}
            />
          </div>
          <p className="break-all font-mono text-xs text-muted-foreground">
            Request ID {requestId}
          </p>
          {fieldError !== "" ? (
            <p role="alert" className="text-sm text-destructive">
              {fieldError}
            </p>
          ) : null}
          {accepted !== "" ? (
            <Alert>
              <AlertDescription>{accepted}</AlertDescription>
            </Alert>
          ) : null}
          {failure ? <RpcError failure={failure} /> : null}
          <div className="flex flex-wrap gap-2">
            <Button type="submit" variant="destructive" disabled={revoke.isPending}>
              {revoke.isPending
                ? "Revoking grant…"
                : failure
                  ? "Retry same request"
                  : "Revoke grant"}
            </Button>
            {failure ? (
              <Button
                type="button"
                variant="outline"
                disabled={revoke.isPending}
                onClick={() => {
                  if (inFlight.current) return;
                  submitted.current = null;
                  setRequestId(newRequestId());
                  setFailure(null);
                }}
              >
                Start a different request
              </Button>
            ) : null}
          </div>
        </form>
      </CardContent>
    </Card>
  );
}
