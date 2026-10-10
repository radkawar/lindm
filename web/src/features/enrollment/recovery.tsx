import { create } from "@bufbuild/protobuf";
import { useQueryClient } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { useRef, useState } from "react";
import { DeviceState, type Device } from "../../../gen/lindm/admin/v1/admin_pb";
import {
  CreateRecoveryEnrollmentGrantRequestSchema,
  type CreateRecoveryEnrollmentGrantRequest,
} from "../../../gen/lindm/admin/v1/enrollment_recovery_pb";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
import { usePrincipal } from "@/hooks/use-permissions";
import type { RpcFailure } from "@/lib/errors";
import { newRequestId } from "@/lib/ids";
import { canPermission } from "@/lib/permissions";
import { adminClient } from "@/lib/rpc";
import { RpcError } from "@/components/ui/rpc-error";
import { enrollmentFailure, validateEnrollment } from "./validation";

export function RecoveryEnrollment({ device }: { device: Device }) {
  const lifetime = useAuthLifetime();
  const principal = usePrincipal();
  const client = useQueryClient();
  const inFlight = useRef(false);
  const [captured, setCaptured] = useState<CreateRecoveryEnrollmentGrantRequest | null>(null);
  const [busy, setBusy] = useState(false);
  const [approvalId, setApprovalId] = useState("");
  const [failure, setFailure] = useState<RpcFailure | null>(null);
  const held = device.lifecycleState === DeviceState.RECOVERY_HOLD;
  const allowed = canPermission(principal, "device.revoke") && !principal.serviceAccount;

  async function requestApproval(data: FormData) {
    if (inFlight.current || lifetime.signal.aborted || !allowed) return;
    inFlight.current = true;
    setBusy(true);
    setFailure(null);
    let submitted = false;
    try {
      if (!captured && String(data.get("confirmation") ?? "").trim() !== device.id)
        throw new Error("Retype this device ID to confirm explicit identity linkage.");
      const request =
        captured ??
        create(CreateRecoveryEnrollmentGrantRequestSchema, {
          requestId: newRequestId(),
          deviceId: device.id,
          expectedGenerationId: device.enrollmentGeneration,
          expectedRevoked: device.lifecycleState === DeviceState.REVOKED,
          lifetimeSeconds: Number(data.get("lifetime")),
          reason: String(data.get("reason") ?? "").trim(),
        });
      validateEnrollment(CreateRecoveryEnrollmentGrantRequestSchema, request);
      setCaptured(request);
      submitted = true;
      const result = await adminClient.createApproval(
        { lifetimeSeconds: 3600, payload: { case: "recoverDevice", value: request } },
        { signal: lifetime.signal, timeoutMs: 30_000 },
      );
      lifetime.signal.throwIfAborted();
      if (!result.approval?.id)
        throw new Error(
          "The server did not return an approval ID. Inspect the inbox before submitting again.",
        );
      setApprovalId(result.approval.id);
      void client.invalidateQueries({ queryKey: ["approvals", lifetime.generation] });
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
        <CardTitle>{held ? "Recover device identity" : "Reinstall this device"}</CardTitle>
      </CardHeader>
      <CardContent className="grid gap-4">
        <Alert variant={held ? "destructive" : "default"}>
          <AlertTitle>
            {held
              ? "Identity on hold. Do not merge clones."
              : "Replace this specific device generation"}
          </AlertTitle>
          <AlertDescription>
            Verify the physical installation independently. Hostname, serial, MAC and TPM hints
            alone do not authorize recovery. The approved one-use grant links a new key and
            generation to this device without releasing the old identity. All old-generation
            credentials are retired when the grant is used. Other clones must enroll separately.
            Never erase a journal to retry an interrupted enrollment. If the generation or
            revocation state changes, refresh and request a new approval. An earlier approval cannot
            override a later revocation.
          </AlertDescription>
        </Alert>
        <p className="break-all text-sm">
          Device {device.id} · Current generation {device.enrollmentGeneration}
        </p>
        {allowed ? (
          <form
            className="grid gap-3"
            onSubmit={(event) => {
              event.preventDefault();
              void requestApproval(new FormData(event.currentTarget));
            }}
          >
            <fieldset className="grid gap-3" disabled={busy || captured !== null || !!approvalId}>
              <label className="grid gap-1.5 text-sm font-medium">
                Retype device ID to link the reinstall
                <Input name="confirmation" required autoComplete="off" />
              </label>
              <label className="grid gap-1.5 text-sm font-medium">
                Recovery grant lifetime (seconds, after issuance)
                <Input name="lifetime" type="number" defaultValue="300" required />
              </label>
              <label className="grid gap-1.5 text-sm font-medium">
                Reason and independently verified linkage evidence
                <Textarea name="reason" required />
              </label>
            </fieldset>
            {captured ? (
              <p className="break-all text-xs text-muted-foreground">
                Exact request {captured.requestId}; expected generation{" "}
                {captured.expectedGenerationId}; expected revoked:{" "}
                {captured.expectedRevoked ? "yes" : "no"}. The server rejects stale linkage; refresh
                and reapprove after a state change.
              </p>
            ) : null}
            {failure ? <RpcError failure={failure} /> : null}
            {approvalId ? (
              <p role="status" className="break-all text-sm">
                Approval {approvalId} requested.{" "}
                <Link to="/approvals" className="underline underline-offset-4">
                  Open approvals
                </Link>
                . A different person must approve. Then return as requester to issue the grant.
              </p>
            ) : (
              <Button type="submit" className="w-fit" variant="destructive" disabled={busy}>
                {busy
                  ? "Requesting…"
                  : captured
                    ? "Retry exact recovery request"
                    : "Request independent recovery approval"}
              </Button>
            )}
          </form>
        ) : (
          <p className="text-sm text-muted-foreground">
            Recovery requires a human account with device revocation permission for this device.
          </p>
        )}
      </CardContent>
    </Card>
  );
}
