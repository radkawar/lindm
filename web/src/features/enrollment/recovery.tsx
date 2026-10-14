// SPDX-License-Identifier: Apache-2.0

import { create } from "@bufbuild/protobuf";
import { useQueryClient } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { useId, useRef, useState } from "react";
import { DeviceState, type Device } from "../../../gen/lindm/admin/v1/admin_pb";
import {
  CreateRecoveryEnrollmentGrantRequestSchema,
  type CreateRecoveryEnrollmentGrantRequest,
} from "../../../gen/lindm/admin/v1/enrollment_recovery_pb";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { SelectField } from "@/components/ui/select-field";
import { Textarea } from "@/components/ui/textarea";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
import { usePrincipal } from "@/hooks/use-permissions";
import type { RpcFailure } from "@/lib/errors";
import { newRequestId } from "@/lib/ids";
import { canPermission } from "@/lib/permissions";
import { adminClient } from "@/lib/rpc";
import { RpcError } from "@/components/ui/rpc-error";
import { TechnicalDetails } from "@/components/ui/technical-details";
import { enrollmentFailure } from "./validation";
import { validateRequest } from "@/lib/validation";

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
  const hostname = device.hostname.trim();
  const confirmationName = hostname || device.id;
  const formId = useId();

  async function requestApproval(data: FormData) {
    if (inFlight.current || lifetime.signal.aborted || !allowed) return;
    inFlight.current = true;
    setBusy(true);
    setFailure(null);
    let submitted = false;
    try {
      if (!captured && String(data.get("confirmation") ?? "").trim() !== confirmationName)
        throw new Error(
          `Type ${hostname ? "the hostname" : "the value"} exactly as shown to confirm.`,
        );
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
      validateRequest(CreateRecoveryEnrollmentGrantRequestSchema, request);
      setCaptured(request);
      submitted = true;
      const result = await adminClient.createApproval(
        { lifetimeSeconds: 3600, payload: { case: "recoverDevice", value: request } },
        { signal: lifetime.signal, timeoutMs: 30_000 },
      );
      lifetime.signal.throwIfAborted();
      if (!result.approval?.id)
        throw new Error(
          "The server did not confirm the approval request. Check the approval inbox before you retry.",
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
            {held ? "This device is on hold. Don't merge clones." : "Reinstall this exact device"}
          </AlertTitle>
          <AlertDescription>
            Check the physical device first. A hostname, serial number or MAC address does not prove
            identity. The recovery code stops the device&apos;s old credentials. Enroll clones as
            new devices.
          </AlertDescription>
        </Alert>
        <TechnicalDetails items={[{ label: "Device ID", value: device.id }]} />
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
                <span>
                  Type {hostname ? "hostname " : ""}
                  <code className="break-all font-mono">{confirmationName}</code> to confirm
                </span>
                <Input
                  name="confirmation"
                  data-freeform="typed confirmation of the device hostname"
                  required
                  autoComplete="off"
                  spellCheck={false}
                />
              </label>
              <div className="grid gap-1.5">
                <Label htmlFor={`${formId}-lifetime`}>Code expires after</Label>
                <SelectField
                  id={`${formId}-lifetime`}
                  name="lifetime"
                  defaultValue="300"
                  disabled={busy || captured !== null || !!approvalId}
                  required
                  options={[
                    { value: "60", label: "1 minute" },
                    { value: "300", label: "5 minutes (default)" },
                    { value: "600", label: "10 minutes" },
                    { value: "900", label: "15 minutes" },
                  ]}
                />
              </div>
              <label className="grid gap-1.5 text-sm font-medium">
                Reason and how you verified the device
                <Textarea name="reason" data-freeform="audit reason and verification" required />
              </label>
            </fieldset>
            {captured ? (
              <TechnicalDetails
                items={[
                  { label: "Request ID", value: captured.requestId },
                  { label: "Expected enrollment generation", value: captured.expectedGenerationId },
                  { label: "Expected revoked", value: captured.expectedRevoked ? "yes" : "no" },
                ]}
              />
            ) : null}
            {failure ? <RpcError failure={failure} /> : null}
            {approvalId ? (
              <div className="grid gap-1">
                <p role="status" className="text-sm">
                  Approval requested. Another admin must approve it in{" "}
                  <Link to="/approvals" className="underline underline-offset-4">
                    approvals
                  </Link>
                  , then come back here to finish.
                </p>
                <TechnicalDetails items={[{ label: "Approval ID", value: approvalId }]} />
              </div>
            ) : (
              <Button type="submit" className="w-fit" variant="destructive" disabled={busy}>
                {busy ? "Requesting…" : captured ? "Try again" : "Request approval to reinstall"}
              </Button>
            )}
          </form>
        ) : (
          <p className="text-sm text-muted-foreground">
            You need permission to revoke this device to reinstall it.
          </p>
        )}
      </CardContent>
    </Card>
  );
}
