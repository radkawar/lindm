import { create, createRegistry, toJsonString } from "@bufbuild/protobuf";
import { createValidator } from "@bufbuild/protovalidate";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { useState, useSyncExternalStore } from "react";
import { toast } from "sonner";
import {
  ActivateTargetPreviewRequestSchema,
  type ActivateTargetPreviewRequest,
} from "../../../gen/lindm/admin/v1/targeting_pb";
import {
  ResourceResolutionDisposition,
  TargetMatch,
  TargetPreviewSchema,
  type TargetPreview,
} from "../../../gen/lindm/policy/v1/targeting_pb";
import { audit_reason } from "../../../gen/lindm/validation/v1/string_rules_pb";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { StatusBadge } from "@/components/ui/status-badge";
import { RpcError } from "@/components/ui/rpc-error";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
import { getAuthLifetime, subscribeAuthLifetime } from "@/lib/auth-lifetime";
import { toRpcFailure, type RpcFailure } from "@/lib/errors";
import { canonicalUuid, newRequestId } from "@/lib/ids";
import { adminClient } from "@/lib/rpc";
import { formatTimestamp } from "@/lib/time";

const validator = createValidator({ registry: createRegistry(audit_reason) });
type PreviewSession = {
  preview?: TargetPreview;
  loading?: boolean;
  previewFailure?: RpcFailure;
  request?: ActivateTargetPreviewRequest;
  status?: "pending" | "accepted" | "ambiguous" | "rejected";
  activationFailure?: RpcFailure;
  approvalId?: string;
  approvalBusy?: boolean;
  approvalFailure?: RpcFailure;
};
let session: PreviewSession = {};
const listeners = new Set<() => void>();
function update(next: PreviewSession) {
  session = next;
  for (const listener of listeners) listener();
}
function subscribe(listener: () => void) {
  listeners.add(listener);
  return () => listeners.delete(listener);
}
subscribeAuthLifetime(() => update({}));

export function TargetPreviewView() {
  const lifetime = useAuthLifetime();
  const client = useQueryClient();
  const current = useSyncExternalStore(subscribe, () => session);
  const [deviceId, setDeviceId] = useState(current.preview?.deviceId ?? "");
  const [reason, setReason] = useState("");
  const [validationError, setValidationError] = useState("");
  const preview = current.preview;
  const unresolved =
    current.status === "pending" ||
    current.status === "ambiguous" ||
    !!current.approvalBusy ||
    !!current.approvalFailure?.ambiguous;
  const approval = useMutation({
    retry: false,
    gcTime: 0,
    meta: { authGeneration: lifetime.generation },
    mutationFn: async (request: ActivateTargetPreviewRequest) => {
      const response = await adminClient.createApproval(
        {
          lifetimeSeconds: 3600,
          payload: { case: "activateTargetPreview", value: request },
        },
        { signal: lifetime.signal },
      );
      lifetime.signal.throwIfAborted();
      if (!response.approval?.id)
        throw new Error("The server did not return an approval identity.");
      return response.approval.id;
    },
    onSuccess: (approvalId) => {
      if (getAuthLifetime() !== lifetime || lifetime.signal.aborted) return;
      update({ ...session, approvalId, approvalBusy: false, approvalFailure: undefined });
      toast.success("Snapshot activation approval requested");
      void client.invalidateQueries({ queryKey: ["approvals", lifetime.generation] });
    },
    onError: (error) => {
      if (getAuthLifetime() !== lifetime || lifetime.signal.aborted) return;
      update({ ...session, approvalBusy: false, approvalFailure: toRpcFailure(error) });
    },
  });
  const read = useMutation({
    retry: false,
    gcTime: 0,
    meta: { authGeneration: lifetime.generation },
    mutationFn: async (id: string) => {
      const response = await adminClient.previewTargetAssignments(
        { deviceId: id },
        { signal: lifetime.signal },
      );
      lifetime.signal.throwIfAborted();
      if (
        !response.preview ||
        !response.preview.previewId ||
        response.preview.previewSha256.length !== 32
      )
        throw new Error("The server did not return a complete immutable preview.");
      return response.preview;
    },
    onSuccess: (result) => {
      if (getAuthLifetime() !== lifetime || lifetime.signal.aborted) return;
      update({ preview: result });
      setReason("");
    },
    onError: (error) => {
      if (getAuthLifetime() !== lifetime || lifetime.signal.aborted) return;
      update({ ...session, loading: false, previewFailure: toRpcFailure(error) });
    },
  });
  const activate = useMutation({
    retry: false,
    gcTime: 0,
    meta: { authGeneration: lifetime.generation },
    mutationFn: async (request: ActivateTargetPreviewRequest) => {
      const response = await adminClient.activateTargetPreview(request, {
        signal: lifetime.signal,
      });
      lifetime.signal.throwIfAborted();
      return response;
    },
    onSuccess: () => {
      if (getAuthLifetime() !== lifetime || lifetime.signal.aborted) return;
      update({ ...session, status: "accepted", activationFailure: undefined });
      toast.success("Target snapshot activation accepted");
      void client.invalidateQueries({ queryKey: ["targeting", lifetime.generation] });
      void client.invalidateQueries({
        queryKey: ["device-resources", lifetime.generation, session.preview?.deviceId],
      });
    },
    onError: (error) => {
      if (getAuthLifetime() !== lifetime || lifetime.signal.aborted) return;
      const failure = toRpcFailure(error);
      update({
        ...session,
        status: failure.ambiguous ? "ambiguous" : "rejected",
        activationFailure: failure,
      });
    },
  });
  return (
    <Card>
      <CardHeader>
        <CardTitle>Preview device resources</CardTitle>
        <CardDescription>
          Review the resources assigned to one device, then activate the captured snapshot.
          Activation rechecks access, device generation and freshness. It does not apply changes
          itself.
        </CardDescription>
      </CardHeader>
      <CardContent className="grid min-w-0 gap-4">
        <form
          className="flex flex-wrap items-end gap-2"
          onSubmit={(event) => {
            event.preventDefault();
            if (
              session.loading ||
              session.status === "pending" ||
              session.status === "ambiguous" ||
              session.approvalBusy ||
              session.approvalFailure?.ambiguous
            )
              return;
            const id = canonicalUuid(deviceId);
            if (!id) {
              setValidationError("Enter a device UUID.");
              return;
            }
            setValidationError("");
            update({ ...session, loading: true, previewFailure: undefined });
            read.mutate(id);
          }}
        >
          <div className="grid min-w-0 grow gap-1.5">
            <Label htmlFor="target-preview-device">Device ID</Label>
            <Input
              id="target-preview-device"
              value={deviceId}
              disabled={!!current.loading || unresolved}
              onChange={(event) => setDeviceId(event.target.value)}
            />
          </div>
          <Button disabled={!!current.loading || unresolved}>
            {current.loading ? "Capturing snapshot…" : "Capture preview"}
          </Button>
        </form>
        {validationError ? (
          <p role="alert" className="text-sm text-destructive">
            {validationError}
          </p>
        ) : null}
        {current.previewFailure ? (
          <RpcError failure={current.previewFailure}>
            {preview ? <p>The snapshot below is from the previous capture.</p> : null}
          </RpcError>
        ) : null}
        {preview ? (
          <>
            <dl className="grid gap-3 text-sm sm:grid-cols-2">
              <div>
                <dt className="text-muted-foreground">Immutable preview</dt>
                <dd className="break-all font-mono">{preview.previewId}</dd>
              </div>
              <div>
                <dt className="text-muted-foreground">Device / generation</dt>
                <dd className="break-all font-mono">
                  {preview.deviceId} / {preview.generationId}
                </dd>
              </div>
              <div>
                <dt className="text-muted-foreground">Evaluated</dt>
                <dd>{formatTimestamp(preview.evaluatedAt).local}</dd>
              </div>
              <div>
                <dt className="text-muted-foreground">Valid until (server rechecks)</dt>
                <dd>{formatTimestamp(preview.validUntil).local}</dd>
              </div>
              {[
                { label: "Input SHA-256", value: preview.inputSha256 },
                { label: "Preview SHA-256", value: preview.previewSha256 },
                { label: "Resolution SHA-256", value: preview.resolutionSha256 },
              ].map((digest) => (
                <div key={digest.label}>
                  <dt className="text-muted-foreground">{digest.label}</dt>
                  <dd className="break-all font-mono text-xs">
                    {digest.value.length === 32
                      ? Array.from(digest.value, (byte) => byte.toString(16).padStart(2, "0")).join(
                          "",
                        )
                      : "Unavailable"}
                  </dd>
                </div>
              ))}
              <div>
                <dt className="text-muted-foreground">Previous active preview</dt>
                <dd className="break-all font-mono">{preview.previousPreviewId ?? "None"}</dd>
              </div>
            </dl>
            <div className="grid gap-2">
              <h3 className="text-sm font-medium">Captured assignment candidates</h3>
              {preview.candidates.length === 0 ? (
                <p className="text-sm text-muted-foreground">
                  No assignment candidates in this capture.
                </p>
              ) : (
                preview.candidates.map((candidate, index) => (
                  <div
                    key={candidate.assignment?.assignmentId ?? index}
                    className="flex flex-wrap gap-2 border p-3 text-sm"
                  >
                    <StatusBadge status="neutral">
                      {candidate.match === TargetMatch.INCLUDED
                        ? "Included"
                        : candidate.match === TargetMatch.EXCLUDED
                          ? "Excluded"
                          : "Unknown"}
                    </StatusBadge>
                    <span className="break-all">
                      Assignment {candidate.assignment?.assignmentId ?? "Not recorded"} · revision{" "}
                      {candidate.revision.toString()} · profile revision{" "}
                      {candidate.assignment?.profileRevisionId ?? "Not recorded"} · priority{" "}
                      {candidate.assignment?.priority ?? "Not recorded"}
                    </span>
                  </div>
                ))
              )}
            </div>
            <details>
              <summary className="cursor-pointer text-sm">
                Complete immutable typed snapshot
              </summary>
              <pre className="mt-2 overflow-auto whitespace-pre-wrap break-all text-xs">
                {toJsonString(TargetPreviewSchema, preview, { prettySpaces: 2 })}
              </pre>
            </details>
            <div className="grid gap-2">
              <h3 className="text-sm font-medium">
                Resolved resources, conflicts and dispatch capability
              </h3>
              <p className="text-sm text-muted-foreground">
                Dispatch support is a control-plane capability, not qualification of this device's
                native backend, requested features or ownership. Native planning can still refuse.
              </p>
              {!preview.resolution ? (
                <Alert>
                  <AlertTitle>Resolution unavailable</AlertTitle>
                  <AlertDescription>
                    No typed resolution was returned. Do not infer readiness from assignment
                    matches.
                  </AlertDescription>
                </Alert>
              ) : preview.resolution.resources.length === 0 ? (
                <p className="text-sm text-muted-foreground">
                  This snapshot resolves no desired resources.
                </p>
              ) : (
                preview.resolution.resources.map((resolved, index) => (
                  <article
                    key={`${resolved.ref?.kind}:${resolved.ref?.canonicalKey}:${index}`}
                    className="grid gap-2 border p-3 text-sm"
                  >
                    <h4 className="break-all font-medium">
                      {resolved.ref?.kind ?? "Unknown kind"} /{" "}
                      {resolved.ref?.canonicalKey ?? "Unknown key"}
                    </h4>
                    <div className="flex flex-wrap gap-2">
                      <StatusBadge
                        status={
                          resolved.disposition === ResourceResolutionDisposition.READY
                            ? "success"
                            : resolved.disposition === ResourceResolutionDisposition.CONFLICT
                              ? "destructive"
                              : resolved.disposition === ResourceResolutionDisposition.BLOCKED
                                ? "warning"
                                : "neutral"
                        }
                      >
                        {resolved.disposition === ResourceResolutionDisposition.READY
                          ? "Resolved"
                          : resolved.disposition === ResourceResolutionDisposition.CONFLICT
                            ? "Conflict"
                            : resolved.disposition === ResourceResolutionDisposition.BLOCKED
                              ? "Blocked"
                              : "Unknown"}
                      </StatusBadge>
                      <StatusBadge status={resolved.dispatchSupported ? "info" : "warning"}>
                        {resolved.dispatchSupported ? "Dispatch supported" : "Dispatch unsupported"}
                      </StatusBadge>
                    </div>
                    <p className="break-all">
                      Required capability: {resolved.capabilityId || "Unavailable"}
                    </p>
                    {resolved.reason ? <p>Reason: {resolved.reason}</p> : null}
                    <p className="break-all">
                      Contributing immutable profile revisions:{" "}
                      {resolved.contributingRevisionIds.join(", ") || "None"}
                    </p>
                    <p className="break-all">
                      Overridden immutable profile revisions:{" "}
                      {resolved.overriddenRevisionIds.join(", ") || "None"}
                    </p>
                  </article>
                ))
              )}
            </div>
            <form
              className="grid gap-3 border-t pt-4"
              onSubmit={(event) => {
                event.preventDefault();
                if (
                  !session.preview ||
                  session.loading ||
                  (session.status && session.status !== "ambiguous")
                )
                  return;
                const request =
                  session.request ??
                  create(ActivateTargetPreviewRequestSchema, {
                    requestId: newRequestId(),
                    deviceId: session.preview.deviceId,
                    previewId: session.preview.previewId,
                    previewSha256: session.preview.previewSha256.slice(),
                    reason,
                  });
                const validation = validator.validate(ActivateTargetPreviewRequestSchema, request);
                if (validation.kind !== "valid") {
                  setValidationError(
                    validation.kind === "invalid"
                      ? validation.violations.map((item) => item.toString()).join("; ")
                      : validation.error.message,
                  );
                  return;
                }
                setValidationError("");
                update({ ...session, request, status: "pending", activationFailure: undefined });
                activate.mutate(request);
              }}
            >
              <Label htmlFor="target-activation-reason">Activation reason</Label>
              <Textarea
                id="target-activation-reason"
                value={current.request?.reason ?? reason}
                readOnly={!!current.request}
                onChange={(event) => setReason(event.target.value)}
                required
              />
              <p className="text-sm text-muted-foreground">
                Activation uses this exact preview and digest. Refresh changed or expired previews,
                and resolve unsupported resources or conflicts before deployment.
              </p>
              {current.request ? (
                <p className="break-all font-mono text-xs">
                  Request ID {current.request.requestId}
                </p>
              ) : null}
              {current.activationFailure ? (
                <RpcError failure={current.activationFailure}>
                  <p>
                    {current.status === "ambiguous"
                      ? "Retry this captured request. Keep this snapshot until the outcome is known."
                      : "Capture a fresh preview before preparing another activation."}
                  </p>
                </RpcError>
              ) : null}
              {current.activationFailure?.message === "approval_required" ? (
                <div className="grid gap-3 border bg-muted/30 p-4 text-sm">
                  <p>
                    This exact device-generation snapshot requires approval by a different
                    authorized human.
                  </p>
                  {current.approvalId ? (
                    <p>
                      Approval {current.approvalId} requested.{" "}
                      <Link to="/approvals" className="underline">
                        Review and execute in approvals
                      </Link>
                      . Expiry and changed-input fences still apply.
                    </p>
                  ) : (
                    <Button
                      type="button"
                      disabled={!!current.approvalBusy}
                      onClick={() => {
                        const request = session.request;
                        if (!request || session.approvalBusy || session.loading) return;
                        update({ ...session, approvalBusy: true, approvalFailure: undefined });
                        approval.mutate(request);
                      }}
                    >
                      {current.approvalBusy
                        ? "Requesting approval…"
                        : current.approvalFailure?.ambiguous
                          ? "Retry exact approval request"
                          : "Request approval for this snapshot"}
                    </Button>
                  )}
                  {current.approvalFailure ? <RpcError failure={current.approvalFailure} /> : null}
                </div>
              ) : null}
              {current.status === "accepted" ? (
                <p role="status" className="text-sm">
                  Snapshot activation accepted. Device execution has not been confirmed.
                </p>
              ) : null}
              <Button
                className="w-fit"
                disabled={
                  !!current.loading ||
                  (current.status !== undefined && current.status !== "ambiguous")
                }
              >
                {current.status === "pending"
                  ? "Activating…"
                  : current.status === "ambiguous"
                    ? "Retry exact activation"
                    : "Activate this snapshot"}
              </Button>
            </form>
          </>
        ) : null}
      </CardContent>
    </Card>
  );
}
