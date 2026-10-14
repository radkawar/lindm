// SPDX-License-Identifier: Apache-2.0

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
import { TechnicalDetails } from "@/components/ui/technical-details";
import { RpcError } from "@/components/ui/rpc-error";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
import { getAuthLifetime, subscribeAuthLifetime } from "@/lib/auth-lifetime";
import { toRpcFailure, type RpcFailure } from "@/lib/errors";
import { canonicalUuid, newRequestId } from "@/lib/ids";
import { adminClient } from "@/lib/rpc";
import { settingTechnicalIds, settingTitle } from "@/lib/setting-identity";
import { formatTimestamp } from "@/lib/time";
import { describeViolations } from "@/lib/validation";
import { useTargetPickers } from "./pickers";

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

export function TargetPreviewView({ initialDevice = "" }: { initialDevice?: string }) {
  const { devicePicker: DevicePicker } = useTargetPickers();
  const lifetime = useAuthLifetime();
  const client = useQueryClient();
  const current = useSyncExternalStore(subscribe, () => session);
  const [deviceId, setDeviceId] = useState(initialDevice || current.preview?.deviceId || "");
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
        throw new Error("The server didn't confirm the approval request.");
      return response.approval.id;
    },
    onSuccess: (approvalId) => {
      if (getAuthLifetime() !== lifetime || lifetime.signal.aborted) return;
      update({ ...session, approvalId, approvalBusy: false, approvalFailure: undefined });
      toast.success("Approval requested");
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
        throw new Error("The server returned an incomplete preview. Try again.");
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
      toast.success("Device changes activated");
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
        <CardTitle>Inspect one device</CardTitle>
        <CardDescription>Preview this device&apos;s settings before activation.</CardDescription>
      </CardHeader>
      <CardContent className="grid min-w-0 gap-4">
        <form
          className="grid min-w-0 gap-3"
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
              setValidationError("Choose a device.");
              return;
            }
            setValidationError("");
            update({ ...session, loading: true, previewFailure: undefined });
            read.mutate(id);
          }}
        >
          <DevicePicker
            label="Device"
            value={deviceId}
            disabled={!!current.loading || unresolved}
            onChange={setDeviceId}
          />
          <Button type="submit" className="w-fit" disabled={!!current.loading || unresolved}>
            {current.loading ? "Loading preview…" : "Preview"}
          </Button>
        </form>
        {validationError ? (
          <p role="alert" className="text-sm text-destructive">
            {validationError}
          </p>
        ) : null}
        {current.previewFailure ? (
          <RpcError failure={current.previewFailure}>
            {preview ? <p>Showing the previous preview.</p> : null}
          </RpcError>
        ) : null}
        {preview ? (
          <>
            <DevicePicker
              label="Previewed device"
              value={preview.deviceId}
              disabled
              onChange={setDeviceId}
            />
            <dl className="grid gap-3 text-sm sm:grid-cols-2">
              <div>
                <dt className="text-muted-foreground">Checked</dt>
                <dd>{formatTimestamp(preview.evaluatedAt).local}</dd>
              </div>
              <div>
                <dt className="text-muted-foreground">Valid until</dt>
                <dd>{formatTimestamp(preview.validUntil).local}</dd>
              </div>
            </dl>
            <TechnicalDetails
              items={[
                { label: "Preview ID", value: preview.previewId },
                { label: "Device ID", value: preview.deviceId },
                { label: "Generation", value: preview.generationId },
                ...[
                  { label: "Input SHA-256", value: preview.inputSha256 },
                  { label: "Preview SHA-256", value: preview.previewSha256 },
                  { label: "Resolution SHA-256", value: preview.resolutionSha256 },
                ].map((digest) => ({
                  label: digest.label,
                  value:
                    digest.value.length === 32
                      ? Array.from(digest.value, (byte) => byte.toString(16).padStart(2, "0")).join(
                          "",
                        )
                      : "Unavailable",
                })),
                { label: "Previous preview", value: preview.previousPreviewId ?? "None" },
              ]}
            >
              <pre className="mt-2 overflow-auto whitespace-pre-wrap break-all text-xs">
                {toJsonString(TargetPreviewSchema, preview, { prettySpaces: 2 })}
              </pre>
            </TechnicalDetails>
            <div className="grid gap-2">
              <h3 className="text-sm font-medium">Matching assignments</h3>
              {preview.candidates.length === 0 ? (
                <p className="text-sm text-muted-foreground">No assignments match this device.</p>
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
                    <span>Priority {candidate.assignment?.priority ?? "unknown"}</span>
                    <TechnicalDetails
                      items={[
                        { label: "Assignment ID", value: candidate.assignment?.assignmentId },
                        { label: "Revision", value: candidate.revision.toString() },
                        {
                          label: "Profile version ID",
                          value: candidate.assignment?.profileRevisionId,
                        },
                      ]}
                    />
                  </div>
                ))
              )}
            </div>
            <div className="grid gap-2">
              <h3 className="text-sm font-medium">Settings this device will get</h3>
              {!preview.resolution ? (
                <Alert>
                  <AlertTitle>Couldn't work out this device's settings</AlertTitle>
                  <AlertDescription>Preview again before activating.</AlertDescription>
                </Alert>
              ) : preview.resolution.resources.length === 0 ? (
                <p className="text-sm text-muted-foreground">No settings apply to this device.</p>
              ) : (
                preview.resolution.resources.map((resolved, index) => (
                  <article
                    key={`${resolved.ref?.kind}:${resolved.ref?.canonicalKey}:${index}`}
                    className="grid gap-2 border p-3 text-sm"
                  >
                    <h4 className="break-all font-medium">
                      {resolved.ref?.kind ?? "Unknown type"} /{" "}
                      {settingTitle(resolved.ref, resolved.resource?.desired) ?? "Unknown"}
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
                          ? "Ready"
                          : resolved.disposition === ResourceResolutionDisposition.CONFLICT
                            ? "Conflict"
                            : resolved.disposition === ResourceResolutionDisposition.BLOCKED
                              ? "Blocked"
                              : "Unknown"}
                      </StatusBadge>
                      <StatusBadge status={resolved.dispatchSupported ? "info" : "warning"}>
                        {resolved.dispatchSupported ? "Supported" : "Not supported"}
                      </StatusBadge>
                    </div>
                    {resolved.reason ? <p>Reason: {resolved.reason}</p> : null}
                    <TechnicalDetails
                      items={[
                        { label: "Required capability", value: resolved.capabilityId },
                        ...settingTechnicalIds(resolved.ref),
                        {
                          label: "From profile versions",
                          value: resolved.contributingRevisionIds.join(", "),
                        },
                        {
                          label: "Overridden profile versions",
                          value: resolved.overriddenRevisionIds.join(", "),
                        },
                      ]}
                    />
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
                      ? describeViolations(validation.violations)
                      : validation.error.message,
                  );
                  return;
                }
                setValidationError("");
                update({ ...session, request, status: "pending", activationFailure: undefined });
                activate.mutate(request);
              }}
            >
              <Label htmlFor="target-activation-reason">Reason</Label>
              <Textarea
                id="target-activation-reason"
                data-freeform="audit reason"
                value={current.request?.reason ?? reason}
                readOnly={!!current.request}
                onChange={(event) => setReason(event.target.value)}
                required
              />
              <p className="text-sm text-muted-foreground">
                Fix any conflicts or unsupported settings first. If the preview expires, preview
                again.
              </p>
              {current.request ? (
                <TechnicalDetails
                  items={[{ label: "Request ID", value: current.request.requestId }]}
                />
              ) : null}
              {current.activationFailure ? (
                <RpcError failure={current.activationFailure}>
                  <p>
                    {current.status === "ambiguous"
                      ? "The server did not confirm activation. Retry the same request. It cannot apply twice."
                      : "Preview again. Activate the reviewed settings."}
                  </p>
                </RpcError>
              ) : null}
              {current.activationFailure?.message === "approval_required" ? (
                <div className="grid gap-3 border bg-muted/30 p-4 text-sm">
                  <p>Activating this device needs approval from another administrator.</p>
                  {current.approvalId ? (
                    <p>
                      Approval requested.{" "}
                      <Link to="/approvals" className="underline">
                        Go to approvals
                      </Link>
                      .
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
                          ? "Retry approval request"
                          : "Request approval"}
                    </Button>
                  )}
                  {current.approvalFailure ? <RpcError failure={current.approvalFailure} /> : null}
                </div>
              ) : null}
              {current.status === "accepted" ? (
                <p role="status" className="text-sm">
                  Activated. The device will apply the changes on its next check-in.
                </p>
              ) : null}
              <Button
                type="submit"
                className="w-fit"
                disabled={
                  !!current.loading ||
                  (current.status !== undefined && current.status !== "ambiguous")
                }
              >
                {current.status === "pending"
                  ? "Activating…"
                  : current.status === "ambiguous"
                    ? "Retry"
                    : "Activate"}
              </Button>
            </form>
          </>
        ) : null}
      </CardContent>
    </Card>
  );
}
