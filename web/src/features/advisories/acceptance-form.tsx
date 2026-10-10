import { create, createRegistry } from "@bufbuild/protobuf";
import { timestampFromDate } from "@bufbuild/protobuf/wkt";
import { createValidator } from "@bufbuild/protovalidate";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { toast } from "sonner";
import { AcceptAdvisoryFindingRequestSchema } from "../../../gen/lindm/admin/v1/advisories_pb";
import { audit_reason } from "../../../gen/lindm/validation/v1/string_rules_pb";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
import { toRpcFailure } from "@/lib/errors";
import { newRequestId } from "@/lib/ids";
import { adminClient } from "@/lib/rpc";
import { formatTimestamp } from "@/lib/time";
import { setAcceptanceAttempt, useAcceptanceAttempt, type AcceptanceAttempt } from "./attempt";

const validator = createValidator({ registry: createRegistry(audit_reason) });

export function AcceptanceForm({ deviceId, findingId }: { deviceId: string; findingId: string }) {
  const lifetime = useAuthLifetime();
  const queryClient = useQueryClient();
  const key = `${deviceId}/${findingId}`;
  const attempt = useAcceptanceAttempt(key);
  const [reason, setReason] = useState("");
  const [expiry, setExpiry] = useState("");
  const [requestId, setRequestId] = useState(newRequestId);
  const [errors, setErrors] = useState<string[]>([]);
  const mutation = useMutation({
    retry: false,
    gcTime: 0,
    meta: { authGeneration: lifetime.generation },
    mutationFn: async (captured: AcceptanceAttempt) => {
      const response = await adminClient.acceptAdvisoryFinding(captured.payload, {
        signal: lifetime.signal,
      });
      lifetime.signal.throwIfAborted();
      return response;
    },
    onSuccess: (_response, captured) => {
      if (!setAcceptanceAttempt(lifetime, key, { ...captured, status: "succeeded", failure: null }))
        return;
      toast.success("Risk acceptance recorded", {
        description: "Acceptance is temporary acknowledgement, not remediation.",
      });
      void queryClient.invalidateQueries({
        queryKey: ["advisory-findings", lifetime.generation, deviceId],
      });
      void queryClient.invalidateQueries({ queryKey: ["advisory-summary", lifetime.generation] });
    },
    onError: (error, captured) => {
      const failure = toRpcFailure(error);
      setAcceptanceAttempt(lifetime, key, {
        ...captured,
        status: failure.ambiguous ? "ambiguous" : "rejected",
        failure,
      });
      if (!lifetime.signal.aborted) {
        toast.error(failure.ambiguous ? "Acceptance outcome unknown" : "Acceptance not recorded", {
          description: "Review the inline result before continuing.",
        });
      }
    },
  });
  function send(captured: AcceptanceAttempt) {
    if (mutation.isPending || attempt?.status === "inflight") return;
    if (setAcceptanceAttempt(lifetime, key, { ...captured, status: "inflight", failure: null }))
      mutation.mutate(captured);
  }
  return (
    <form
      className="grid min-w-0 gap-3"
      onSubmit={(event) => {
        event.preventDefault();
        if (attempt) return;
        const date = new Date(expiry);
        if (!Number.isFinite(date.getTime())) {
          setErrors(["Enter an acceptance expiry date and time."]);
          return;
        }
        const payload = create(AcceptAdvisoryFindingRequestSchema, {
          requestId,
          deviceId,
          findingId,
          reason: reason.trim(),
          expiresAt: timestampFromDate(date),
        });
        const validation = validator.validate(AcceptAdvisoryFindingRequestSchema, payload);
        if (validation.kind !== "valid") {
          setErrors(
            validation.kind === "invalid"
              ? validation.violations.map((item) => item.toString())
              : [validation.error.message],
          );
          return;
        }
        setErrors([]);
        send({ payload, status: "inflight", failure: null });
      }}
    >
      <p className="text-sm">
        Risk acceptance is not a fix. Expiry is validated and enforced by the server.
      </p>
      {attempt ? (
        <div className="grid gap-3 border bg-muted/30 p-4 text-sm">
          <p className="break-all font-mono text-xs">Request ID: {attempt.payload.requestId}</p>
          <p className="whitespace-pre-wrap break-words">Reason: {attempt.payload.reason}</p>
          <p>Requested expiry: {formatTimestamp(attempt.payload.expiresAt).local}</p>
          <p role="status">
            {attempt.status === "succeeded"
              ? "Acceptance recorded. Refreshing server findings."
              : attempt.status === "inflight"
                ? "Recording acceptance…"
                : "Acceptance not confirmed."}
          </p>
          {attempt.failure ? (
            <Alert variant="destructive">
              <AlertTitle>Acceptance not confirmed</AlertTitle>
              <AlertDescription>
                {attempt.failure.codeName}: {attempt.failure.message}
              </AlertDescription>
            </Alert>
          ) : null}
          {attempt.status === "ambiguous" ? (
            <>
              <p>
                The outcome is unknown. Retry sends exactly the same request ID and inputs. This
                record survives navigation, but not a tab reload.
              </p>
              <Button type="button" onClick={() => send(attempt)}>
                Retry same acceptance request
              </Button>
            </>
          ) : null}
          {attempt.status === "rejected" || attempt.status === "succeeded" ? (
            <Button
              type="button"
              variant="outline"
              onClick={() => {
                setAcceptanceAttempt(lifetime, key, null);
                setRequestId(newRequestId());
                mutation.reset();
              }}
            >
              Prepare another acceptance
            </Button>
          ) : null}
        </div>
      ) : (
        <>
          <Label htmlFor={`reason-${findingId}`}>Acceptance reason</Label>
          <Textarea
            id={`reason-${findingId}`}
            required
            value={reason}
            onChange={(event) => setReason(event.target.value)}
          />
          <Label htmlFor={`expiry-${findingId}`}>Expiry (local time)</Label>
          <Input
            id={`expiry-${findingId}`}
            type="datetime-local"
            required
            value={expiry}
            onChange={(event) => setExpiry(event.target.value)}
          />
          <Button type="submit" className="w-fit">
            Accept risk until expiry
          </Button>
        </>
      )}
      {errors.length ? (
        <div
          role="alert"
          className="grid gap-1 border border-destructive/30 bg-destructive/5 p-3 text-sm text-destructive"
        >
          {errors.map((error, index) => (
            <p key={index}>{error}</p>
          ))}
        </div>
      ) : null}
    </form>
  );
}
