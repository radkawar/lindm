import { create, createRegistry } from "@bufbuild/protobuf";
import { timestampFromDate } from "@bufbuild/protobuf/wkt";
import { createValidator } from "@bufbuild/protovalidate";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Link } from "@tanstack/react-router";
import { toast } from "sonner";
import { AcceptAdvisoryFindingRequestSchema } from "../../../gen/lindm/admin/v1/advisories_pb";
import { audit_reason } from "../../../gen/lindm/validation/v1/string_rules_pb";
import { RpcError } from "@/components/ui/rpc-error";
import { TechnicalDetails } from "@/components/ui/technical-details";
import { Button } from "@/components/ui/button";
import { SelectField } from "@/components/ui/select-field";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
import { classifyRpcFailure, toRpcFailure } from "@/lib/errors";
import { newRequestId } from "@/lib/ids";
import { adminClient } from "@/lib/rpc";
import { formatTimestamp } from "@/lib/time";
import { describeViolation } from "@/lib/validation";
import { setAcceptanceAttempt, useAcceptanceAttempt, type AcceptanceAttempt } from "./attempt";

const validator = createValidator({ registry: createRegistry(audit_reason) });

export function AcceptanceForm({ deviceId, findingId }: { deviceId: string; findingId: string }) {
  const lifetime = useAuthLifetime();
  const queryClient = useQueryClient();
  const key = `${deviceId}/${findingId}`;
  const attempt = useAcceptanceAttempt(key);
  const [reason, setReason] = useState("");
  const [days, setDays] = useState("30");
  const [propose, setPropose] = useState(true);
  const [requestId, setRequestId] = useState(newRequestId);
  const [errors, setErrors] = useState<string[]>([]);
  const mutation = useMutation({
    retry: false,
    gcTime: 0,
    meta: { authGeneration: lifetime.generation },
    mutationFn: async (captured: AcceptanceAttempt) => {
      if (captured.propose) {
        const response = await adminClient.createApproval(
          {
            lifetimeSeconds: 3600,
            payload: { case: "acceptAdvisoryFinding", value: captured.payload },
          },
          { signal: lifetime.signal },
        );
        lifetime.signal.throwIfAborted();
        return response;
      }
      const response = await adminClient.acceptAdvisoryFinding(captured.payload, {
        signal: lifetime.signal,
      });
      lifetime.signal.throwIfAborted();
      return response;
    },
    onSuccess: (_response, captured) => {
      if (!setAcceptanceAttempt(lifetime, key, { ...captured, status: "succeeded", failure: null }))
        return;
      toast.success(captured.propose ? "Risk acceptance proposed" : "Risk accepted");
      if (captured.propose) {
        void queryClient.invalidateQueries({ queryKey: ["approvals", lifetime.generation] });
        return;
      }
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
        const { tone, title } = classifyRpcFailure(failure);
        toast[tone === "destructive" ? "error" : tone === "warning" ? "warning" : "message"](
          title,
          { description: "Check the result below before trying again." },
        );
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
        const date = new Date(Date.now() + Number(days) * 86_400_000);
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
              ? validation.violations.map((item) => describeViolation(item).message)
              : [validation.error.message],
          );
          return;
        }
        setErrors([]);
        send({ payload, propose, status: "inflight", failure: null });
      }}
    >
      <p className="text-sm">
        Risk acceptance does not fix the package. The acceptance expires automatically.
      </p>
      {attempt ? (
        <div className="grid gap-3 border bg-muted/30 p-4 text-sm">
          <TechnicalDetails items={[{ label: "Request ID", value: attempt.payload.requestId }]} />
          <p className="whitespace-pre-wrap break-words">Reason: {attempt.payload.reason}</p>
          <p>Expires: {formatTimestamp(attempt.payload.expiresAt).local}</p>
          <p role="status">
            {attempt.status === "succeeded"
              ? attempt.propose
                ? "Proposal saved. Another administrator must approve it before lindm accepts this risk."
                : "Risk accepted. Updating findings…"
              : attempt.status === "inflight"
                ? "Saving…"
                : "Not saved."}
          </p>
          {attempt.failure ? <RpcError failure={attempt.failure} /> : null}
          {attempt.propose && attempt.status === "succeeded" ? (
            <Link to="/approvals" className="underline underline-offset-4">
              Open approval inbox
            </Link>
          ) : null}
          {attempt.status === "ambiguous" ? (
            <>
              <p>
                The save result is unknown. Retry the same request to prevent duplicate records.
              </p>
              <Button type="button" onClick={() => send(attempt)}>
                Retry
              </Button>
            </>
          ) : null}
          {attempt.status === "rejected" ? (
            <Button
              type="button"
              variant="outline"
              onClick={() => {
                setAcceptanceAttempt(lifetime, key, null);
                setRequestId(newRequestId());
                mutation.reset();
              }}
            >
              Change and try again
            </Button>
          ) : null}
        </div>
      ) : (
        <>
          <Label htmlFor={`reason-${findingId}`}>Reason</Label>
          <Textarea
            id={`reason-${findingId}`}
            data-freeform="risk acceptance reason"
            required
            value={reason}
            onChange={(event) => setReason(event.target.value)}
          />
          <Label htmlFor={`expiry-${findingId}`}>Accept the risk for</Label>
          <SelectField
            id={`expiry-${findingId}`}
            className="w-48"
            value={days}
            onValueChange={setDays}
            options={[
              { value: "7", label: "7 days" },
              { value: "30", label: "30 days" },
              { value: "90", label: "90 days" },
            ]}
          />
          <label className="flex items-start gap-2 text-sm">
            <input
              type="checkbox"
              checked={propose}
              onChange={(event) => setPropose(event.target.checked)}
            />
            Ask another administrator to approve first (they have one hour to decide)
          </label>
          <p className="text-sm text-muted-foreground">
            Organisation policy can require approval before lindm accepts a risk.
          </p>
          <Button type="submit" className="w-fit">
            {propose ? "Propose risk acceptance" : "Accept risk"}
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
