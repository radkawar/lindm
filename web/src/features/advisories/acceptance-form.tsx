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
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
import { classifyRpcFailure, toRpcFailure } from "@/lib/errors";
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
        const date = new Date(expiry);
        if (!Number.isFinite(date.getTime())) {
          setErrors(["Enter when the acceptance should expire."]);
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
        send({ payload, propose, status: "inflight", failure: null });
      }}
    >
      <p className="text-sm">Accepting a risk doesn't fix the package. It expires automatically.</p>
      {attempt ? (
        <div className="grid gap-3 border bg-muted/30 p-4 text-sm">
          <TechnicalDetails items={[{ label: "Request ID", value: attempt.payload.requestId }]} />
          <p className="whitespace-pre-wrap break-words">Reason: {attempt.payload.reason}</p>
          <p>Expires: {formatTimestamp(attempt.payload.expiresAt).local}</p>
          <p role="status">
            {attempt.status === "succeeded"
              ? attempt.propose
                ? "Proposed. A different administrator must review before this risk can be accepted."
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
              <p>We couldn't confirm this was saved. Retry: it won't be recorded twice.</p>
              <Button type="button" onClick={() => send(attempt)}>
                Retry
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
              Accept again
            </Button>
          ) : null}
        </div>
      ) : (
        <>
          <Label htmlFor={`reason-${findingId}`}>Reason</Label>
          <Textarea
            id={`reason-${findingId}`}
            required
            value={reason}
            onChange={(event) => setReason(event.target.value)}
          />
          <Label htmlFor={`expiry-${findingId}`}>Expires (local time)</Label>
          <Input
            id={`expiry-${findingId}`}
            type="datetime-local"
            required
            value={expiry}
            onChange={(event) => setExpiry(event.target.value)}
          />
          <label className="flex items-start gap-2 text-sm">
            <input
              type="checkbox"
              checked={propose}
              onChange={(event) => setPropose(event.target.checked)}
            />
            Request independent approval (valid for one hour)
          </label>
          <p className="text-sm text-muted-foreground">
            Direct acceptance is refused when organisation policy requires approval.
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
