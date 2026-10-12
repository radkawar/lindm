import {
  createRegistry,
  fromJsonString,
  toJsonString,
  type DescMessage,
  type JsonObject,
  type MessageShape,
} from "@bufbuild/protobuf";
import { createValidator } from "@bufbuild/protovalidate";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useState, useSyncExternalStore, type ReactNode } from "react";
import { toast } from "sonner";
import { audit_reason } from "../../../gen/lindm/validation/v1/string_rules_pb";
import { RpcError } from "@/components/ui/rpc-error";
import { Button } from "@/components/ui/button";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
import { getAuthLifetime, subscribeAuthLifetime } from "@/lib/auth-lifetime";
import { toRpcFailure, type RpcFailure } from "@/lib/errors";
import { describeViolations } from "@/lib/validation";
import { TargetFields } from "./fields";
import { useTargetPickers } from "./pickers";

const validator = createValidator({ registry: createRegistry(audit_reason) });
type Attempt = {
  document: string;
  status: "pending" | "accepted" | "ambiguous" | "rejected";
  failure?: RpcFailure;
};
const attempts = new Map<string, Attempt>();
const listeners = new Set<() => void>();
function notify() {
  for (const listener of listeners) listener();
}
function subscribe(listener: () => void) {
  listeners.add(listener);
  return () => listeners.delete(listener);
}
subscribeAuthLifetime(() => {
  attempts.clear();
  notify();
});

// Frozen requests survive route navigation in this principal's tab memory only.
export function TargetMutation<S extends DescMessage>({
  title,
  formKey,
  schema,
  initial,
  send,
  onAccepted,
  fields,
}: {
  title: string;
  formKey: string;
  schema: S;
  initial: () => MessageShape<S>;
  send: (request: MessageShape<S>, signal: AbortSignal) => Promise<unknown>;
  onAccepted?: () => void;
  fields?: (
    request: MessageShape<S>,
    change: (request: MessageShape<S>) => void,
    disabled: boolean,
  ) => ReactNode;
}) {
  const lifetime = useAuthLifetime();
  const pickers = useTargetPickers();
  const client = useQueryClient();
  const [formGeneration, setFormGeneration] = useState(0);
  const attempt = useSyncExternalStore(subscribe, () => attempts.get(formKey));
  const Container =
    attempt?.status === "accepted" || attempt?.status === "rejected" ? "section" : "form";
  const [document, setDocument] = useState(() =>
    toJsonString(schema, initial(), { prettySpaces: 2 }),
  );
  const [error, setError] = useState("");
  const mutation = useMutation({
    retry: false,
    gcTime: 0,
    meta: { authGeneration: lifetime.generation },
    mutationFn: async (request: MessageShape<S>) => {
      const result = await send(request, lifetime.signal);
      lifetime.signal.throwIfAborted();
      return result;
    },
    onSuccess: () => {
      if (getAuthLifetime() !== lifetime || lifetime.signal.aborted) return;
      const current = attempts.get(formKey);
      if (current) attempts.set(formKey, { ...current, status: "accepted" });
      notify();
      toast.success("Changes saved");
      void client.invalidateQueries({ queryKey: ["targeting", lifetime.generation] });
      onAccepted?.();
    },
    onError: (cause) => {
      if (getAuthLifetime() !== lifetime || lifetime.signal.aborted) return;
      const failure = toRpcFailure(cause);
      const current = attempts.get(formKey);
      if (current)
        attempts.set(formKey, {
          ...current,
          status: failure.ambiguous ? "ambiguous" : "rejected",
          failure,
        });
      notify();
    },
  });
  return (
    <Container
      className="grid min-w-0 gap-3 border p-4"
      onSubmit={(event) => {
        event.preventDefault();
        const current = attempts.get(formKey);
        if (current && current.status !== "ambiguous") return;
        try {
          const request = fromJsonString(schema, current?.document ?? document);
          const validation = validator.validate(schema, request);
          if (validation.kind !== "valid") {
            setError(
              validation.kind === "invalid"
                ? describeViolations(validation.violations)
                : validation.error.message,
            );
            return;
          }
          attempts.set(formKey, {
            document: toJsonString(schema, request, { prettySpaces: 2 }),
            status: "pending",
          });
          notify();
          setError("");
          mutation.mutate(request);
        } catch (cause) {
          setError(cause instanceof Error ? cause.message : "Invalid JSON");
        }
      }}
    >
      <h3 className="text-sm font-semibold">{title}</h3>
      <p className="text-sm text-muted-foreground">Once sent, edits are locked.</p>
      {fields ? (
        fields(
          fromJsonString(schema, attempt?.document ?? document),
          (request) => setDocument(toJsonString(schema, request)),
          !!attempt,
        )
      ) : (
        <TargetFields
          key={formGeneration}
          schema={schema}
          value={JSON.parse(attempt?.document ?? document) as JsonObject}
          onChange={(value) => setDocument(JSON.stringify(value))}
          pickers={pickers}
          disabled={!!attempt}
        />
      )}
      {error ? (
        <p role="alert" className="text-sm text-destructive">
          {error}
        </p>
      ) : null}
      {attempt?.failure ? (
        <RpcError failure={attempt.failure}>
          <p>
            {attempt.status === "ambiguous"
              ? "We couldn't confirm this was saved. Retry: it won't apply twice."
              : "Refresh, then try again."}
          </p>
        </RpcError>
      ) : null}
      {attempt?.status === "accepted" ? (
        <p role="status" className="text-sm">
          Saved.
        </p>
      ) : null}
      <div className="flex flex-wrap gap-2">
        {!attempt || attempt.status === "ambiguous" ? (
          <Button type="submit">{attempt ? "Retry" : title}</Button>
        ) : null}
        {attempt?.status === "pending" ? (
          <Button type="submit" disabled>
            Sending…
          </Button>
        ) : null}
        {attempt && (attempt.status === "accepted" || attempt.status === "rejected") ? (
          <Button
            type="button"
            variant="outline"
            onClick={() => {
              // A new attempt must have a distinct request ID, never silently reuse the frozen identity.
              setDocument(toJsonString(schema, initial(), { prettySpaces: 2 }));
              setFormGeneration((current) => current + 1);
              attempts.delete(formKey);
              notify();
              setError("");
            }}
          >
            Start over
          </Button>
        ) : null}
      </div>
    </Container>
  );
}
