import {
  fromJsonString,
  toJsonString,
  type DescMessage,
  type MessageShape,
} from "@bufbuild/protobuf";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Fragment, useState, useSyncExternalStore, type ReactNode } from "react";
import { toast } from "sonner";
import { RpcError } from "@/components/ui/rpc-error";
import { Button } from "@/components/ui/button";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
import { getAuthLifetime, subscribeAuthLifetime } from "@/lib/auth-lifetime";
import { toRpcFailure, type RpcFailure } from "@/lib/errors";
import { checkRequest } from "@/lib/validation";

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

// Lets a closed "create" form reopen blank once its last attempt has settled.
// Pending and ambiguous attempts stay so the exact request can be retried.
export function discardSettledAttempt(formKey: string) {
  const current = attempts.get(formKey);
  if (current?.status !== "accepted" && current?.status !== "rejected") return;
  attempts.delete(formKey);
  notify();
}

// Frozen requests survive route navigation in this principal's tab memory only.
export function TargetMutation<S extends DescMessage>({
  title,
  formKey,
  schema,
  initial,
  send,
  onAccepted,
  fields,
  validate,
  framed = true,
}: {
  title: string;
  formKey: string;
  schema: S;
  initial: () => MessageShape<S>;
  send: (request: MessageShape<S>, signal: AbortSignal) => Promise<unknown>;
  onAccepted?: () => void;
  fields: (
    request: MessageShape<S>,
    change: (request: MessageShape<S>) => void,
    disabled: boolean,
  ) => ReactNode;
  // The administrator's own checks, in task language, before protobuf validation.
  validate?: (request: MessageShape<S>) => string | undefined;
  // False inside a dialog, which already supplies the frame and the title.
  framed?: boolean;
}) {
  const lifetime = useAuthLifetime();
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
      className={framed ? "grid min-w-0 gap-3 border p-4" : "grid min-w-0 gap-3"}
      onSubmit={(event) => {
        event.preventDefault();
        const current = attempts.get(formKey);
        if (current && current.status !== "ambiguous") return;
        try {
          const request = fromJsonString(schema, current?.document ?? document);
          const problem = validate?.(request);
          if (problem) {
            setError(problem);
            return;
          }
          const invalid = checkRequest(schema, request);
          if (invalid) {
            setError(invalid.message);
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
      {framed ? <h3 className="text-sm font-semibold">{title}</h3> : null}
      <Fragment key={formGeneration}>
        {fields(
          fromJsonString(schema, attempt?.document ?? document),
          (request) => setDocument(toJsonString(schema, request)),
          !!attempt,
        )}
      </Fragment>
      {error ? (
        <p role="alert" className="text-sm text-destructive">
          {error}
        </p>
      ) : null}
      {attempt?.failure ? (
        <RpcError failure={attempt.failure}>
          <p>
            {attempt.status === "ambiguous"
              ? "The server did not confirm the save. Retry the same request. The fields remain unchanged until confirmation."
              : "Nothing was saved. Start over to change the entries. Send the request again."}
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
