import { create } from "@bufbuild/protobuf";
import { useEffect, useRef, useState, type FormEvent } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  LocalEnrollmentRequestSchema,
  LocalLoginRequestSchema,
} from "../../../gen/lindm/auth/v1/auth_pb";
import { beginEnrollment, beginLogin, finishAuthentication } from "./local-api";

export function LocalForm({
  enrollment = false,
  emergency = false,
  onSuccess,
}: {
  enrollment?: boolean;
  emergency?: boolean;
  onSuccess: () => Promise<void>;
}) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [secret, setSecret] = useState("");
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const active = useRef<AbortController | null>(null);
  useEffect(() => () => active.current?.abort(), []);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (active.current) return;
    const controller = new AbortController();
    active.current = controller;
    setBusy(true);
    setError("");
    try {
      if (
        !window.isSecureContext ||
        typeof PublicKeyCredential === "undefined" ||
        typeof PublicKeyCredential.parseCreationOptionsFromJSON !== "function" ||
        typeof PublicKeyCredential.parseRequestOptionsFromJSON !== "function"
      ) {
        throw new Error("Use a current browser supporting WebAuthn JSON over HTTPS.");
      }
      const challenge = enrollment
        ? await beginEnrollment(
            create(LocalEnrollmentRequestSchema, { secret, password }),
            controller.signal,
          )
        : await beginLogin(
            create(LocalLoginRequestSchema, { username, password, incidentReason: reason }),
            controller.signal,
          );
      setPassword("");
      setSecret("");
      const credential = enrollment
        ? await navigator.credentials.create({
            publicKey: PublicKeyCredential.parseCreationOptionsFromJSON(
              JSON.parse(challenge.optionsJson) as PublicKeyCredentialCreationOptionsJSON,
            ),
            signal: controller.signal,
          })
        : await navigator.credentials.get({
            publicKey: PublicKeyCredential.parseRequestOptionsFromJSON(
              JSON.parse(challenge.optionsJson) as PublicKeyCredentialRequestOptionsJSON,
            ),
            signal: controller.signal,
          });
      if (!(credential instanceof PublicKeyCredential))
        throw new Error("Authenticator did not return a credential.");
      await finishAuthentication(
        challenge.token,
        JSON.stringify(credential.toJSON()),
        enrollment,
        controller.signal,
      );
      controller.signal.throwIfAborted();
      await onSuccess();
    } catch (failure) {
      if (!controller.signal.aborted) {
        setError(failure instanceof Error ? failure.message : "Authentication failed.");
      }
    } finally {
      if (!controller.signal.aborted) {
        setPassword("");
        setSecret("");
        setBusy(false);
      }
      if (active.current === controller) active.current = null;
    }
  }

  return (
    <form className="grid gap-3" onSubmit={(event) => void submit(event)}>
      {enrollment ? (
        <>
          <Label htmlFor="account-secret">One-time enrollment secret</Label>
          <Input
            id="account-secret"
            type="password"
            autoComplete="off"
            required
            value={secret}
            disabled={busy}
            onChange={(event) => setSecret(event.target.value)}
          />
        </>
      ) : (
        <>
          <Label htmlFor="local-username">Username</Label>
          <Input
            id="local-username"
            autoComplete="username"
            required
            value={username}
            disabled={busy}
            onChange={(event) => setUsername(event.target.value)}
          />
        </>
      )}
      <Label htmlFor="local-password">
        {enrollment ? "New password (at least 12 bytes)" : "Password"}
      </Label>
      <Input
        id="local-password"
        type="password"
        autoComplete={enrollment ? "new-password" : "current-password"}
        required
        value={password}
        disabled={busy}
        onChange={(event) => setPassword(event.target.value)}
      />
      {emergency ? (
        <>
          <Label htmlFor="incident-reason">Incident reason (required for break-glass)</Label>
          <Input
            id="incident-reason"
            value={reason}
            disabled={busy}
            onChange={(event) => setReason(event.target.value)}
          />
          <p className="text-sm text-muted-foreground">
            Do not include passwords or other secrets. Emergency access is audited and restricted.
          </p>
        </>
      ) : null}
      <p className="text-sm text-muted-foreground">
        {enrollment
          ? "Set your password, then register a security key or passkey with user verification. Enrollment does not sign you in."
          : "After your password is accepted, verify with your registered security key or passkey."}
      </p>
      {error ? <p role="alert">{error}</p> : null}
      <Button type="submit" disabled={busy}>
        {busy ? "Waiting for authenticator…" : enrollment ? "Enroll account" : "Sign in locally"}
      </Button>
      {busy ? (
        <Button
          type="button"
          variant="outline"
          onClick={() => {
            active.current?.abort();
            active.current = null;
            setBusy(false);
            setPassword("");
            setSecret("");
          }}
        >
          Cancel
        </Button>
      ) : null}
    </form>
  );
}
