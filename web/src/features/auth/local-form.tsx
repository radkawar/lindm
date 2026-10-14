// SPDX-License-Identifier: Apache-2.0

import { create } from "@bufbuild/protobuf";
import { useEffect, useRef, useState, type FormEvent } from "react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { RpcError } from "@/components/ui/rpc-error";
import { toRpcFailure, type RpcFailure } from "@/lib/errors";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  LocalEnrollmentRequestSchema,
  FirstRunSetupRequestSchema,
  LocalLoginRequestSchema,
} from "../../../gen/lindm/auth/v1/auth_pb";
import { beginEnrollment, beginLogin, beginSetup, finishAuthentication } from "./local-api";

export function LocalForm({
  enrollment = false,
  setup = false,
  emergency = false,
  onSuccess,
}: {
  enrollment?: boolean;
  setup?: boolean;
  emergency?: boolean;
  onSuccess: () => Promise<void>;
}) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [secret, setSecret] = useState("");
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<RpcFailure | null>(null);
  const [notice, setNotice] = useState("");
  const active = useRef<AbortController | null>(null);
  useEffect(() => () => active.current?.abort(), []);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (active.current) return;
    const controller = new AbortController();
    active.current = controller;
    setBusy(true);
    setError(null);
    setNotice("");
    try {
      if (
        !window.isSecureContext ||
        typeof PublicKeyCredential === "undefined" ||
        typeof PublicKeyCredential.parseCreationOptionsFromJSON !== "function" ||
        typeof PublicKeyCredential.parseRequestOptionsFromJSON !== "function"
      ) {
        setNotice("Open the console over HTTPS in a current browser that supports security keys.");
        return;
      }
      const challenge = setup
        ? await beginSetup(
            create(FirstRunSetupRequestSchema, { code: secret, username, password }),
            controller.signal,
          )
        : enrollment
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
      const credential =
        enrollment || setup
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
        throw new Error("Your security key didn't respond. Try again.");
      await finishAuthentication(
        challenge.token,
        JSON.stringify(credential.toJSON()),
        enrollment || setup,
        controller.signal,
      );
      controller.signal.throwIfAborted();
      await onSuccess();
    } catch (failure) {
      if (!controller.signal.aborted) {
        if (failure instanceof DOMException && failure.name === "NotAllowedError") {
          setNotice(
            setup
              ? "Passkey setup did not finish. Enter the same setup code, username and password to continue."
              : "Authenticator verification did not finish. Retry when ready.",
          );
        } else {
          setError(toRpcFailure(failure));
        }
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
    <form className="grid gap-3" aria-busy={busy} onSubmit={(event) => void submit(event)}>
      {enrollment || setup ? (
        <>
          <Label htmlFor="account-secret">
            {setup ? "Setup code" : "One-time enrollment secret"}
          </Label>
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
      ) : null}
      {!enrollment || setup ? (
        <>
          <Label htmlFor="local-username">Username</Label>
          <Input
            id="local-username"
            data-freeform="administrator chooses a new setup username or enters a sign-in username"
            autoComplete="username"
            required
            value={username}
            disabled={busy}
            onChange={(event) => setUsername(event.target.value)}
          />
        </>
      ) : null}
      <Label htmlFor="local-password">
        {setup ? "Password" : enrollment ? "New password (at least 12 bytes)" : "Password"}
      </Label>
      <Input
        id="local-password"
        type="password"
        autoComplete={enrollment || setup ? "new-password" : "current-password"}
        aria-describedby={setup ? "setup-password-help" : undefined}
        required
        value={password}
        disabled={busy}
        onChange={(event) => setPassword(event.target.value)}
      />
      {setup ? (
        <p id="setup-password-help" className="text-sm text-muted-foreground">
          Use at least 12 bytes. Have a security key or passkey ready for the next step.
        </p>
      ) : null}
      {emergency ? (
        <>
          <Label htmlFor="incident-reason">Reason for emergency sign-in (required)</Label>
          <Input
            id="incident-reason"
            data-freeform="audit reason for emergency sign-in"
            value={reason}
            disabled={busy}
            onChange={(event) => setReason(event.target.value)}
          />
          <p className="text-sm text-muted-foreground">
            Do not include passwords. The audit log records emergency sign-ins.
          </p>
        </>
      ) : null}
      <p className="text-sm text-muted-foreground">
        {setup
          ? "Create the owner account, then register a passkey to open the dashboard."
          : enrollment
            ? "Set a password. Register a security key or passkey. Then sign in."
            : "Enter your password. Confirm with your security key or passkey."}
      </p>
      {setup ? (
        <p className="text-sm text-muted-foreground">
          If you stop, continue with the same setup code, username and password.
        </p>
      ) : null}
      {notice ? (
        <Alert>
          <AlertTitle>Security key needed</AlertTitle>
          <AlertDescription>{notice}</AlertDescription>
        </Alert>
      ) : null}
      {error ? <RpcError failure={error} /> : null}
      <Button type="submit" disabled={busy}>
        {busy
          ? "Waiting for authenticator…"
          : setup
            ? "Create owner account"
            : enrollment
              ? "Enroll account"
              : "Sign in locally"}
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
