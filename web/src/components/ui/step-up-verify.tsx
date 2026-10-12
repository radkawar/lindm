import { useContext, useEffect, useId, useRef, useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { PrincipalContext } from "@/hooks/use-permissions";
import { StepUpError, stepUp, type StepUpFailure } from "@/lib/step-up";

const failureText: Record<StepUpFailure, string> = {
  password: "Password is incorrect. Repeated failures lock the account for a while.",
  passkey: "Your passkey didn't confirm. Try again when you're ready.",
  unavailable:
    "This sign-in can't be re-verified here. Sign out, then sign in with your local account and passkey.",
  failed: "Verification couldn't be completed. Try again.",
};

// In-page "Verify it's you": password, then passkey, on the current session.
// After success it calls onVerified (the caller resubmits its same request) or,
// without one, asks the administrator to submit again.
export function StepUpVerify({ onVerified }: { onVerified?: () => void }) {
  const principal = useContext(PrincipalContext);
  const passwordId = useId();
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState<StepUpFailure | null>(null);
  const [verified, setVerified] = useState(false);
  const active = useRef<AbortController | null>(null);
  useEffect(() => () => active.current?.abort(), []);

  async function verify() {
    if (active.current || !principal || password === "") return;
    const controller = new AbortController();
    active.current = controller;
    setBusy(true);
    setFailure(null);
    try {
      await stepUp(password, principal.csrfToken, controller.signal);
      if (controller.signal.aborted) return;
      setVerified(true);
      onVerified?.();
    } catch (error) {
      if (!controller.signal.aborted)
        setFailure(error instanceof StepUpError ? error.failure : "failed");
    } finally {
      if (!controller.signal.aborted) {
        setPassword("");
        setBusy(false);
      }
      if (active.current === controller) active.current = null;
    }
  }

  if (verified) {
    return (
      <p role="status" className="mt-2">
        {onVerified ? "Verified. Sending your request again…" : "Verified. Submit again."}
      </p>
    );
  }
  return (
    <div className="mt-3 grid max-w-sm gap-2" data-slot="step-up-verify">
      <Label htmlFor={passwordId}>Your password</Label>
      <Input
        id={passwordId}
        type="password"
        autoComplete="current-password"
        value={password}
        disabled={busy}
        onChange={(event) => setPassword(event.target.value)}
        onKeyDown={(event) => {
          if (event.key !== "Enter") return;
          // Never submit a surrounding form with the password.
          event.preventDefault();
          void verify();
        }}
      />
      {failure ? (
        <p role="alert" className="text-sm">
          {failureText[failure]}
        </p>
      ) : null}
      <Button
        type="button"
        className="w-fit"
        disabled={busy || password === ""}
        onClick={() => void verify()}
      >
        {busy ? "Waiting for passkey…" : "Verify with passkey"}
      </Button>
    </div>
  );
}
