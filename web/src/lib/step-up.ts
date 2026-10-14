// SPDX-License-Identifier: Apache-2.0

import { create, fromJson, toJson, type JsonValue } from "@bufbuild/protobuf";
import {
  LocalStepUpRequestSchema,
  WebAuthnChallengeSchema,
  WebAuthnFinishRequestSchema,
} from "../../gen/lindm/auth/v1/auth_pb";

// Why an in-page step-up did not complete: a wrong password, a passkey check
// that failed or was cancelled, a session that can never step up here, or any
// other failure (network, server).
export type StepUpFailure = "password" | "passkey" | "unavailable" | "failed";

export class StepUpError extends Error {
  constructor(readonly failure: StepUpFailure) {
    super(`step_up_${failure}`);
  }
}

async function post(path: string, body: JsonValue, csrfToken: string, signal: AbortSignal) {
  const response = await fetch(path, {
    method: "POST",
    mode: "same-origin",
    credentials: "same-origin",
    cache: "no-store",
    redirect: "error",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json",
      "X-CSRF-Token": csrfToken,
    },
    body: JSON.stringify(body),
    signal,
  });
  if (response.ok) return response;
  // Never reflect the body; the reason header is a fixed vocabulary.
  const reason = response.headers.get("Lindm-Reason");
  throw new StepUpError(
    reason === "invalid_credentials"
      ? "password"
      : reason === "step_up_failed"
        ? "passkey"
        : reason === "step_up_unavailable"
          ? "unavailable"
          : "failed",
  );
}

// Re-verifies the signed-in local account on this same session: password,
// then a passkey assertion. Resolves once the server records the verification.
export async function stepUp(password: string, csrfToken: string, signal: AbortSignal) {
  const begin = await post(
    "/auth/local/step-up/begin",
    toJson(LocalStepUpRequestSchema, create(LocalStepUpRequestSchema, { password })),
    csrfToken,
    signal,
  );
  const challenge = fromJson(WebAuthnChallengeSchema, (await begin.json()) as JsonValue);
  let credential: Credential | null;
  try {
    credential = await navigator.credentials.get({
      publicKey: PublicKeyCredential.parseRequestOptionsFromJSON(
        JSON.parse(challenge.optionsJson) as PublicKeyCredentialRequestOptionsJSON,
      ),
      signal,
    });
  } catch (error) {
    signal.throwIfAborted();
    if (error instanceof DOMException) throw new StepUpError("passkey");
    throw error;
  }
  if (!(credential instanceof PublicKeyCredential)) throw new StepUpError("passkey");
  await post(
    "/auth/local/step-up/finish",
    toJson(
      WebAuthnFinishRequestSchema,
      create(WebAuthnFinishRequestSchema, {
        token: challenge.token,
        credentialJson: JSON.stringify(credential.toJSON()),
      }),
    ),
    csrfToken,
    signal,
  );
}
