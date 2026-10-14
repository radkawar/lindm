// SPDX-License-Identifier: Apache-2.0

import {
  create,
  fromJson,
  toJson,
  type DescMessage,
  type JsonValue,
  type MessageShape,
} from "@bufbuild/protobuf";
import { Code, ConnectError } from "@connectrpc/connect";
import {
  AuthenticationOptionsSchema,
  IdentitySettingsSchema,
  WebAuthnChallengeSchema,
  WebAuthnFinishRequestSchema,
  LocalLoginRequestSchema,
  LocalEnrollmentRequestSchema,
  SessionPrincipalSchema,
  FirstRunSetupRequestSchema,
  ListAccountsResponseSchema,
  CreateAccountRequestSchema,
  UpdateAccountRequestSchema,
  ResetAccountRequestSchema,
  AccountEnrollmentSchema,
  type LocalLoginRequest,
  type LocalEnrollmentRequest,
  type FirstRunSetupRequest,
  type CreateAccountRequest,
  type UpdateAccountRequest,
} from "../../../gen/lindm/auth/v1/auth_pb";

async function request(path: string, body?: JsonValue, csrfToken?: string, signal?: AbortSignal) {
  const response = await fetch(path, {
    method: body === undefined ? "GET" : "POST",
    mode: "same-origin",
    credentials: "same-origin",
    cache: "no-store",
    redirect: "error",
    headers: {
      Accept: "application/json",
      ...(body === undefined ? {} : { "Content-Type": "application/json" }),
      ...(csrfToken === undefined ? {} : { "X-CSRF-Token": csrfToken }),
      ...(path === "/auth/setup/begin" ? { "X-Lindm-Setup": "1" } : {}),
    },
    body: body === undefined ? undefined : JSON.stringify(body),
    signal,
  });
  if (!response.ok) {
    // Do not reflect response bodies that might accidentally contain authentication secrets.
    throw new ConnectError(
      `Sign-in failed (${response.status}). Try again.`,
      response.status === 401
        ? Code.Unauthenticated
        : response.status === 403
          ? Code.PermissionDenied
          : response.status === 429
            ? Code.ResourceExhausted
            : response.status === 400
              ? Code.InvalidArgument
              : Code.Unknown,
      response.headers,
    );
  }
  return response;
}

async function decode<T extends DescMessage>(
  schema: T,
  response: Response,
): Promise<MessageShape<T>> {
  return fromJson(schema, (await response.json()) as JsonValue);
}

export async function fetchAuthenticationOptions(signal?: AbortSignal) {
  return decode(
    AuthenticationOptionsSchema,
    await request("/auth/options", undefined, undefined, signal),
  );
}

export async function fetchIdentitySettings(signal: AbortSignal) {
  return decode(
    IdentitySettingsSchema,
    await request("/auth/settings", undefined, undefined, signal),
  );
}

export async function beginLogin(value: LocalLoginRequest, signal: AbortSignal) {
  return decode(
    WebAuthnChallengeSchema,
    await request(
      "/auth/local/login/begin",
      toJson(LocalLoginRequestSchema, value),
      undefined,
      signal,
    ),
  );
}

export async function beginSetup(value: FirstRunSetupRequest, signal: AbortSignal) {
  return decode(
    WebAuthnChallengeSchema,
    await request(
      "/auth/setup/begin",
      toJson(FirstRunSetupRequestSchema, value),
      undefined,
      signal,
    ),
  );
}

export async function beginEnrollment(value: LocalEnrollmentRequest, signal: AbortSignal) {
  return decode(
    WebAuthnChallengeSchema,
    await request(
      "/auth/local/enroll/begin",
      toJson(LocalEnrollmentRequestSchema, value),
      undefined,
      signal,
    ),
  );
}

export async function finishAuthentication(
  token: string,
  credentialJson: string,
  enrollment: boolean,
  signal: AbortSignal,
) {
  const response = await request(
    `/auth/local/${enrollment ? "enroll" : "login"}/finish`,
    toJson(
      WebAuthnFinishRequestSchema,
      create(WebAuthnFinishRequestSchema, { token, credentialJson }),
    ),
    undefined,
    signal,
  );
  if (!enrollment) return decode(SessionPrincipalSchema, response);
}

export async function fetchAccounts(signal: AbortSignal) {
  return decode(
    ListAccountsResponseSchema,
    await request("/auth/accounts", undefined, undefined, signal),
  );
}

export async function createAccount(
  value: CreateAccountRequest,
  csrf: string,
  signal: AbortSignal,
) {
  return decode(
    AccountEnrollmentSchema,
    await request("/auth/accounts/create", toJson(CreateAccountRequestSchema, value), csrf, signal),
  );
}

export async function updateAccount(
  value: UpdateAccountRequest,
  csrf: string,
  signal: AbortSignal,
) {
  await request("/auth/accounts/update", toJson(UpdateAccountRequestSchema, value), csrf, signal);
}

export async function resetAccount(accountId: string, csrf: string, signal: AbortSignal) {
  return decode(
    AccountEnrollmentSchema,
    await request(
      "/auth/accounts/reset",
      toJson(ResetAccountRequestSchema, create(ResetAccountRequestSchema, { accountId })),
      csrf,
      signal,
    ),
  );
}
