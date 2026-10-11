import { fromJsonString, toJsonString } from "@bufbuild/protobuf";
import { Code, ConnectError } from "@connectrpc/connect";
import {
  ApplyOrganizationRequestSchema,
  ApplyOrganizationResponseSchema,
  type ApplyOrganizationRequest,
} from "../../../gen/lindm/org/v1/apply_pb";

export async function applyOrganization(
  request: ApplyOrganizationRequest,
  csrf: string,
  signal: AbortSignal,
) {
  let response: Response;
  try {
    response = await fetch("/auth/organization/apply", {
      method: "POST",
      mode: "same-origin",
      credentials: "same-origin",
      cache: "no-store",
      redirect: "error",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json",
        "X-CSRF-Token": csrf,
      },
      body: toJsonString(ApplyOrganizationRequestSchema, request),
      signal: AbortSignal.any([signal, AbortSignal.timeout(30_000)]),
    });
  } catch {
    throw new ConnectError(
      "The organization response was not received. Check current state before reviewing again.",
      Code.Unavailable,
    );
  }
  // Neither malformed response bodies nor decoder errors may escape: they can
  // contain shown-once credentials. Partial apply is a typed response, not a throw.
  const code =
    response.status === 401
      ? Code.Unauthenticated
      : response.status === 403
        ? Code.PermissionDenied
        : response.status === 409
          ? Code.Aborted
          : Code.Unknown;
  try {
    const result = fromJsonString(ApplyOrganizationResponseSchema, await response.text());
    if (response.ok || result.failureCode) return result;
  } catch {
    // Use only the HTTP status below, never response text or decoder diagnostics.
  }
  throw new ConnectError(
    "Couldn't confirm the organization operation. Review current accounts and resources before continuing.",
    code,
    response.headers,
  );
}
