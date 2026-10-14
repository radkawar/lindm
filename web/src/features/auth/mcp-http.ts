// SPDX-License-Identifier: Apache-2.0

import { fromJsonString, type DescMessage, type MessageShape } from "@bufbuild/protobuf";
import { Code, ConnectError } from "@connectrpc/connect";

// Never include response bodies or decoder diagnostics in errors: an issuance
// response can contain the only copy of a credential. No HTTP mutation retries.
export async function mcpRequest<T extends DescMessage>(
  path: "/auth/mcp/settings" | "/auth/mcp/tokens" | "/auth/mcp/tokens/revoke",
  schema: T,
  signal: AbortSignal,
  body?: string,
  csrf?: string,
): Promise<MessageShape<T>> {
  let response: Response;
  try {
    response = await fetch(path, {
      method: body === undefined ? "GET" : "POST",
      mode: "same-origin",
      credentials: "same-origin",
      cache: "no-store",
      redirect: "error",
      headers: {
        Accept: "application/json",
        ...(body === undefined ? {} : { "Content-Type": "application/json" }),
        ...(csrf === undefined ? {} : { "X-CSRF-Token": csrf }),
      },
      body,
      signal: AbortSignal.any([signal, AbortSignal.timeout(30_000)]),
    });
  } catch {
    throw new ConnectError("Couldn't confirm the assistant access request.", Code.Unavailable);
  }
  if (!response.ok) {
    const code =
      response.status === 400
        ? Code.InvalidArgument
        : response.status === 401
          ? Code.Unauthenticated
          : response.status === 403
            ? Code.PermissionDenied
            : response.status === 429
              ? Code.ResourceExhausted
              : response.status === 503
                ? Code.Unavailable
                : Code.Unknown;
    throw new ConnectError(
      "Couldn't complete the assistant access request.",
      code,
      response.headers,
    );
  }
  try {
    return fromJsonString(schema, await response.text());
  } catch {
    throw new ConnectError("Couldn't read the assistant access response.", Code.DataLoss);
  }
}
