// SPDX-License-Identifier: Apache-2.0

import { toJsonString } from "@bufbuild/protobuf";
import { Code, ConnectError } from "@connectrpc/connect";
import { queryOptions } from "@tanstack/react-query";
import {
  MCPSettingsSchema,
  IssueMCPTokenRequestSchema,
  IssueMCPTokenResponseSchema,
  RevokeMCPTokenRequestSchema,
  RevokeMCPTokenResponseSchema,
  UpdateMCPSettingsRequestSchema,
  type IssueMCPTokenRequest,
  type RevokeMCPTokenRequest,
  type UpdateMCPSettingsRequest,
} from "../../../gen/lindm/auth/v1/mcp_pb";
import type { AuthLifetime } from "@/lib/auth-lifetime";
import { validateRequest } from "@/lib/validation";
import { mcpRequest } from "./mcp-http";

export function mcpSettingsQueryOptions(lifetime: AuthLifetime) {
  return queryOptions({
    queryKey: ["mcp-settings", lifetime.generation],
    meta: { authGeneration: lifetime.generation },
    queryFn: ({ signal }) =>
      mcpRequest(
        "/auth/mcp/settings",
        MCPSettingsSchema,
        AbortSignal.any([signal, lifetime.signal]),
      ),
    refetchInterval: 30_000,
  });
}

export async function updateMCPSettings(
  request: UpdateMCPSettingsRequest,
  csrf: string,
  signal: AbortSignal,
) {
  validateRequest(UpdateMCPSettingsRequestSchema, request);
  return mcpRequest(
    "/auth/mcp/settings",
    MCPSettingsSchema,
    signal,
    toJsonString(UpdateMCPSettingsRequestSchema, request),
    csrf,
  );
}

export async function issueMCPToken(
  request: IssueMCPTokenRequest,
  csrf: string,
  signal: AbortSignal,
) {
  validateRequest(IssueMCPTokenRequestSchema, request);
  const result = await mcpRequest(
    "/auth/mcp/tokens",
    IssueMCPTokenResponseSchema,
    signal,
    toJsonString(IssueMCPTokenRequestSchema, request),
    csrf,
  );
  if (!result.bearerToken || !result.token?.id)
    throw new ConnectError("Couldn't confirm the new assistant token.", Code.DataLoss);
  return result;
}

export async function revokeMCPToken(
  request: RevokeMCPTokenRequest,
  csrf: string,
  signal: AbortSignal,
) {
  validateRequest(RevokeMCPTokenRequestSchema, request);
  await mcpRequest(
    "/auth/mcp/tokens/revoke",
    RevokeMCPTokenResponseSchema,
    signal,
    toJsonString(RevokeMCPTokenRequestSchema, request),
    csrf,
  );
}
