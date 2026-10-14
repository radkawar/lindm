// SPDX-License-Identifier: Apache-2.0

import { Code, ConnectError, createClient, type Interceptor } from "@connectrpc/connect";
import { createConnectTransport } from "@connectrpc/connect-web";
import { AdminService } from "../../gen/lindm/admin/v1/admin_pb";
import { IntegrationService } from "../../gen/lindm/integrations/v1/delivery_pb";
import { ReportService } from "../../gen/lindm/integrations/v1/reports_pb";
import { checkRequest } from "@/lib/validation";

let csrfToken = "";

export function setCsrfToken(token: string): void {
  csrfToken = token;
}

export function clearCsrfToken(): void {
  csrfToken = "";
}

const csrfInterceptor: Interceptor = (next) => async (request) => {
  if (csrfToken === "") {
    throw new Error("Refusing the API call without a CSRF token.");
  }
  request.header.set("X-CSRF-Token", csrfToken);
  return await next(request);
};

// Every request passes the protos' rules and encodes before it leaves, so a bad
// form value surfaces as a definite field error (see toRpcFailure), never as
// encoder text or an "outcome unknown" transport failure.
const requestGuard: Interceptor = (next) => async (request) => {
  const problem = request.stream ? undefined : checkRequest(request.method.input, request.message);
  if (problem)
    throw new ConnectError(problem.message, Code.InvalidArgument, undefined, undefined, problem);
  return await next(request);
};

const transport = createConnectTransport({
  baseUrl: location.origin,
  defaultTimeoutMs: 30_000,
  interceptors: [requestGuard, csrfInterceptor],
  fetch: (input, init) => fetch(input, { ...init, credentials: "same-origin", cache: "no-store" }),
});

export const adminClient = Object.assign(
  createClient(AdminService, transport),
  createClient(IntegrationService, transport),
  createClient(ReportService, transport),
);
