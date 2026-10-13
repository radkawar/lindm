import assert from "node:assert/strict";
import test from "node:test";
import { StringValueSchema } from "@bufbuild/protobuf/wkt";
import { Code, ConnectError } from "@connectrpc/connect";
import { mcpRequest } from "../src/features/auth/mcp-http.ts";

// These cover the console transport contract, not live authentication or MCP execution.
test("assistant mutations send CSRF and protobuf JSON once with no browser caching", async (t) => {
  let calls = 0;
  t.mock.method(globalThis, "fetch", async (path, options) => {
    calls++;
    assert.equal(path, "/auth/mcp/tokens");
    assert.equal(options.method, "POST");
    assert.equal(options.mode, "same-origin");
    assert.equal(options.credentials, "same-origin");
    assert.equal(options.cache, "no-store");
    assert.equal(options.redirect, "error");
    assert.equal(options.headers["X-CSRF-Token"], "session-csrf");
    assert.equal(options.headers["Content-Type"], "application/json");
    assert.equal(options.body, '"request-value"');
    assert.equal(options.signal.aborted, false);
    return new Response('"shown-once-value"', { status: 200 });
  });
  const result = await mcpRequest(
    "/auth/mcp/tokens",
    StringValueSchema,
    new AbortController().signal,
    '"request-value"',
    "session-csrf",
  );
  assert.equal(result.value, "shown-once-value");
  assert.equal(calls, 1);
});

test("settings reads use GET without a credential body", async (t) => {
  t.mock.method(globalThis, "fetch", async (_path, options) => {
    assert.equal(options.method, "GET");
    assert.equal(options.body, undefined);
    assert.equal(options.headers["X-CSRF-Token"], undefined);
    assert.equal(options.cache, "no-store");
    return new Response('"settings"', { status: 200 });
  });
  assert.equal(
    (await mcpRequest("/auth/mcp/settings", StringValueSchema, new AbortController().signal)).value,
    "settings",
  );
});

for (const [status, code] of [
  [400, Code.InvalidArgument],
  [401, Code.Unauthenticated],
  [403, Code.PermissionDenied],
  [429, Code.ResourceExhausted],
  [503, Code.Unavailable],
  [500, Code.Unknown],
]) {
  test(`HTTP ${status} retains its error classification without response secrets or retries`, async (t) => {
    let calls = 0;
    t.mock.method(globalThis, "fetch", async () => {
      calls++;
      return new Response("PRIVATE_RESPONSE_TOKEN", {
        status,
        headers: { "Lindm-Reason": "forbidden" },
      });
    });
    await assert.rejects(
      mcpRequest("/auth/mcp/tokens", StringValueSchema, new AbortController().signal, "{}", "csrf"),
      (error) => {
        assert.ok(error instanceof ConnectError);
        assert.equal(error.code, code);
        assert.equal(error.metadata.get("Lindm-Reason"), "forbidden");
        assert.equal(String(error).includes("PRIVATE_RESPONSE_TOKEN"), false);
        return true;
      },
    );
    assert.equal(calls, 1);
  });
}

test("lost and unreadable issuance responses remain uncertain and redact decoder diagnostics", async (t) => {
  let calls = 0;
  const mock = t.mock.method(globalThis, "fetch", async () => {
    calls++;
    throw new Error("PRIVATE_TRANSPORT_TOKEN");
  });
  await assert.rejects(
    mcpRequest("/auth/mcp/tokens", StringValueSchema, new AbortController().signal, "{}", "csrf"),
    (error) =>
      error.code === Code.Unavailable && !String(error).includes("PRIVATE_TRANSPORT_TOKEN"),
  );
  assert.equal(calls, 1);
  mock.mock.mockImplementation(async () => {
    calls++;
    return new Response('{"PRIVATE_RESPONSE_TOKEN":', { status: 200 });
  });
  await assert.rejects(
    mcpRequest("/auth/mcp/tokens", StringValueSchema, new AbortController().signal, "{}", "csrf"),
    (error) => error.code === Code.DataLoss && !String(error).includes("PRIVATE_RESPONSE_TOKEN"),
  );
  assert.equal(calls, 2);
});

test("session cancellation reaches the HTTP request", async (t) => {
  const controller = new AbortController();
  controller.abort();
  t.mock.method(globalThis, "fetch", async (_path, options) => {
    assert.equal(options.signal.aborted, true);
    throw new DOMException("Aborted", "AbortError");
  });
  await assert.rejects(
    mcpRequest("/auth/mcp/settings", StringValueSchema, controller.signal),
    (error) => error.code === Code.Unavailable,
  );
});
