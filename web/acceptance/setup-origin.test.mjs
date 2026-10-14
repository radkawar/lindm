// SPDX-License-Identifier: Apache-2.0
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { consoleSetupDNSWarning } from "../src/features/auth/setup-origin.ts";
import { reviewSetupDNSWarning } from "./review-setup.mjs";

for (const hostname of ["127.0.0.1", "192.0.2.10", "[::1]", "[2001:db8::10]"]) {
  test(`setup requires a DNS origin for ${hostname}`, () => {
    assert.match(consoleSetupDNSWarning(hostname), /DNS name, not an IP address/);
    assert.match(consoleSetupDNSWarning(hostname), /HTTPS certificate/);
  });
}

for (const hostname of ["localhost", "console", "console.example", "127.console.example"]) {
  test(`setup does not warn about IP origins for DNS hostname ${hostname}`, () => {
    assert.equal(consoleSetupDNSWarning(hostname), null);
  });
}

test("setup DOM contract checks DNS absence and IPv4/IPv6 warning visibility", async () => {
  // Unit-test the DOM review contract adapter; live DOM checks run in reviewSetup.
  for (const hostname of ["console.example", "192.0.2.10", "[2001:db8::10]"]) {
    const warning = consoleSetupDNSWarning(hostname);
    const page = {
      evaluate: async () => hostname,
      locator: (selector) => {
        assert.equal(selector, "#setup-dns-warning");
        return {
          isVisible: async () => warning !== null,
          innerText: async () => `Console DNS name required\n${warning}`,
          count: async () => (warning ? 1 : 0),
        };
      },
    };
    let assertions = 0;
    await reviewSetupDNSWarning(page, (condition, message) => {
      assertions++;
      assert.ok(condition, message);
    });
    assert.equal(assertions, warning ? 2 : 1);
  }
});

test("IP warning is setup-only and uses the actual browser hostname", () => {
  const source = readFileSync(
    new URL("../src/features/auth/local-form.tsx", import.meta.url),
    "utf8",
  );
  assert.ok(source.includes("setup ? consoleSetupDNSWarning(window.location.hostname) : null"));
  assert.match(source, /\{dnsWarning \? \(\s*<Alert id="setup-dns-warning">/);
});
