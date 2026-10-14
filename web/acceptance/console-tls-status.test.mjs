// SPDX-License-Identifier: Apache-2.0
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const source = (path) => readFileSync(new URL(path, import.meta.url), "utf8");

test("operational HTTPS checks retain distinct console and device resource identities", () => {
  const backend = source("../../internal/server/status_linux.go");
  assert.match(
    backend,
    /certificateStatus\("https_certificate", resources\.AdminServerCertificate\.Leaf, now\)/,
  );
  assert.match(
    backend,
    /certificateStatus\("device_https_certificate", resources\.ServerCertificate\.Leaf, now\)/,
  );
  assert.match(backend, /certificateStatus\("console_ca", resources\.AdminCACertificate, now\)/);
  assert.match(backend, /certificateStatus\("device_ca", resources\.DeviceCACertificate, now\)/);
  const monitor = source("../../internal/server/status.go");
  for (const component of [
    "https_certificate",
    "console_ca",
    "device_https_certificate",
    "device_ca",
  ]) {
    assert.ok(monitor.includes(`"${component}"`));
  }
});

test("setup alone offers conditional console CA guidance and preserves password help", () => {
  const form = source("../src/features/auth/local-form.tsx");
  assert.match(
    form,
    /\{setup \? \(\s*<p[^>]*>\s*If this console uses a private CA, import the console CA printed by the installer, not the\s+device CA\. A publicly trusted console certificate needs no custom CA import\.\s*<\/p>\s*\) : null\}/,
  );
  assert.ok(form.includes('aria-describedby={setup ? "setup-password-help" : undefined}'));
  assert.ok(
    form.includes("Use at least 12 bytes. Have a security key or passkey ready for the next step."),
  );
});

test("status labels distinguish console trust, device transport, and device client trust", () => {
  const view = source("../src/features/server-status/view.tsx");
  for (const [id, label] of [
    ["https_certificate", "Console HTTPS certificate"],
    ["console_ca", "Console certificate authority"],
    ["device_https_certificate", "Device HTTPS certificate"],
    ["device_ca", "Device client certificate authority"],
  ]) {
    assert.ok(view.includes(`${id}: "${label}"`));
  }
  assert.ok(view.includes(".sort((a, b) => CHECK_PRIORITY[a.state] - CHECK_PRIORITY[b.state])"));
});
