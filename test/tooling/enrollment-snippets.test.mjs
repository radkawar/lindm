import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import test from "node:test";
import {
  provisioningFormats,
  provisioningSnippet,
} from "../../web/src/features/enrollment/snippets.ts";

// Synthetic credential tests serialization only, not enrollment or native success.
const token = "test-credential-only_0123456789abcdef";
const command =
  "/usr/libexec/lindm/lindm-agent bootstrap -root /etc/lindm/execution-root.json -bundle /etc/lindm/bootstrap.dsse.json -provisioning-token-file /etc/lindm/provisioning-token";

function checkShell(script) {
  const result = spawnSync("/bin/sh", ["-n"], { input: script, encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
}

function assertFirstBoot(script) {
  assert.ok(script.includes(command));
  assert.match(script, /resume -wait-seconds 3600/);
  assert.match(script, /TimeoutStartSec=3660/);
  assert.match(script, /ExecStartPost=\/usr\/bin\/rm -f \/etc\/lindm\/provisioning-token/);
  assert.match(
    script,
    /systemctl enable lindm-executor.service lindm-agent.service lindm-provision.service/,
  );
  assert.doesNotMatch(script, /systemctl start|systemctl.*--now/);
}

function assertHeredocToken(script) {
  const content = script.split("<<'LINDM_TOKEN'\n")[1].split("\nLINDM_TOKEN")[0];
  assert.equal(Buffer.from(content, "base64").toString("utf8"), token);
  assert.match(script, /umask 077/);
  assert.match(script, /chmod 0600 \/etc\/lindm\/provisioning-token/);
  assert.ok(!script.includes(token));
}

test("all five formats use authenticated installed bootstrap and bounded approval resume", () => {
  assert.deepEqual(
    provisioningFormats.map((format) => format.value),
    ["cloud-init", "kickstart", "autoinstall", "autoyast", "nixos"],
  );
  for (const { value } of provisioningFormats) {
    const snippet = provisioningSnippet(value, token);
    assert.match(snippet, /-root \/etc\/lindm\/execution-root\.json/);
    assert.match(snippet, /-bundle \/etc\/lindm\/bootstrap\.dsse\.json/);
    assert.match(snippet, /-provisioning-token-file /);
    assert.match(snippet, /resume -wait-seconds 3600/);
    assert.match(snippet, /lindm-executor\.service/);
    assert.doesNotMatch(
      snippet,
      /curl\s|wget\s|--insecure|--bootstrap-manifest|--bootstrap-trust-anchor/,
    );
    assert.doesNotMatch(snippet, /Environment=|environment\.variables/);
  }
});

test("cloud-init delivers the actual token as root-only data, never command arguments", () => {
  const snippet = provisioningSnippet("cloud-init", token);
  assert.ok(snippet.startsWith("#cloud-config\n"));
  const tokenEntry = snippet
    .split("  - path: /etc/lindm/provisioning-token\n")[1]
    .split("  - path:")[0];
  assert.match(tokenEntry, /owner: root:root/);
  assert.match(tokenEntry, /permissions: '0600'/);
  assert.equal(JSON.parse(tokenEntry.split("content: ")[1].trim()), token);
  assert.ok(snippet.includes(`      ${command}`));
  assert.ok(!snippet.split("runcmd:")[1].includes(token));
  assert.match(
    snippet,
    /enable, --now, lindm-executor.service, lindm-agent.service, lindm-provision.service/,
  );
});

test("Kickstart installs a protected token and valid first-boot shell without enrollment in chroot", () => {
  const snippet = provisioningSnippet("kickstart", token);
  const body = snippet.split("%post --erroronfail\n")[1].split("%end")[0];
  checkShell(body);
  assertFirstBoot(body);
  assertHeredocToken(body);
});

test("autoinstall delivers target user-data rather than passing secrets to curtin shell argv", () => {
  const snippet = provisioningSnippet("autoinstall", token);
  assert.match(snippet, /autoinstall:\n  version: 1\n  user-data:/);
  const body = snippet
    .split("  user-data:\n")[1]
    .split("\n")
    .map((line) => line.slice(4))
    .join("\n");
  assert.equal(
    body.trim(),
    provisioningSnippet("cloud-init", token).split("\n").slice(1).join("\n").trim(),
  );
  assert.doesNotMatch(snippet, /curtin.*-ec|late-commands:/);
});

test("AutoYaST chroot hook delivers the protected token without enrollment in chroot", () => {
  const snippet = provisioningSnippet("autoyast", token);
  assert.ok(snippet.startsWith('<?xml version="1.0"?>'));
  assert.match(snippet, /<chrooted config:type="boolean">true<\/chrooted>/);
  const script = snippet.split("<![CDATA[\n")[1].split("]]>")[0];
  checkShell(script);
  assertFirstBoot(script);
  assertHeredocToken(script);
});

test("NixOS consumes a target-encrypted systemd credential without a secret in the Nix store", () => {
  const snippet = provisioningSnippet("nixos", token);
  assert.match(snippet, /type = lib.types.package;/);
  assert.match(snippet, /\$\{cfg.package\}\/libexec\/lindm\/lindm-agent bootstrap/);
  assert.match(
    snippet,
    /LoadCredentialEncrypted = "lindm.provisioning-token:\/etc\/credstore.encrypted\/lindm.provisioning-token";/,
  );
  assert.match(
    snippet,
    /-provisioning-token-file "\$CREDENTIALS_DIRECTORY\/lindm.provisioning-token"/,
  );
  assert.match(snippet, /systemd-creds encrypt --name=lindm.provisioning-token/);
  assert.match(snippet, /User = "root";/);
  assert.match(snippet, /UMask = "0077";/);
  assert.ok(!snippet.includes(token));
  assert.ok(!snippet.includes(btoa(token)));
  assert.doesNotMatch(snippet, /writeText|readFile|environment.etc/);
});
