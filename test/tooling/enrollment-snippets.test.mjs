import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import test from "node:test";
import {
  enrollmentInstallScript,
  grantSnippet,
  provisioningFormats,
  provisioningSnippet,
} from "../../web/src/features/enrollment/snippets.ts";

// Synthetic public metadata and credentials; not native installation evidence.
const token = "test-credential-only_0123456789abcdef";
const command =
  "/usr/libexec/lindm/lindm-agent bootstrap -root /etc/lindm/execution-root.json -bundle /etc/lindm/bootstrap.dsse.json -provisioning-token-file /etc/lindm/provisioning-token";
const ready = { ready: true, reason: "", remedy: "" };
const platform = {
  id: "ubuntu-24.04",
  label: "Ubuntu 24.04 LTS",
  osId: "ubuntu",
  versionIds: ["24.04"],
  versionRule: "exact",
  variantIds: [],
  packageFamily: "apt",
  architectures: ["arm64"],
  readiness: ready,
};
const instructions = {
  readiness: ready,
  platforms: [platform],
  executionRootUrl: "https://mdm.example.test/repo/execution-root.json",
  executionRootSha256: "a".repeat(64),
  bootstrapBundleUrl: "https://mdm.example.test/repo/bootstrap.dsse.json",
  grantCommand: command.replace(
    "-provisioning-token-file /etc/lindm/provisioning-token",
    "-grant-file /run/lindm-enrollment/grant",
  ),
  provisioningCommand: command,
  resumeCommand: "/usr/libexec/lindm/lindm-agent resume -wait-seconds 3600",
  aptRepository: {
    baseUrl: "https://mdm.example.test/repo/apt",
    suite: "stable",
    components: ["main"],
    signingKeyUrl: "https://mdm.example.test/repo/apt/lindm-package-signing.asc",
    signingKeyFingerprint: "A".repeat(40),
  },
  dnfRepository: {
    baseUrl: "https://mdm.example.test/repo/rpm",
    signingKeyUrl: "https://mdm.example.test/repo/rpm/lindm-package-signing.asc",
    signingKeyFingerprint: "B".repeat(40),
  },
  archRepository: {
    baseUrl: "https://mdm.example.test/repo/arch",
    repositoryName: "lindm",
    signingKeyUrl: "https://mdm.example.test/repo/arch/lindm-package-signing.asc",
    signingKeyFingerprint: "D".repeat(40),
  },
};
const install = enrollmentInstallScript(instructions, platform);

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

test("missing publication or trust never produces an install or enrollment command", () => {
  assert.equal(enrollmentInstallScript(undefined, platform), "");
  assert.equal(
    enrollmentInstallScript({ ...instructions, readiness: { ready: false } }, platform),
    "",
  );
  assert.equal(
    enrollmentInstallScript(instructions, { ...platform, readiness: { ready: false } }),
    "",
  );
  assert.equal(enrollmentInstallScript({ ...instructions, executionRootSha256: "" }, platform), "");
  assert.equal(
    enrollmentInstallScript({ ...instructions, tlsCaPem: "unpaired certificate" }, platform),
    "",
  );
  assert.equal(enrollmentInstallScript(instructions, { ...platform, packageFamily: "nix" }), "");
  assert.equal(
    enrollmentInstallScript(
      { ...instructions, archRepository: undefined },
      { ...platform, packageFamily: "pacman" },
    ),
    "",
  );
  assert.equal(grantSnippet(token, instructions, ""), "");
  assert.equal(provisioningSnippet("cloud-init", token, instructions, ""), "");
});

test("one shell command supplies the secret on stdin and authenticates deployment trust", () => {
  const snippet = grantSnippet(token, instructions, install);
  checkShell(snippet);
  assert.ok(snippet.startsWith("sudo sh <<'LINDM_ENROLL'\n"));
  const content = snippet.split("<<'LINDM_GRANT'\n")[1].split("\nLINDM_GRANT")[0];
  assert.equal(Buffer.from(content, "base64").toString("utf8"), token);
  assert.ok(!snippet.includes(token));
  assert.ok(snippet.includes(instructions.executionRootSha256));
  assert.ok(snippet.includes(instructions.aptRepository.signingKeyFingerprint));
  assert.ok(
    snippet.indexOf("sha256sum --check --status") < snippet.indexOf(instructions.grantCommand),
  );
  assert.match(snippet, /trap 'rm -f \/run\/lindm-enrollment\/grant' EXIT/);
  assert.match(snippet, /timeout 30 sh -c 'until test -S \/run\/lindm\/executor.sock/);
  assert.equal(snippet.split(instructions.grantCommand).length, 2);
  assert.ok(snippet.indexOf("timeout 30") < snippet.indexOf(instructions.grantCommand));
  assert.doesNotMatch(
    snippet,
    /--insecure|--location|AllowUnauthenticated=true|trusted=yes|curl[^\n]*\|\s*(sh|bash)/,
  );
});

test("APT publishes a deb822 source restricted to its pinned signing key", () => {
  assert.match(
    install,
    /Types: deb\nURIs: https:\/\/mdm.example.test\/repo\/apt\nSuites: stable\nComponents: main\nSigned-By: \/etc\/apt\/keyrings\/lindm.gpg/,
  );
  assert.match(install, /\/etc\/apt\/sources.list.d\/lindm.sources/);
  assert.doesNotMatch(install, /\/etc\/apt\/sources.list.d\/lindm.list/);
});

test("pacman refreshes only lindmd but retains native dependency resolution", () => {
  const script = enrollmentInstallScript(instructions, { ...platform, packageFamily: "pacman" });
  checkShell(script);
  assert.match(script, /pacman --config "\$work\/pacman.conf" --sync --refresh --noconfirm\n/);
  assert.match(script, /pacman --sync --noconfirm 'lindm\/lindm-agent'/);
  assert.doesNotMatch(script, /pacman --config[^\n]*lindm-agent/);
  assert.doesNotMatch(script, /pacman --sync --refresh/);
});

test("every native manager shares CA certificate and execution-root authentication", () => {
  for (const family of ["apt", "dnf", "zypper", "pacman"]) {
    const data = {
      ...instructions,
      tlsCaPem: "fixture certificate bytes",
      tlsCaSha256: "c".repeat(64),
    };
    const script = enrollmentInstallScript(data, { ...platform, packageFamily: family });
    checkShell(script);
    assert.match(script, /openssl x509 -in "\$work\/ca.pem" -outform DER/);
    assert.ok(script.indexOf(data.tlsCaSha256) < script.indexOf("update-ca-"));
    assert.match(script, /curl --disable .*--cacert "\$work\/ca.pem"/);
    assert.ok(script.includes(data.executionRootSha256));
    assert.ok(script.indexOf("--show-keys") < script.indexOf("lindm-agent"));
  }
});

test("all native provisioning formats reuse the secure install script", () => {
  assert.deepEqual(
    provisioningFormats.map(({ value }) => value),
    ["cloud-init", "kickstart", "autoinstall", "autoyast", "nixos"],
  );
  for (const format of ["cloud-init", "kickstart", "autoinstall", "autoyast"]) {
    const snippet = provisioningSnippet(format, token, instructions, install);
    assert.ok(snippet.includes(instructions.executionRootSha256));
    assert.ok(snippet.includes(instructions.aptRepository.signingKeyFingerprint));
    assert.match(snippet, /resume -wait-seconds 3600/);
  }
});

test("cloud-init delivers the token as root-only data, never command arguments", () => {
  const snippet = provisioningSnippet("cloud-init", token, instructions, install);
  const tokenEntry = snippet
    .split("  - path: /etc/lindm/provisioning-token\n")[1]
    .split("  - path:")[0];
  assert.match(tokenEntry, /owner: root:root/);
  assert.match(tokenEntry, /permissions: '0600'/);
  assert.equal(JSON.parse(tokenEntry.split("content: ")[1].trim()), token);
  assert.ok(snippet.includes(`      ${command}`));
  assert.ok(!snippet.split("runcmd:")[1].includes(token));
  const runcmd = JSON.parse(snippet.split("  - [sh, -c, ")[1].split("]\n")[0]);
  checkShell(runcmd);
  assert.match(
    runcmd,
    /systemctl enable --now lindm-executor.service lindm-agent.service lindm-provision.service/,
  );
});

test("Kickstart and AutoYaST stage first-boot enrollment without enrolling in chroot", () => {
  for (const format of ["kickstart", "autoyast"]) {
    const snippet = provisioningSnippet(format, token, instructions, install);
    const body =
      format === "kickstart"
        ? snippet.split("%post --erroronfail\n")[1].split("%end")[0]
        : snippet.split("<![CDATA[\n")[1].split("]]>")[0];
    checkShell(body);
    assertFirstBoot(body);
    assertHeredocToken(body);
  }
});

test("autoinstall supplies cloud-init user-data, not secret shell arguments", () => {
  const snippet = provisioningSnippet("autoinstall", token, instructions, install);
  const body = snippet
    .split("  user-data:\n")[1]
    .split("\n")
    .map((line) => line.slice(4))
    .join("\n");
  assert.equal(
    body.trim(),
    provisioningSnippet("cloud-init", token, instructions, install)
      .split("\n")
      .slice(1)
      .join("\n")
      .trim(),
  );
  assert.doesNotMatch(snippet, /curtin.*-ec|late-commands:/);
});

test("NixOS retains the verified-derivation and target-encrypted credential path", () => {
  const snippet = provisioningSnippet("nixos", token, instructions, "");
  assert.match(snippet, /\$\{cfg.package\}\/libexec\/lindm\/lindm-agent bootstrap/);
  assert.match(snippet, /LoadCredentialEncrypted = "lindm.provisioning-token:/);
  assert.match(
    snippet,
    /-provisioning-token-file "\$CREDENTIALS_DIRECTORY\/lindm.provisioning-token"/,
  );
  assert.ok(!snippet.includes(token));
  assert.ok(!snippet.includes(btoa(token)));
  assert.doesNotMatch(snippet, /writeText|readFile|environment.etc/);
});
