// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmodSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
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
    assert.ok(snippet.includes(`ExecStart=${command}\n`));
    assert.ok(snippet.includes(`ExecStart=${instructions.resumeCommand}\n`));
    assert.match(snippet, /TimeoutStartSec=3700/);
    assert.match(snippet, /ExecStartPost=\/usr\/bin\/rm -f \/etc\/lindm\/provisioning-token/);
    // No script under /etc is executed: SELinux labels it etc_t, not a service executable.
    assert.doesNotMatch(snippet, /provision-at-boot/);
  }
});

test("cloud-init delivers the token as root-only data and never blocks first boot", () => {
  const snippet = provisioningSnippet("cloud-init", token, instructions, install);
  const tokenEntry = snippet
    .split("  - path: /etc/lindm/provisioning-token\n")[1]
    .split("  - path:")[0];
  assert.match(tokenEntry, /owner: root:root/);
  assert.match(tokenEntry, /permissions: '0600'/);
  assert.equal(JSON.parse(tokenEntry.split("content: ")[1].trim()), token);
  assert.ok(snippet.includes(`      ExecStart=${command}`));
  assert.ok(!snippet.split("runcmd:")[1].includes(token));
  const runcmd = JSON.parse(snippet.split("  - [sh, -c, ")[1].split("]\n")[0]);
  checkShell(runcmd);
  assert.match(runcmd, /systemctl enable --now lindm-executor.service lindm-agent.service\n/);
  // The approval wait lasts up to an hour; cloud-final must not wait for it.
  assert.match(runcmd, /systemctl enable lindm-provision.service\n/);
  assert.match(runcmd, /systemctl start --no-block lindm-provision.service$/);
  assert.doesNotMatch(runcmd, /--now[^\n]*lindm-provision/);
});

test("Kickstart and AutoYaST install in the target chroot and only enable first-boot units", () => {
  for (const format of ["kickstart", "autoyast"]) {
    const snippet = provisioningSnippet(format, token, instructions, install);
    const body =
      format === "kickstart"
        ? snippet.split("%post --erroronfail --interpreter=/bin/sh\n")[1].split("%end")[0]
        : snippet.split("<![CDATA[\n")[1].split("]]>")[0];
    checkShell(body);
    assertHeredocToken(body);
    assert.ok(body.indexOf("install lindm-agent") < body.indexOf("<<'LINDM_TOKEN'"));
    assert.match(body, /chmod 0644 \/etc\/systemd\/system\/lindm-provision.service/);
    assert.match(body, /selinuxenabled; then\n {2}restorecon -RF \/etc\/lindm /);
    assert.match(
      body,
      /systemctl enable lindm-executor.service lindm-agent.service lindm-provision.service\n?$/,
    );
    assert.doesNotMatch(body, /systemctl (start|restart)|--now|daemon-reload/);
  }
  const autoyast = provisioningSnippet("autoyast", token, instructions, install);
  assert.match(autoyast, /<chroot-scripts config:type="list">\n {6}<script>\n/);
  assert.match(autoyast, /<chrooted config:type="boolean">true<\/chrooted>/);
  // Without its own lock root zypper fails: YaST holds /run/zypp.pid. The
  // variable is exported before the installer script and its subshells.
  const script = autoyast.split("<![CDATA[\n")[1];
  const exported = script.indexOf("export ZYPP_LOCKFILE_ROOT=/var/run/autoyast\n");
  assert.ok(exported >= 0 && exported < script.indexOf("set -eu\n"));
  assert.doesNotMatch(
    provisioningSnippet("kickstart", token, instructions, install),
    /ZYPP_LOCKFILE_ROOT/,
  );
  // An unregistered RHEL 10.2 DVD install has no repository in %post and its
  // selection lacks openssl/gnupg2, so the profile must list them.
  assert.match(
    provisioningSnippet("kickstart", token, instructions, install),
    /^# list ca-certificates curl gnupg2 openssl in the profile's %packages\.$/m,
  );
});

test("autoinstall supplies first-boot cloud-init user-data, not secret shell arguments", () => {
  const snippet = provisioningSnippet("autoinstall", token, instructions, install);
  assert.match(snippet, /\nautoinstall:\n {2}version: 1\n {2}user-data:\n/);
  const body = snippet
    .split("  user-data:\n")[1]
    .split("\n")
    .map((line) => line.slice(4))
    .join("\n");
  const cloudInit = provisioningSnippet("cloud-init", token, instructions, install);
  assert.equal(body, `write_files:${cloudInit.split("\nwrite_files:")[1]}`);
  assert.doesNotMatch(snippet, /curtin|late-commands:/);
});

test("DNF and zypper installs work without distribution repositories in an installer target", () => {
  const dnf = enrollmentInstallScript(instructions, { ...platform, packageFamily: "dnf" });
  checkShell(dnf);
  assert.match(dnf, /if ! rpm -q ca-certificates gnupg2 openssl >\/dev\/null 2>&1; then\n/);
  const zypper = enrollmentInstallScript(instructions, { ...platform, packageFamily: "zypper" });
  checkShell(zypper);
  assert.match(zypper, /if ! rpm -q ca-certificates curl gpg2 openssl >\/dev\/null 2>&1; then\n/);
  assert.match(zypper, /type=rpm-md\n/);
  assert.doesNotMatch(zypper, /localpkg_gpgcheck|sslverify/);
  // Only lindmd's repository is refreshed and searched; install media are not.
  assert.match(zypper, /zypper --non-interactive --reposd-dir "\$work\/repos.d" refresh lindm\n/);
  assert.match(
    zypper,
    /zypper --non-interactive --reposd-dir "\$work\/repos.d" install --no-recommends --from lindm lindm-agent/,
  );
});

test("NixOS is a registry gate, never a snippet depending on outside hosting", () => {
  assert.equal(provisioningSnippet("nixos", token, instructions, install), "");
});

// Runs the install script's apt_get against a stand-in apt-get that prints the
// given stderr lines (one invocation per entry, last one repeating) and exits
// 100, or exits 0 for "ok"; date advances 100 s per call and sleep is free.
function runAptGet(responses) {
  const dir = mkdtempSync(join(tmpdir(), "lindm-apt-"));
  const fake = (name, body) => {
    writeFileSync(join(dir, name), `#!/bin/sh\n${body}\n`);
    chmodSync(join(dir, name), 0o755);
  };
  writeFileSync(join(dir, "responses"), responses.join("\n@@\n"));
  fake(
    "apt-get",
    `n=$(cat "${dir}/calls" 2>/dev/null || echo 0); echo $((n + 1)) > "${dir}/calls"
printf '%s\\n' "$*" >> "${dir}/args"
r=$(awk -v n="$n" 'BEGIN { RS = "\\n@@\\n" } { last = $0; if (NR - 1 == n) { print; found = 1; exit } } END { if (!found) print last }' "${dir}/responses")
test "$r" = ok && exit 0
printf '%s\\n' "$r" >&2; exit 100`,
  );
  fake(
    "date",
    `n=$(cat "${dir}/clock" 2>/dev/null || echo 0); echo $((n + 100)) > "${dir}/clock"; echo "$n"`,
  );
  fake("sleep", "exit 0");
  const start = install.indexOf("apt_get() {");
  const fn = install.slice(start, install.indexOf("\n}\n", start) + 3);
  const result = spawnSync("/bin/sh", ["-c", `set -eu\nwork=${dir}\n${fn}apt_get update`], {
    encoding: "utf8",
    env: { PATH: `${dir}:/usr/bin:/bin` },
  });
  const calls = Number(readFileSync(join(dir, "calls"), "utf8"));
  const args = readFileSync(join(dir, "args"), "utf8");
  return { status: result.status, stderr: result.stderr, calls, args };
}

const listsLock =
  "E: Could not get lock /var/lib/apt/lists/lock. It is held by process 1234 (apt-get)\nE: Unable to lock directory /var/lib/apt/lists/";
const frontendLock =
  "E: Could not get lock /var/lib/dpkg/lock-frontend. It is held by process 6853 (dpkg)\nE: Unable to acquire the dpkg frontend lock (/var/lib/dpkg/lock-frontend), is another process using it?";

// pop-system-updater's boot refresh held APT's lists lock and the copied
// command exited 100 on Pop!_OS 24.04; DPkg::Lock::Timeout does not cover
// apt-get update's lists lock, so the script waits only on lock refusals.
test("APT commands wait for another package manager's locks, bounded, and fail on anything else", () => {
  checkShell(install);
  assert.doesNotMatch(install.replace(/apt_get\(\) \{[\s\S]*?\n\}\n/, ""), /(^|\n)apt-get /);
  assert.equal(install.match(/\napt_get /g).length, 4);
  for (const format of ["cloud-init", "autoinstall"]) {
    assert.ok(provisioningSnippet(format, token, instructions, install).includes("apt_get() {"));
  }

  const waited = runAptGet([listsLock, frontendLock, "ok"]);
  assert.equal(waited.status, 0, waited.stderr);
  assert.equal(waited.calls, 3);
  assert.equal(waited.stderr.match(/Waiting for another package manager to finish…/g).length, 1);
  assert.match(waited.args, /^-o DPkg::Lock::Timeout=600 update$/m);

  const broken = runAptGet([
    `${listsLock}\nE: The repository 'https://mdm.example.test/repo/apt stable Release' is not signed.`,
  ]);
  assert.notEqual(broken.status, 0);
  assert.equal(broken.calls, 1);
  assert.match(broken.stderr, /is not signed/);

  const silent = runAptGet([""]);
  assert.notEqual(silent.status, 0);
  assert.equal(silent.calls, 1);

  const held = runAptGet([listsLock]);
  assert.notEqual(held.status, 0);
  assert.ok(held.calls > 1 && held.calls <= 7, `lock wait unbounded: ${held.calls} calls`);
  assert.match(held.stderr, /Could not get lock/);
});
