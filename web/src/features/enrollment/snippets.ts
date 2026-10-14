// SPDX-License-Identifier: Apache-2.0

import type { GetEnrollmentInstructionsResponse } from "../../../gen/lindm/admin/v1/enrollment_instructions_pb";

type Platform = GetEnrollmentInstructionsResponse["platforms"][number];

// Values are the registry's provisioning format names (EnrollmentPlatform
// provisioning_formats); the server decides which releases offer each one.
export const provisioningFormats = [
  { value: "cloud-init", label: "cloud-init" },
  { value: "kickstart", label: "Kickstart" },
  { value: "autoinstall", label: "Ubuntu autoinstall" },
  { value: "autoyast", label: "AutoYaST" },
  { value: "nixos", label: "NixOS" },
] as const;

export type ProvisioningFormat = (typeof provisioningFormats)[number]["value"];

const tokenFile = "/etc/lindm/provisioning-token";
const unitFile = "/etc/systemd/system/lindm-provision.service";
const executorReady = `timeout 30 sh -c 'until test -S /run/lindm/executor.sock && /usr/libexec/lindm/lindm-agent status >/dev/null 2>&1; do sleep 1; done' || {
  echo 'Executor did not become ready within 30 seconds. Check lindm-executor.service before retrying enrollment.' >&2
  exit 1
}`;
const prerequisites = `# SENSITIVE BOOT INPUT: contains a reusable, bounded provisioning token.
# Deliver only to intended installations; never embed in a reusable/golden image.
# Installs from this server's signed repository and pins deployment trust.
# Protect installer/seed transport and retained copies; revoke unused credentials.
# Enrollment waits at most 3600 seconds for independent approval, then fails visibly.
`;

// The first-boot unit runs the installed agent's exact server templates. It
// executes no file from /etc: package-installed binaries keep their native
// labels, and the unit needs no separately written script.
function provisionUnit(instructions: GetEnrollmentInstructionsResponse): string {
  return `[Unit]
Description=Lindm first-boot enrollment with bounded approval wait
After=network-online.target lindm-executor.service
Wants=network-online.target
Requires=lindm-executor.service
ConditionPathExists=${tokenFile}

[Service]
Type=oneshot
UMask=0077
TimeoutStartSec=3700
ExecStartPre=/usr/bin/timeout 30 /bin/sh -c 'until test -S /run/lindm/executor.sock && /usr/libexec/lindm/lindm-agent status >/dev/null 2>&1; do sleep 1; done'
ExecStart=${instructions.provisioningCommand}
ExecStart=${instructions.resumeCommand}
ExecStartPost=/usr/bin/rm -f ${tokenFile}
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target`;
}

// cloud-config body shared by cloud-init and autoinstall user-data. It runs on
// the installed system's first boot, where systemd and the network are up.
// The enrollment unit starts without blocking: it waits up to an hour for
// approval and must not hold cloud-init's final stage or login.
function cloudConfig(
  secret: string,
  instructions: GetEnrollmentInstructionsResponse,
  installScript: string,
): string {
  const start = `set -eu
${installScript}
systemctl daemon-reload
systemctl enable --now lindm-executor.service lindm-agent.service
systemctl enable lindm-provision.service
systemctl start --no-block lindm-provision.service`;
  return `write_files:
  - path: ${tokenFile}
    owner: root:root
    permissions: '0600'
    content: ${JSON.stringify(secret)}
  - path: ${unitFile}
    owner: root:root
    permissions: '0644'
    content: |
${provisionUnit(instructions).replaceAll(/^/gm, "      ")}
runcmd:
  - [sh, -c, ${JSON.stringify(start)}]`;
}

// Kickstart %post and AutoYaST chroot scripts run inside the installed target
// before its first boot: the installer's network is active, but the target's
// systemd is not running, so units are only enabled. Enrollment happens on the
// first boot. Base64 is not encryption; it only keeps the token out of shell syntax.
function installerScript(
  secret: string,
  instructions: GetEnrollmentInstructionsResponse,
  installScript: string,
): string {
  return `set -eu
umask 077
${installScript}
install -d -m 0755 /etc/lindm
base64 -d > ${tokenFile} <<'LINDM_TOKEN'
${btoa(secret)}
LINDM_TOKEN
chmod 0600 ${tokenFile}
cat > ${unitFile} <<'LINDM_UNIT'
${provisionUnit(instructions)}
LINDM_UNIT
chmod 0644 ${unitFile}
if command -v selinuxenabled >/dev/null 2>&1 && selinuxenabled; then
  restorecon -RF /etc/lindm ${unitFile}
fi
systemctl enable lindm-executor.service lindm-agent.service lindm-provision.service`;
}

// Returns "" unless every pin is available; NixOS is a registry gate, not a snippet.
export function provisioningSnippet(
  format: ProvisioningFormat,
  secret: string,
  instructions: GetEnrollmentInstructionsResponse,
  installScript: string,
): string {
  if (!installScript) return "";
  switch (format) {
    case "cloud-init":
      return `#cloud-config
${prerequisites}${cloudConfig(secret, instructions, installScript)}
`;
    case "kickstart":
      return `${prerequisites}# Merge this %post section into the complete trusted Kickstart profile.
# It runs in the installed target, so the installer network must be active
# (for example network --activate) and reach this server. A target with no
# reachable distribution repository (an unregistered RHEL DVD install) must
# list ca-certificates curl gnupg2 openssl in the profile's %packages.
%post --erroronfail --interpreter=/bin/sh
${installerScript(secret, instructions, installScript)}
%end
`;
    case "autoinstall":
      return `#cloud-config
${prerequisites}# Merge these fields into the complete trusted autoinstall configuration.
# The installed system's cloud-init applies user-data on its first boot.
autoinstall:
  version: 1
  user-data:
${cloudConfig(secret, instructions, installScript).replaceAll(/^/gm, "    ")}
`;
    case "autoyast":
      return `<?xml version="1.0"?>
<!-- SENSITIVE installer profile: reusable, bounded provisioning token.
     Protect seed transport and retained installer copies; never embed in a
     golden image. Merge the chroot script into your complete AutoYaST profile.
     It runs in the installed target with the installer network, installs from
     this server's signed repository with pinned deployment trust, and enables
     enrollment for the first boot. -->
<profile xmlns="http://www.suse.com/1.0/yast2ns" xmlns:config="http://www.suse.com/1.0/configns">
  <scripts>
    <chroot-scripts config:type="list">
      <script>
        <filename>lindm-enroll.sh</filename>
        <chrooted config:type="boolean">true</chrooted>
        <interpreter>shell</interpreter>
        <source><![CDATA[
# YaST holds the system zypp lock while AutoYaST scripts run; zypper here
# uses the separate lock root the AutoYaST guide documents for scripts.
export ZYPP_LOCKFILE_ROOT=/var/run/autoyast
${installerScript(secret, instructions, installScript)}
]]></source>
      </script>
    </chroot-scripts>
  </scripts>
</profile>
`;
    case "nixos":
      return "";
  }
}

export function grantSnippet(
  secret: string,
  instructions: GetEnrollmentInstructionsResponse,
  installScript: string,
): string {
  if (!installScript) return "";
  // A single shell command, with sensitive input on stdin rather than sudo argv.
  return `sudo sh <<'LINDM_ENROLL'
set -eu
test "$(id -u)" -eq 0
umask 077
${installScript}
install -d -o root -g root -m 0700 /run/lindm-enrollment
trap 'rm -f /run/lindm-enrollment/grant' EXIT
base64 -d > /run/lindm-enrollment/grant <<'LINDM_GRANT'
${btoa(secret)}
LINDM_GRANT
chmod 0600 /run/lindm-enrollment/grant
systemctl enable --now lindm-executor.service lindm-agent.service
${executorReady}
${instructions.grantCommand}
${instructions.resumeCommand}
LINDM_ENROLL
`;
}

function shellQuote(value: string): string {
  return `'${value.replaceAll("'", "'\"'\"'")}'`;
}

export function enrollmentInstallScript(
  instructions: GetEnrollmentInstructionsResponse | undefined,
  platform: Platform | undefined,
): string {
  if (!instructions?.readiness?.ready || !platform?.readiness?.ready) return "";
  const family = platform.packageFamily;
  const repository =
    family === "apt"
      ? instructions.aptRepository
      : family === "pacman"
        ? instructions.archRepository
        : instructions.dnfRepository;
  if (!repository || !["apt", "dnf", "zypper", "pacman"].includes(family)) return "";
  if (
    !instructions.executionRootUrl ||
    !instructions.executionRootSha256 ||
    !instructions.bootstrapBundleUrl ||
    !repository.signingKeyFingerprint ||
    !platform.architectures.length
  )
    return "";
  if (!!instructions.tlsCaPem !== !!instructions.tlsCaSha256) return "";

  const caDirectory =
    family === "apt"
      ? "/usr/local/share/ca-certificates"
      : family === "zypper"
        ? "/etc/pki/trust/anchors"
        : family === "pacman"
          ? "/etc/ca-certificates/trust-source/anchors"
          : "/etc/pki/ca-trust/source/anchors";
  const privateCA =
    instructions.tlsCaPem && instructions.tlsCaSha256
      ? `printf '%s' ${shellQuote(instructions.tlsCaPem)} > "$work/ca.pem"
openssl x509 -in "$work/ca.pem" -outform DER -out "$work/ca.der"
printf '%s  %s\\n' ${shellQuote(instructions.tlsCaSha256)} "$work/ca.der" | sha256sum --check --status
install -d -m 0755 ${caDirectory}
install -m 0644 "$work/ca.pem" ${caDirectory}/lindm.crt
${family === "apt" || family === "zypper" ? "update-ca-certificates" : "update-ca-trust"}
`
      : "";
  const fetch = `curl --disable --fail --silent --show-error --proto '=https' --tlsv1.2${instructions.tlsCaPem ? ' --cacert "$work/ca.pem"' : ""}`;
  const verifyKey = `${fetch} ${shellQuote(repository.signingKeyUrl)} -o "$work/key.asc"
gpg --batch --with-colons --show-keys "$work/key.asc" > "$work/key-info"
test "$(awk -F: '$1 == "pub" { primary = 1; next } primary && $1 == "fpr" { print $10; primary = 0 }' "$work/key-info")" = ${shellQuote(repository.signingKeyFingerprint)}`;
  const versionPatterns = platform.versionIds
    .flatMap((version) =>
      platform.versionRule === "major"
        ? [shellQuote(version), `${shellQuote(`${version}.`)}*`]
        : [shellQuote(version)],
    )
    .join("|");
  const versionCheck = versionPatterns
    ? `${platform.versionRule === "major" ? `case "\${VERSION_ID:-}" in *.*.*) echo 'Selected operating system version does not match this device.' >&2; exit 1 ;; esac\n` : ""}case "\${VERSION_ID:-}" in ${versionPatterns}) ;; *) echo 'Selected operating system version does not match this device.' >&2; exit 1 ;; esac\n`
    : platform.versionRule === "absent"
      ? `test -z "\${VERSION_ID:-}"\n`
      : platform.versionRule === "snapshot"
        ? `case "\${VERSION_ID:-}" in [0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]) ;; *) echo 'Expected a dated operating system snapshot.' >&2; exit 1 ;; esac\n`
        : "";
  const variantCheck = platform.variantIds.length
    ? `case "\${VARIANT_ID:-}" in ${platform.variantIds.map(shellQuote).join("|")}) ;; *) echo 'Selected operating system edition does not match this device.' >&2; exit 1 ;; esac\n`
    : "";
  const header = `(
set -eu
umask 077
. /etc/os-release
test "$ID" = ${shellQuote(platform.osId)}
${versionCheck}${variantCheck}case "$(uname -m)" in
  x86_64) arch=amd64 ;;
  aarch64) arch=arm64 ;;
  *) echo 'Unsupported device architecture.' >&2; exit 1 ;;
esac
case "$arch" in ${platform.architectures.map(shellQuote).join("|")}) ;; *) echo 'No package published for this architecture.' >&2; exit 1 ;; esac
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
export GNUPGHOME="$work/gnupg"
install -d -m 0700 "$GNUPGHOME"
`;
  const trust = `
${fetch} ${shellQuote(instructions.executionRootUrl)} -o "$work/execution-root.json"
printf '%s  %s\\n' ${shellQuote(instructions.executionRootSha256)} "$work/execution-root.json" | sha256sum --check --status
${fetch} ${shellQuote(instructions.bootstrapBundleUrl)} -o "$work/bootstrap.dsse.json"
install -d -m 0755 /etc/lindm
install -m 0644 "$work/execution-root.json" /etc/lindm/execution-root.json
install -m 0644 "$work/bootstrap.dsse.json" /etc/lindm/bootstrap.dsse.json
)`;
  if (family === "apt" && instructions.aptRepository) {
    const apt = instructions.aptRepository;
    const source = `Types: deb
URIs: ${apt.baseUrl}
Suites: ${apt.suite}
Components: ${apt.components.join(" ")}
Signed-By: /etc/apt/keyrings/lindm.gpg`;
    return `${header}apt-get -o Acquire::AllowInsecureRepositories=false -o APT::Get::AllowUnauthenticated=false update
apt-get -y -o APT::Get::AllowUnauthenticated=false install ca-certificates curl gnupg openssl
${privateCA}${verifyKey}
install -d -m 0755 /etc/apt/keyrings
gpg --batch --yes --dearmor --output /etc/apt/keyrings/lindm.gpg "$work/key.asc"
chmod 0644 /etc/apt/keyrings/lindm.gpg
printf '%s\\n' ${shellQuote(source)} > /etc/apt/sources.list.d/lindm.sources
chmod 0644 /etc/apt/sources.list.d/lindm.sources
apt-get -o Acquire::AllowInsecureRepositories=false -o APT::Get::AllowUnauthenticated=false update
apt-get -y -o APT::Get::AllowUnauthenticated=false install lindm-agent${trust}`;
  }
  if (family === "pacman" && instructions.archRepository) {
    const name = instructions.archRepository.repositoryName;
    const archConfig = `[${name}]
SigLevel = PackageRequired DatabaseRequired TrustedOnly
Server = ${repository.baseUrl}`;
    return `${header}pacman --sync --needed --noconfirm ca-certificates curl gnupg openssl
${privateCA}${verifyKey}
pacman-key --init
pacman-key --add "$work/key.asc"
pacman-key --lsign-key ${shellQuote(repository.signingKeyFingerprint)}
install -d -m 0755 /etc/pacman.d
printf '%s\\n' ${shellQuote(archConfig)} > /etc/pacman.d/lindm.conf
chmod 0644 /etc/pacman.d/lindm.conf
if ! grep -qxF 'Include = /etc/pacman.d/lindm.conf' /etc/pacman.conf; then
  printf '\\nInclude = /etc/pacman.d/lindm.conf\\n' >> /etc/pacman.conf
fi
# Refresh only the server repository, not distribution databases.
printf '%s\\n' '[options]' 'Architecture = auto' 'SigLevel = PackageRequired DatabaseRequired TrustedOnly' ${shellQuote(archConfig)} > "$work/pacman.conf"
pacman --config "$work/pacman.conf" --sync --refresh --noconfirm
# Resolve native dependencies from existing distribution databases without
# refreshing them or hiding them behind the server-only refresh configuration.
pacman --sync --noconfirm ${shellQuote(`${name}/lindm-agent`)}${trust}`;
  }
  if (family === "zypper") {
    const config = `[lindm]
name=Lindm
baseurl=${repository.baseUrl}
type=rpm-md
enabled=1
autorefresh=1
gpgcheck=1
repo_gpgcheck=1
pkg_gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/lindm`;
    // An installer chroot may still list install media or unreachable mirrors;
    // only this server's repository is refreshed and searched for the agent.
    return `${header}printf '%s\\n' '[main]' 'gpgcheck = true' 'repo_gpgcheck = true' 'pkg_gpgcheck = true' > "$work/zypp.conf"
export ZYPP_CONF="$work/zypp.conf"
if ! rpm -q ca-certificates curl gpg2 openssl >/dev/null 2>&1; then
  zypper --non-interactive install --no-recommends ca-certificates curl gpg2 openssl
fi
${privateCA}${verifyKey}
install -d -m 0755 /etc/pki/rpm-gpg /etc/zypp/repos.d
install -m 0644 "$work/key.asc" /etc/pki/rpm-gpg/lindm
rpm --import /etc/pki/rpm-gpg/lindm
printf '%s\\n' ${shellQuote(config)} > /etc/zypp/repos.d/lindm.repo
chmod 0644 /etc/zypp/repos.d/lindm.repo
install -d -m 0700 "$work/repos.d"
install -m 0600 /etc/zypp/repos.d/lindm.repo "$work/repos.d/lindm.repo"
zypper --non-interactive --reposd-dir "$work/repos.d" refresh lindm
zypper --non-interactive --reposd-dir "$work/repos.d" install --no-recommends --from lindm lindm-agent${trust}`;
  }
  const config = `[lindm]
name=Lindm
baseurl=${repository.baseUrl}
enabled=1
gpgcheck=1
localpkg_gpgcheck=1
repo_gpgcheck=1
sslverify=1
gpgkey=file:///etc/pki/rpm-gpg/lindm`;
  // Prerequisites usually ship with the base system; an unregistered or
  // offline installer target may have no distribution repository at all.
  return `${header}if ! rpm -q ca-certificates gnupg2 openssl >/dev/null 2>&1; then
  dnf -y --setopt=gpgcheck=1 --setopt=localpkg_gpgcheck=1 install ca-certificates gnupg2 openssl
fi
if ! command -v curl >/dev/null 2>&1; then dnf -y --setopt=gpgcheck=1 install curl; fi
${privateCA}${verifyKey}
install -d -m 0755 /etc/pki/rpm-gpg
install -m 0644 "$work/key.asc" /etc/pki/rpm-gpg/lindm
rpm --import /etc/pki/rpm-gpg/lindm
printf '%s\\n' ${shellQuote(config)} > /etc/yum.repos.d/lindm.repo
chmod 0644 /etc/yum.repos.d/lindm.repo
dnf -y --setopt=lindm.gpgcheck=1 --setopt=lindm.localpkg_gpgcheck=1 --setopt=lindm.repo_gpgcheck=1 install lindm-agent${trust}`;
}
