import type { GetEnrollmentInstructionsResponse } from "../../../gen/lindm/admin/v1/enrollment_instructions_pb";

export const provisioningFormats = [
  { value: "cloud-init", label: "cloud-init" },
  { value: "kickstart", label: "Kickstart" },
  { value: "autoinstall", label: "Ubuntu autoinstall" },
  { value: "autoyast", label: "AutoYaST" },
  { value: "nixos", label: "NixOS module" },
] as const;

export type ProvisioningFormat = (typeof provisioningFormats)[number]["value"];

const binary = "/usr/libexec/lindm/lindm-agent";
const tokenFile = "/etc/lindm/provisioning-token";
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

function bootScript(bootstrapCommand: string, resumeCommand: string): string {
  return `#!/bin/sh
set -eu
umask 077
${bootstrapCommand}
${resumeCommand}
`;
}

const unit = `[Unit]
Description=Lindm first-boot provisioning and bounded approval resume
After=network-online.target lindm-executor.service
Wants=network-online.target
Requires=lindm-executor.service
ConditionPathExists=${tokenFile}

[Service]
Type=oneshot
UMask=0077
TimeoutStartSec=3660
ExecStart=/etc/lindm/provision-at-boot
ExecStartPost=/usr/bin/rm -f ${tokenFile}
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target`;

function installerScript(secret: string, installScript: string, script: string): string {
  // Base64 is not encryption; it only makes the quoted heredoc non-executable.
  // The caller keeps this entire sensitive seed only in component memory.
  return `set -eu
umask 077
${installScript}
install -d -m 0755 /etc/lindm
base64 -d > ${tokenFile} <<'LINDM_TOKEN'
${btoa(secret)}
LINDM_TOKEN
chmod 0600 ${tokenFile}
cat > /etc/lindm/provision-at-boot <<'LINDM_SCRIPT'
${script}LINDM_SCRIPT
chmod 0700 /etc/lindm/provision-at-boot
cat > /etc/systemd/system/lindm-provision.service <<'LINDM_UNIT'
${unit}
LINDM_UNIT
systemctl enable lindm-executor.service lindm-agent.service lindm-provision.service`;
}

export function provisioningSnippet(
  format: ProvisioningFormat,
  secret: string,
  instructions: GetEnrollmentInstructionsResponse,
  installScript: string,
): string {
  if (!installScript && format !== "nixos") return "";
  const script = bootScript(
    `${executorReady}\n${instructions.provisioningCommand}`,
    instructions.resumeCommand,
  );
  switch (format) {
    case "cloud-init":
      return `#cloud-config
${prerequisites}write_files:
  - path: ${tokenFile}
    owner: root:root
    permissions: '0600'
    content: ${JSON.stringify(secret)}
  - path: /etc/lindm/provision-at-boot
    owner: root:root
    permissions: '0700'
    content: |
${script
  .split("\n")
  .map((line) => `      ${line}`)
  .join("\n")}
  - path: /etc/systemd/system/lindm-provision.service
    owner: root:root
    permissions: '0644'
    content: |
${unit
  .split("\n")
  .map((line) => `      ${line}`)
  .join("\n")}
runcmd:
  - [sh, -c, ${JSON.stringify(
    `set -eu\n${installScript}\nsystemctl daemon-reload\nsystemctl enable --now lindm-executor.service lindm-agent.service lindm-provision.service`,
  )}]
`;
    case "kickstart":
      return `${prerequisites}# Merge this post section into the complete trusted installer profile.
%post --erroronfail
${installerScript(secret, installScript, script)}
%end
`;
    case "autoinstall":
      return `#cloud-config
${prerequisites}# Merge these fields into the complete trusted autoinstall configuration.
autoinstall:
  version: 1
  user-data:
${provisioningSnippet("cloud-init", secret, instructions, installScript)
  .split("\n")
  .slice(1)
  .map((line) => `    ${line}`)
  .join("\n")}
`;
    case "autoyast":
      return `<?xml version="1.0"?>
<!-- SENSITIVE installer profile: reusable, bounded provisioning token.
     Protect seed transport and retained installer copies; never embed in a
     golden image. Merge into your complete installer profile.
     Installs from this server's signed repository with pinned deployment trust. -->
<profile xmlns="http://www.suse.com/1.0/yast2ns" xmlns:config="http://www.suse.com/1.0/configns">
  <scripts>
    <chroot-scripts config:type="list">
      <script>
        <chrooted config:type="boolean">true</chrooted>
        <interpreter>shell</interpreter>
        <source><![CDATA[
${installerScript(secret, installScript, script)}
]]></source>
      </script>
    </chroot-scripts>
  </scripts>
</profile>
`;
    case "nixos":
      // Never interpolate the secret into a Nix expression: the store is public.
      return `# Import this module and set services.lindmEnrollment.package to your verified
# lindm-agent derivation (libexec/lindm/lindm-agent). Install the executor module
# and authenticated deployment config/trust separately. NO SECRET belongs in Nix.
# Download the actual token file from this page, transfer securely to this target
# as /run/lindm/provisioning-token owned by root:root with mode 0600,
# then run ON THE TARGET as root:
# install -d -m 0700 /etc/credstore.encrypted
# systemd-creds encrypt --name=lindm.provisioning-token /run/lindm/provisioning-token /etc/credstore.encrypted/lindm.provisioning-token
# chmod 0600 /etc/credstore.encrypted/lindm.provisioning-token
# rm /run/lindm/provisioning-token
# systemctl start lindm-provision.service
# The encrypted credential is target-bound; never copy it into a golden image.
{ config, lib, pkgs, ... }:
let cfg = config.services.lindmEnrollment; in {
  options.services.lindmEnrollment.package = lib.mkOption {
    type = lib.types.package;
    description = "Verified lindm-agent package containing libexec/lindm/lindm-agent";
  };
  config.systemd.services.lindm-provision = {
    description = "Lindm provisioning with bounded approval resume";
    wantedBy = [ "multi-user.target" ];
    wants = [ "network-online.target" ];
    after = [ "network-online.target" "lindm-executor.service" ];
    requires = [ "lindm-executor.service" ];
    unitConfig.ConditionPathExists = "/etc/credstore.encrypted/lindm.provisioning-token";
    serviceConfig = {
      Type = "oneshot";
      User = "root";
      UMask = "0077";
      TimeoutStartSec = 3660;
      RemainAfterExit = true;
      LoadCredentialEncrypted = "lindm.provisioning-token:/etc/credstore.encrypted/lindm.provisioning-token";
      ExecStartPost = "\${pkgs.coreutils}/bin/rm -f /etc/credstore.encrypted/lindm.provisioning-token";
    };
    script = ''
${bootScript(
  instructions.provisioningCommand
    .replace(binary, "${cfg.package}/libexec/lindm/lindm-agent")
    .replace(tokenFile, '"$CREDENTIALS_DIRECTORY/lindm.provisioning-token"'),
  instructions.resumeCommand.replace(binary, "${cfg.package}/libexec/lindm/lindm-agent"),
)
  .split("\n")
  .map((line) => `      ${line}`)
  .join("\n")}
    '';
  };
}
`;
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
  platform: GetEnrollmentInstructionsResponse["platforms"][number] | undefined,
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
  const config = `[lindm]
name=Lindm
baseurl=${repository.baseUrl}
enabled=1
gpgcheck=1
localpkg_gpgcheck=1
repo_gpgcheck=1
sslverify=1
gpgkey=file:///etc/pki/rpm-gpg/lindm`;
  if (family === "zypper") {
    return `${header}printf '%s\\n' '[main]' 'gpgcheck = true' 'repo_gpgcheck = true' 'pkg_gpgcheck = true' > "$work/zypp.conf"
export ZYPP_CONF="$work/zypp.conf"
zypper --non-interactive install --no-recommends ca-certificates curl gpg2 openssl
${privateCA}${verifyKey}
install -d -m 0755 /etc/pki/rpm-gpg /etc/zypp/repos.d
install -m 0644 "$work/key.asc" /etc/pki/rpm-gpg/lindm
rpm --import /etc/pki/rpm-gpg/lindm
printf '%s\\n' ${shellQuote(`${config}\npkg_gpgcheck=1`)} > /etc/zypp/repos.d/lindm.repo
chmod 0644 /etc/zypp/repos.d/lindm.repo
zypper --non-interactive refresh lindm
zypper --non-interactive install --no-recommends --from lindm lindm-agent${trust}`;
  }
  return `${header}dnf -y --setopt=gpgcheck=1 --setopt=localpkg_gpgcheck=1 install ca-certificates gnupg2 openssl
if ! command -v curl >/dev/null 2>&1; then dnf -y --setopt=gpgcheck=1 install curl; fi
${privateCA}${verifyKey}
install -d -m 0755 /etc/pki/rpm-gpg
install -m 0644 "$work/key.asc" /etc/pki/rpm-gpg/lindm
rpm --import /etc/pki/rpm-gpg/lindm
printf '%s\\n' ${shellQuote(config)} > /etc/yum.repos.d/lindm.repo
chmod 0644 /etc/yum.repos.d/lindm.repo
dnf -y --setopt=lindm.gpgcheck=1 --setopt=lindm.localpkg_gpgcheck=1 --setopt=lindm.repo_gpgcheck=1 install lindm-agent${trust}`;
}
