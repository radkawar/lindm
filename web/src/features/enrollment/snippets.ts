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
const prerequisites = `# SENSITIVE BOOT INPUT: contains a reusable, bounded provisioning token.
# Deliver only to intended installations; never embed in a reusable/golden image.
# A signed agent package and its systemd units/config are required before bootstrap.
# Authenticate /etc/lindm/execution-root.json and bootstrap.dsse.json out of band.
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
  installScript = "",
): string {
  const script = bootScript(instructions.provisioningCommand, instructions.resumeCommand);
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
     Signed lindm-agent package/config and authenticated deployment trust must
     already be installed. -->
<profile xmlns="http://www.suse.com/1.0/yast2ns" xmlns:config="http://www.suse.com/1.0/configns">
  <scripts>
    <chroot-scripts config:type="list">
      <script>
        <chrooted config:type="boolean">true</chrooted>
        <interpreter>shell</interpreter>
        <source><![CDATA[
${installerScript(secret, "", script)}
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

export const grantFormats = [
  { value: "apt", label: "Debian / Ubuntu (APT)" },
  { value: "dnf", label: "Fedora / RHEL (DNF)" },
] as const;

export type GrantFormat = (typeof grantFormats)[number]["value"];

export function grantSnippet(
  secret: string,
  instructions: GetEnrollmentInstructionsResponse,
  installScript: string,
): string {
  return `# SENSITIVE: single-use enrollment code for one device.
# Run as root from protected input, not a logged shell or retained shell history.
# Authenticate the deployment execution root and signed bootstrap bundle first.
set -eu
test "$(id -u)" -eq 0
umask 077
${installScript ? `${installScript}\n` : "# Prerequisite: install the signed lindm-agent package and deployment configuration first.\n"}install -d -o root -g root -m 0700 /run/lindm-enrollment
base64 -d > /run/lindm-enrollment/grant <<'LINDM_GRANT'
${btoa(secret)}
LINDM_GRANT
chmod 0600 /run/lindm-enrollment/grant
systemctl enable --now lindm-executor.service lindm-agent.service
${instructions.grantCommand}
${instructions.resumeCommand}
rm -f /run/lindm-enrollment/grant
`;
}

function shellQuote(value: string): string {
  return `'${value.replaceAll("'", "'\"'\"'")}'`;
}

export function enrollmentInstallScript(
  instructions: GetEnrollmentInstructionsResponse | undefined,
  family: GrantFormat,
): string {
  const repository = family === "apt" ? instructions?.aptRepository : instructions?.dnfRepository;
  if (!repository) return "";

  const verifyKey = `curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' ${shellQuote(repository.signingKeyUrl)} -o "$key"
test "$(gpg --batch --with-colons --show-keys "$key" | awk -F: '$1 == "pub" { primary = 1; next } primary && $1 == "fpr" { print $10; primary = 0 }')" = ${shellQuote(repository.signingKeyFingerprint)}`;
  const header = `# Install only from this deployment's configured signed repository.
set -eu
umask 077
`;
  if (family === "apt" && instructions?.aptRepository) {
    const apt = instructions.aptRepository;
    const source = `deb [signed-by=/etc/apt/keyrings/lindm.gpg] ${apt.baseUrl} ${apt.suite} ${apt.components.join(" ")}`;
    return `${header}apt-get -o Acquire::AllowInsecureRepositories=false -o APT::Get::AllowUnauthenticated=false update
apt-get -y -o APT::Get::AllowUnauthenticated=false install ca-certificates curl gnupg
key="$(mktemp)"
trap 'rm -f "$key"' EXIT
${verifyKey}
install -d -m 0755 /etc/apt/keyrings
gpg --batch --yes --dearmor --output /etc/apt/keyrings/lindm.gpg "$key"
chmod 0644 /etc/apt/keyrings/lindm.gpg
printf '%s\\n' ${shellQuote(source)} > /etc/apt/sources.list.d/lindm.list
chmod 0644 /etc/apt/sources.list.d/lindm.list
apt-get -o Acquire::AllowInsecureRepositories=false -o APT::Get::AllowUnauthenticated=false update
apt-get -y -o APT::Get::AllowUnauthenticated=false install lindm-agent
rm -f "$key"
trap - EXIT`;
  }
  const config = `[lindm]
name=Lindm
baseurl=${repository.baseUrl}
enabled=1
gpgcheck=1
localpkg_gpgcheck=1
repo_gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/lindm`;
  return `${header}dnf -y --setopt=gpgcheck=1 --setopt=localpkg_gpgcheck=1 install ca-certificates curl gnupg2
key="$(mktemp)"
trap 'rm -f "$key"' EXIT
${verifyKey}
install -d -m 0755 /etc/pki/rpm-gpg
install -m 0644 "$key" /etc/pki/rpm-gpg/lindm
rpm --import /etc/pki/rpm-gpg/lindm
printf '%s\\n' ${shellQuote(config)} > /etc/yum.repos.d/lindm.repo
chmod 0644 /etc/yum.repos.d/lindm.repo
dnf -y --setopt=lindm.gpgcheck=1 --setopt=lindm.localpkg_gpgcheck=1 --setopt=lindm.repo_gpgcheck=1 install lindm-agent
rm -f "$key"
trap - EXIT`;
}
