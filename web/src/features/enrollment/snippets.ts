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
const prerequisites = `# SENSITIVE ONE-TIME BOOT INPUT: contains a bounded provisioning credential.
# Deliver only to intended installations; never embed in a reusable/golden image.
# Install the signed lindm-agent package and its systemd units/config first.
# Authenticate /etc/lindm/execution-root.json and bootstrap.dsse.json out of band.
# Protect installer/seed transport and retained copies; revoke unused credentials.
# Enrollment waits at most 3600 seconds for independent approval, then fails visibly.
`;

function bootScript(agent: string, token: string): string {
  return `#!/bin/sh
set -eu
umask 077
${agent} bootstrap -root /etc/lindm/execution-root.json -bundle /etc/lindm/bootstrap.dsse.json -provisioning-token-file ${token}
${agent} resume -wait-seconds 3600
`;
}

const script = bootScript(binary, tokenFile);
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

function installerScript(secret: string): string {
  // Base64 is not encryption; it only makes the quoted heredoc non-executable.
  // The caller keeps this entire sensitive seed only in component memory.
  return `set -eu
umask 077
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

export function provisioningSnippet(format: ProvisioningFormat, secret: string): string {
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
  - [systemctl, daemon-reload]
  - [systemctl, enable, --now, lindm-executor.service, lindm-agent.service, lindm-provision.service]
`;
    case "kickstart":
      return `${prerequisites}# Merge this post section into the complete trusted installer profile.
%post --erroronfail
${installerScript(secret)}
%end
`;
    case "autoinstall":
      return `#cloud-config
${prerequisites}# Merge these fields into the complete trusted autoinstall configuration.
autoinstall:
  version: 1
  user-data:
${provisioningSnippet("cloud-init", secret)
  .split("\n")
  .slice(1)
  .map((line) => `    ${line}`)
  .join("\n")}
`;
    case "autoyast":
      return `<?xml version="1.0"?>
<!-- SENSITIVE one-time installer profile. Protect seed transport/retention;
     never embed in a golden image. Merge into your complete installer profile.
     Signed lindm-agent package/config and authenticated deployment trust must
     already be installed. -->
<profile xmlns="http://www.suse.com/1.0/yast2ns" xmlns:config="http://www.suse.com/1.0/configns">
  <scripts>
    <chroot-scripts config:type="list">
      <script>
        <chrooted config:type="boolean">true</chrooted>
        <interpreter>shell</interpreter>
        <source><![CDATA[
${installerScript(secret)}
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
# as /run/lindm/provisioning-token root:root0600, then run ON THE TARGET as root:
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
  "${cfg.package}/libexec/lindm/lindm-agent",
  '"$CREDENTIALS_DIRECTORY/lindm.provisioning-token"',
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
