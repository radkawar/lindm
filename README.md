<!-- markdownlint-disable MD041 -->
<!-- The solid brand icon precedes the real Markdown H1. -->

<img src="docs/brand/pwa-192.png" alt="lindm icon" width="96" height="96">

# lindm

[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)
[![Checks](https://github.com/radkawar/lindm/actions/workflows/check.yml/badge.svg)](https://github.com/radkawar/lindm/actions/workflows/check.yml)

lindm is a self-hosted MDM for Linux fleets.
It uses each distribution's native package and system tools. You run the server yourself.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/images/console-dashboard-dark.webp">
  <img src="docs/images/console-dashboard-light.webp" alt="Dashboard with work that needs review and the latest recorded activity." width="100%">
</picture>

Screenshots and animations use synthetic demo data.

## What it does

- One-line or installer-file enrollment, with agents served by your own server.
- TPM-backed disk encryption with escrowed recovery keys.
- Remote lock, wipe and recovery wipe for lost devices.
- Profiles with staged rollouts and two-person approval.
- Vulnerability findings from vendor advisory feeds.
- OS update windows.
- Browser-based remote assistance with user consent.
- A signed audit log and exports.
- An MCP server for AI assistants.

## A look at the console

### Enroll devices

Choose a distribution, create a one-time code or a bounded provisioning token, and copy the install command.
The device page shows enrollment, inventory and security findings separately.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/images/flow-enrollment-dark.gif">
  <img src="docs/images/flow-enrollment-light.gif" alt="Choosing an operating system and copying its enrollment command, then reviewing a demo device." width="100%">
</picture>

### Configure a fleet

Publish a profile, review the affected devices and roll it out in stages.
Review the pilot's results before advancing to the fleet.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/images/flow-policy-dark.gif">
  <img src="docs/images/flow-policy-light.gif" alt="Publishing a profile, reviewing impact, obtaining a second administrator's approval and advancing a completed demo pilot to the fleet." width="100%">
</picture>

### Review vulnerabilities

Follow an advisory to its affected devices and review the finding before requesting a patch or accepting a risk.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/images/flow-vulnerability-dark.gif">
  <img src="docs/images/flow-vulnerability-light.gif" alt="Opening vendor advisories, their affected devices and a device's security findings." width="100%">
</picture>

<details>
<summary>Lost devices, remote assistance and administration</summary>

### Respond to a lost device

Find the device, review a lock or wipe request and record the reason.
Destructive actions require independent approval.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/images/flow-lost-device-dark.gif">
  <img src="docs/images/flow-lost-device-light.gif" alt="Reviewing a named lost device and its lock request before independent approval." width="100%">
</picture>

### Ask to help

Choose the access, tools and time limit before asking the user for consent.
This demo shows the request and consent states, not a live shared desktop.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/images/flow-assist-dark.gif">
  <img src="docs/images/flow-assist-light.gif" alt="Finding a device, reviewing remote assistance permissions and waiting for user consent." width="100%">
</picture>

### Manage access

Create administrator accounts, define roles and review changes in the audit log.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/images/flow-admin-dark.gif">
  <img src="docs/images/flow-admin-light.gif" alt="Defining a read-only role, creating an administrator account and updating its access." width="100%">
</picture>

</details>

## Distributions

<!-- BEGIN GENERATED readme-support -->

✓ supported · ✗ not supported (reason below) · not yet tested.

Paired values show disk encryption / TPM2 unlock, lock / cryptographic wipe, and GNOME viewing / controls. A single value applies to both. Profiles include all configuration providers; assistance controls include keyboard, clipboard, display selection and messages.

| Distribution / release                                      | Architecture | Enrolment      | Profiles        | Disk / TPM                       | Lock / wipe        | OS updates      | Findings        | Assistance                        |
| ----------------------------------------------------------- | ------------ | -------------- | --------------- | -------------------------------- | ------------------ | --------------- | --------------- | --------------------------------- |
| [Ubuntu 22.04 LTS](docs/platforms/ubuntu.md)                | x86_64       | ✓              | ✗ [^support-1]  | not yet tested                   | not yet tested     | ✓               | not yet tested  | not yet tested / ✗ [^support-2]   |
| [Ubuntu 22.04 LTS](docs/platforms/ubuntu.md)                | arm64        | ✓              | ✗ [^support-1]  | not yet tested                   | not yet tested     | ✓               | not yet tested  | not yet tested / ✗ [^support-2]   |
| [Ubuntu 24.04 LTS](docs/platforms/ubuntu.md)                | x86_64       | ✓              | not yet tested  | ✓ / not yet tested               | not yet tested     | ✓               | not yet tested  | not yet tested                    |
| [Ubuntu 24.04 LTS](docs/platforms/ubuntu.md)                | arm64        | not yet tested | not yet tested  | not yet tested                   | not yet tested     | ✓               | not yet tested  | not yet tested                    |
| [Ubuntu 26.04 LTS](docs/platforms/ubuntu.md)                | x86_64       | ✓              | not yet tested  | ✓                                | ✓                  | ✓               | not yet tested  | ✓ / ✗ [^support-2]                |
| [Ubuntu 26.04 LTS](docs/platforms/ubuntu.md)                | arm64        | ✓              | not yet tested  | ✓                                | ✓                  | ✓               | not yet tested  | not yet tested / ✗ [^support-2]   |
| [Debian 12](docs/platforms/debian.md)                       | x86_64       | ✓              | not yet tested  | not yet tested                   | not yet tested     | ✗ [^support-3]  | not yet tested  | not yet tested / ✗ [^support-2]   |
| [Debian 12](docs/platforms/debian.md)                       | arm64        | not yet tested | not yet tested  | not yet tested                   | not yet tested     | ✗ [^support-3]  | not yet tested  | not yet tested / ✗ [^support-2]   |
| [Debian 13](docs/platforms/debian.md)                       | x86_64       | ✓              | not yet tested  | not yet tested                   | not yet tested     | ✗ [^support-3]  | not yet tested  | not yet tested / ✗ [^support-2]   |
| [Debian 13](docs/platforms/debian.md)                       | arm64        | ✓              | not yet tested  | not yet tested                   | not yet tested     | ✗ [^support-3]  | not yet tested  | not yet tested / ✗ [^support-2]   |
| [Fedora 43](docs/platforms/fedora.md)                       | x86_64       | ✓              | ✗ [^support-4]  | ✓                                | ✓                  | ✓               | not yet tested  | ✓ / ✗ [^support-2]                |
| [Fedora 43](docs/platforms/fedora.md)                       | arm64        | ✓              | ✗ [^support-4]  | ✓ / not yet tested               | ✓                  | ✓               | not yet tested  | ✓ / ✗ [^support-2]                |
| [Fedora 44](docs/platforms/fedora.md)                       | x86_64       | ✓              | ✓               | ✓                                | not yet tested     | ✓               | not yet tested  | not yet tested                    |
| [Fedora 44](docs/platforms/fedora.md)                       | arm64        | not yet tested | not yet tested  | not yet tested                   | ✓ / not yet tested | ✓               | not yet tested  | not yet tested                    |
| [RHEL 9](docs/platforms/rhel.md)                            | x86_64       | ✓              | not yet tested  | not yet tested                   | not yet tested     | ✓               | not yet tested  | ✓ / ✗ [^support-2]                |
| [RHEL 9](docs/platforms/rhel.md)                            | arm64        | ✓              | not yet tested  | ✓                                | ✓                  | not yet tested  | not yet tested  | not yet tested / ✗ [^support-2]   |
| [RHEL 10](docs/platforms/rhel.md)                           | x86_64       | ✓              | not yet tested  | not yet tested                   | not yet tested     | ✓               | not yet tested  | ✓ / ✗ [^support-2]                |
| [RHEL 10](docs/platforms/rhel.md)                           | arm64        | ✓              | not yet tested  | ✓                                | ✓                  | not yet tested  | not yet tested  | not yet tested / ✗ [^support-2]   |
| [Rocky Linux 9](docs/platforms/alma-rocky.md)               | x86_64       | ✓              | ✓               | ✓                                | ✓                  | ✓               | not yet tested  | ✓ / ✗ [^support-2]                |
| [Rocky Linux 9](docs/platforms/alma-rocky.md)               | arm64        | ✓              | not yet tested  | not yet tested                   | not yet tested     | ✓               | not yet tested  | not yet tested / ✗ [^support-2]   |
| [Rocky Linux 10](docs/platforms/alma-rocky.md)              | x86_64       | ✓              | ✓               | ✓                                | ✓                  | ✓               | not yet tested  | ✓ / ✗ [^support-2]                |
| [Rocky Linux 10](docs/platforms/alma-rocky.md)              | arm64        | ✓              | not yet tested  | not yet tested                   | not yet tested     | ✓               | not yet tested  | not yet tested / ✗ [^support-2]   |
| [AlmaLinux 9](docs/platforms/alma-rocky.md)                 | x86_64       | ✓              | ✓               | ✓                                | ✓                  | ✓               | not yet tested  | ✓ / ✗ [^support-2]                |
| [AlmaLinux 9](docs/platforms/alma-rocky.md)                 | arm64        | ✓              | not yet tested  | not yet tested                   | not yet tested     | ✓               | not yet tested  | not yet tested / ✗ [^support-2]   |
| [AlmaLinux 10](docs/platforms/alma-rocky.md)                | x86_64       | ✓              | ✓               | not yet tested                   | not yet tested     | ✓               | not yet tested  | not yet tested / ✗ [^support-2]   |
| [AlmaLinux 10](docs/platforms/alma-rocky.md)                | arm64        | ✓              | not yet tested  | not yet tested                   | not yet tested     | ✓               | not yet tested  | not yet tested / ✗ [^support-2]   |
| [Linux Mint 22.3](docs/platforms/mint.md)                   | x86_64       | ✓              | not yet tested  | not yet tested                   | not yet tested     | ✗ [^support-5]  | not yet tested  | ✗ [^support-6] / ✗ [^support-7]   |
| [Pop!\_OS 24.04 LTS](docs/platforms/popos.md)               | x86_64       | ✓              | not yet tested  | not yet tested                   | not yet tested     | ✗ [^support-5]  | not yet tested  | ✗ [^support-8] / ✗ [^support-9]   |
| [Arch Linux](docs/platforms/arch.md) (rolling)              | x86_64       | ✓              | ✓               | ✓                                | ✓                  | ✓               | not yet tested  | ✓ / ✗ [^support-2]                |
| [Omarchy 4.0.4](docs/platforms/omarchy.md)                  | x86_64       | not yet tested | ✗ [^support-10] | not yet tested / ✗ [^support-11] | not yet tested     | ✗ [^support-12] | ✗ [^support-13] | ✗ [^support-14] / ✗ [^support-15] |
| [openSUSE Tumbleweed](docs/platforms/opensuse.md) (rolling) | x86_64       | ✓              | not yet tested  | ✓                                | ✓                  | ✓               | not yet tested  | ✓ / ✗ [^support-2]                |
| [openSUSE Tumbleweed](docs/platforms/opensuse.md) (rolling) | arm64        | ✓              | not yet tested  | ✓                                | ✓                  | not yet tested  | not yet tested  | ✓ / ✗ [^support-2]                |

Encryption and wipe require an encrypted installation; TPM2 unlock requires a compatible TPM and boot configuration. Wipe erases encryption keys, not physical drives. Assistance requires a compatible desktop and user consent. Distribution pages describe other desktops and assistance tools. Findings cover distribution packages; derived distributions marked “base packages” cover their upstream packages.

[^support-1]: The shipped systemd is older than the configuration definition provider requires.

[^support-2]: The desktop does not support all requested remote-assistance controls.

[^support-3]: The update runner does not implement this distribution's security-origin selection.

[^support-4]: The shipped package manager cannot prepare the required unprivileged transaction. Password-policy integration is not supported with this release's PAM stack.

[^support-5]: No automatic OS-update integration is supported for this release.

[^support-6]: The desktop portal provides neither screen capture nor remote control.

[^support-7]: The desktop portal provides neither screen capture nor remote control. The desktop does not support all requested remote-assistance controls.

[^support-8]: The desktop cannot display the required Allow/Decline consent buttons.

[^support-9]: The desktop cannot display the required Allow/Decline consent buttons. The desktop does not support all requested remote-assistance controls.

[^support-10]: Password-policy integration is not supported with this release's PAM stack. The firewall provider requires firewalld, but the installed firewall uses ufw.

[^support-11]: The installed boot configuration cannot unlock systemd TPM2 tokens.

[^support-12]: The distribution requires its own updater and refuses direct package-manager system upgrades.

[^support-13]: No vendor advisory feed covers this distribution's packages.

[^support-14]: The desktop does not report its locked state, so screen sharing cannot stop safely at lock.

[^support-15]: The desktop does not report its locked state, so screen sharing cannot stop safely at lock. The desktop does not support all requested remote-assistance controls.

<!-- END GENERATED readme-support -->

## Install

Build a release with your own signing keys, then install the bundle on your server.
Installation from a prepared bundle is the five-minute part.
The build takes longer, depending on your machine and network.
See the [installation guide](docs/install.md) for prerequisites and server setup.

1. Install the pinned tools from [CONTRIBUTING](CONTRIBUTING.md), then clone and build:

   ```sh
   git clone https://github.com/radkawar/lindm.git
   cd lindm
   make bootstrap
   make release-keys
   make release
   ```

   Keep the release keys and their encryption passphrase on the signing workstation.
   Read [self-built releases and signing keys](docs/self-built-releases.md) for key custody and public trust files.

2. Copy the verified `artifacts/release/` bundle and public trust files to the server.
   From the bundle directory, run:

   ```sh
   sudo ./install.sh --release-key-file "$TRUSTED_RELEASE_PUBLIC_KEY" \
     --release-key-id "$RELEASE_KEY_ID" --backup-recipient-file "$BACKUP_RECIPIENT_FILE"
   ```

   Supply the stable HTTPS origin when prompted.

3. Trust the deployment CA in your browser, then open the setup URL printed by the installer.
   Read the one-use setup code as root from `/var/lib/lindmd-operations/setup/code`.
   Enter the code, create the owner account and register a user-verifying passkey.

4. In **Settings**, confirm that the agent repository is **Ready**.
   Select **Enroll**, choose the device's operating system and copy the install-and-enroll command.
   Run it on a second device. The console shows the device as **Enrolled**.

## How it works

`lindmd` is a Go server with PostgreSQL as its store and work queue.
It serves the React console and Connect RPC on separate administration and device TLS listeners.
The device agent separates an unprivileged network process from a root executor through a protected Unix socket.
The executor checks signed authority and owns device identity, trust and durable execution state.
See [architecture](docs/architecture.md) for the security boundaries.

## Contribute

See [CONTRIBUTING](CONTRIBUTING.md) for development and DCO sign-off, and the [roadmap](ROADMAP.md) for planned work.
Report vulnerabilities privately through [SECURITY](SECURITY.md).
The [code of conduct](CODE_OF_CONDUCT.md) applies to project discussions.

[Documentation](docs/platforms/README.md) · [Enrollment](docs/agent-enrollment.md) · [Operations](docs/security-and-operations.md) · [Platform details](docs/platforms/README.md#support-status-matrix)

lindm's original code is licensed under [Apache-2.0](LICENSE).
Third-party code and data retain their own licenses. See [NOTICE](NOTICE).
