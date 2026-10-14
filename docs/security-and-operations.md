# Security, deployment and operations

Status: this page defines security requirements and acceptance targets, not measured service guarantees.
Lindm remains a development preview, not a production-ready release.
Use the [verification ledger](verification.md) for qualified Tier 1 x86_64 operations and their limits.
Arm64 release qualification awaits the lab, despite partial native passes.
See [architecture](architecture.md) for identity, authorization, protocol and journal invariants.

**Evidence access:** `~/.cache` and `$HOME` evidence paths identify maintainer-local retained records with hash references.
The repository does not include these records or provide public downloads.

## 1. Threat model

| Threat                              | Required controls                                                                                               | Residual limitation / test                                                                                 |
| ----------------------------------- | --------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------- |
| Network attacker or hostile mirror  | TLS/mTLS, pinned bootstrap trust, signed update metadata/content, anti-rollback/freeze checks                   | Availability can be denied; corruption/replay/expiry tests must fail safely                                |
| Leaked grant or copied golden image | One-use bounded grant, CSR proof, separate enrollment generation, no keys in images                             | A stolen unused bearer grant may race its owner; approval/hardware binding where required                  |
| Compromised device                  | Device-scoped auth, bounded untrusted input, observation freshness, no fleet/admin privileges                   | Root may fabricate its own posture; software evidence is not hardware attestation                          |
| Compromised desktop/network process | Separate privileged executor, peer identity, signed typed plans, UID-bound session actions                      | Root executor/kernel compromise is outside this isolation boundary                                         |
| Malicious or phished admin          | MFA/step-up, scoped RBAC, two-person approvals, target binding, external audit                                  | Colluding authorized admins can damage managed devices; minimize blast radius                              |
| Compromised control plane           | Restricted service identity, key separation, hardened host, segmented DB/storage, approval and release controls | Execution signing alone does not make a compromised server safe                                            |
| Malicious package or updater        | Publisher approval, repository signature verification, TUF, bounded staging, SBOM/provenance                    | Approved packages can execute privileged maintainer scripts; scanning is not a proof of safety             |
| SSRF or content import exploit      | Explicit egress destination policy, DNS/IP revalidation, redirect restrictions, archive/path/size limits        | Local mirrors need administrator-configured private-address allowlists, not blanket private-network access |
| Backup/database theft               | Envelope-encrypted secrets, separate key custody, encrypted backups and least-privilege access                  | A live host holding usable keys is not protected by at-rest encryption alone                               |
| Restored stale database             | Restore hold, recovery epoch, device journal reconciliation, revoke/reapprove high-risk work                    | Never silently replay stale destructive actions or resurrect revoked credentials                           |
| Capacity exhaustion                 | Per-principal limits, bounded concurrency/queues/batches, backpressure and disk budgets                         | Failed admission is visible; accepted durable work is not silently discarded                               |

Security review must cover every trust transition, a malicious enrolled device,
cross-group authorization, package/config injection, local privilege escalation,
key custody, update compromise and recovery. Fuzz parsers, protocol bounds, filters,
archive extraction and provider plans. Release requires an independent penetration
assessment and closure of critical/high findings, not just a linter report.

## 2. Key and secret custody

Separate keys for deployment CA, device identity, execution authorization, release
update signing, webhook signing, recovery-data wrapping, backup encryption and audit
checkpoints. Use maintained crypto/PKI libraries and OS CSPRNG; never implement custom
cryptographic primitives. Log identifiers, not token values, CSR private keys,
passwords, recovery material, session cookies or secret-bearing policy fields.

The default single-host deployment uses root-protected key files mounted read-only
into the relevant process and documents its host-compromise risk. An external KMS or
PKCS#11/HSM integration is required for higher-assurance deployments, including a
local offline-compatible option. Offline release root/targets signing custody is
never bundled into the online server image. Provide rotation/revocation drills with
overlap, missed rotations, old agents, expired certs and lost keys.

### Enrollment installation from your server

Agents always come from the customer's own `lindmd` server. There is no public
Lindm package repository, external hosting option or separate hosting prerequisite.
The signed air-gap bundle workflow is unchanged.

`GetEnrollmentInstructions` requires fresh, unrestricted `enrollment.manage`
authority. It returns the configured `public_url` enrollment origin and optional
`device_public_url`, never a browser Host header, listener bind address or guessed
hostname. It also returns registry-backed OS choices and repository readiness.
Missing release artifacts block installation with a specific remedy in both the
enrollment dialog and Settings; they never produce an install-first fallback.

When `execution_bootstrap` is configured, startup reads its `root_file` and
`bootstrap_file` through the existing bounded, ownership-checked resource loader.
It verifies the DSSE signature/quorum, deployment, enrollment/device origins,
device CA and TLS pins before serving either listener. The administrative HTTPS
origin then exposes these exact public bytes without a login or client certificate:

- `GET /bootstrap/execution-root.json`
- `GET /bootstrap/bootstrap.dsse.json`

Both also support `HEAD`, have `Cache-Control: no-store`, and reject write methods.
No directory listing, arbitrary file retrieval, private signing key, bearer grant,
or unsigned replacement bundle is published. Without configured bootstrap material,
these paths return 404. The device listener remains mTLS-only. A reverse proxy must
preserve these public read-only paths on `public_url`; do not require an admin
session for initial installation or expose local configuration directories.
Documents are the startup-verified snapshot; replacing referenced files requires
restarting the server and passing the same verification again.

**Delivery is not initial trust.** Obtain the command through the authenticated console.
Use an independent trusted channel to provide the device with the complete package signing-key fingerprint and execution-root SHA-256.
Include any private server CA certificate and its fingerprint.
The command verifies these pins before installing repository trust or starting enrollment.
It verifies the HTTPS hostname and certificate chain throughout.
The agent verifies the DSSE bundle against the authenticated execution root, including expiry and exact deployment bindings.
On APT systems the command waits, for at most ten minutes, while another package
manager holds APT's locks (Pop!\_OS's `pop-system-updater` refreshes at boot and
every 12 hours; Ubuntu's `apt-daily` and unattended-upgrades run on timers). It
prints "Waiting for another package manager to finish…" once and retries only
while every APT error is a lock refusal; any other APT failure stops it.

Never use HTTP or disable certificate checks.
Never use a short OpenPGP key ID.
Never trust a downloaded root merely because it signs its own bundle.

#### Prepare the server's installation repository

Install the authenticated `lindmd` release package or its air-gap/OCI artifact.
It carries `/usr/share/lindmd/agent-repository`: signed native repositories,
their agent packages and the agent release attestations. On first start, `lindmd`
verifies that payload and serves it at `/repo/apt`, `/repo/rpm` and `/repo/arch`.
No `releaseRepository` setting or separate publication step is needed.

**Settings › Agent repository** shows **Ready**, the package versions per OS and
architecture, or each platform's verification failure. The release covers the
registry's supported native installation families; design-only platforms remain
explicitly unavailable. A new `lindmd` release carries the matching agent version.
Upgrade all replicas to the same authenticated artifact and restart them together.
The server reads the installed payload; it never rebuilds or re-signs packages,
copies private keys, or repairs a failed signature check.

The air-gap installer uses exactly the same `lindmd` artifact and repository
payload. Internet access is not required to publish or download these agent
packages. Native OS dependencies still need the site's own trusted distribution
repositories or installation media.

##### Custom publication override

Keep `releaseRepository.directory` and `nativeRepositories` only when the site
needs a separately curated or replicated native snapshot, for example a staged
agent version independent of the server upgrade. This override replaces the
bundled native repositories; absent formats do not silently fall back to the
installed bundle. The operator owns complete signed snapshots, full signer pins
and coordinated replica restarts. A release directory used only for TUF updates
does not override the bundle when `nativeRepositories` is absent.

For that advanced use, publish the same signed release artifacts with
`internal/packaging`'s publishers. Retain signed metadata, packages and public
keys. Do not rebuild or re-sign packages in `lindmd`.

On the release signing workstation, set `SIGNER_HOME`, `SIGNER_FINGERPRINT` and
`SIGNER_PASSPHRASE_FILE` to the protected production package-signing inputs;
set the four `AGENT_*` paths below to the already built release artifacts.
`STAGING` must be a new private directory under a trusted parent. The maintained
publication commands create `STAGING/apt` and `STAGING/rpm`:

```sh
go run ./cmd/lab packages apt -output "$STAGING" \
  -signer-home "$SIGNER_HOME" -fingerprint "$SIGNER_FINGERPRINT" \
  -passphrase-file "$SIGNER_PASSPHRASE_FILE" \
  "$AGENT_DEB_AMD64" "$AGENT_DEB_ARM64"
go run ./cmd/lab packages rpm -output "$STAGING" \
  -signer-home "$SIGNER_HOME" -fingerprint "$SIGNER_FINGERPRINT" \
  -passphrase-file "$SIGNER_PASSPHRASE_FILE" \
  "$AGENT_RPM_AMD64" "$AGENT_RPM_ARM64"
```

APT emits separate amd64/arm64 package indexes covered by one signed Release;
RPM metadata carries both native architectures. Transfer only those completed
repository directories to the server's `repo/` subtree, never the signing home
or passphrase file. `-development-key` is reserved for disposable lab fixtures,
not production publication.

Configure the existing release directory and independently pinned native package
signer fingerprints in strict protobuf JSON:

```json
{
  "releaseRepository": {
    "directory": "/var/lib/lindm/releases",
    "nativeRepositories": {
      "aptSigningKeyFingerprint": "0123456789ABCDEF0123456789ABCDEF01234567",
      "rpmSigningKeyFingerprint": "0123456789ABCDEF0123456789ABCDEF01234567"
    }
  }
}
```

The fingerprint above is illustrative, not trusted release material. Obtain the
full uppercase 40-hex or 64-hex primary-key fingerprint through the release owner's
trusted channel. Keep all private signing keys outside the served directory.
Install the complete APT publisher output under
`/var/lib/lindm/releases/repo/apt` and RPM publisher output under
`/var/lib/lindm/releases/repo/rpm`. Include the target machine architectures;
an amd64-only publication cannot install an arm64 device. Server startup/readiness
checks do not replace native signature verification by the package manager.

For packaged Arch installations, publish the signed `.pkg.tar.zst` archives and
adjacent signatures with `lab packages arch`, using the same explicit signer
options. Place its output at `releaseRepository.directory/repo/arch` and configure
`nativeRepositories.archSigningKeyFingerprint`. The console's pacman path uses
`/repo/arch`, requiring signed packages and sync database with the exact trusted
key; absent Arch artifacts remain a visible gate. The RPM publication serves both
DNF and zypper clients; the registry, not the file extension, selects the command.

All replicas must mount or receive the identical signed snapshot before serving
traffic. Publish complete snapshots atomically, never update individual metadata
and package files underneath active readers. Preserve signed metadata lifetimes,
retain packages referenced by installed snapshots and restart replicas together
when replacing native repository snapshots or pinned bootstrap material. Startup
authenticates and captures a bounded file allowlist; changed or replaced files are
not silently admitted until restart. Stable metadata URLs revalidate against
content-digest ETags rather than caching changing names as immutable. For native
enrollment, the server needs read access only, not signing custody or repository
write access.

##### Signing-key rotation and compromise

The release pipeline's dedicated native signer signs packages and repository
metadata. Its private key never reaches `lindmd`. This choice preserves the
existing RPM/pacman package-signature trust and immutable repository snapshots;
it does not give a deployment daemon release authority. Agent package hashes
also match the authenticated release's DSSE attestations. Native signing,
release attestation, TUF update authority, execution signing and TLS keys remain
separate trust domains.

Rotate the native signer on the protected release workstation and publish a new
authenticated `lindmd` release. Verify that release through the independently
pinned release-attestation channel before installation. Restart every replica
with its identical payload. The console's **Repository and trust details** shows
the complete current native signer fingerprint; each copied installation command
pins it before installing trust. There is no daemon signing-key rotation endpoint.

Already installed devices retain their old native key pins. A server upgrade
does not silently replace those pins, and native installs or package refreshes
fail rather than accept the new key. Distribute the new console-generated trust
and installation instructions over the site's authenticated administrative
channel, replace only the lindm-specific keyrings/trust entries, and verify the
full fingerprint before restoring native repository access. Do not rerun a
used enrollment credential or replace an enrolled device's identity. TUF updates
retain their independent authenticated root and rollback checks.

For compromise, stop distribution of the affected release, preserve the release
and audit evidence, and inventory devices that trusted the exposed fingerprint.
Publish a clean release with a new native signer and authenticated attestations.
Remove the old native key from each device's lindm-specific trust and authorize
the new full fingerprint through the trusted administrative channel. A compromised
package signer alone cannot create a valid release attestation, but devices that
already trust it must not continue using native repository trust until repaired.
Never bypass signature checks, globally trust a fetched key, or treat a server
restart as revocation of keys stored on devices.

The server exposes the matching `/repo/apt/` and `/repo/rpm/` paths on its configured
HTTPS origin. Preserve unauthenticated `GET`/`HEAD` access through any reverse proxy.
Unauthenticated means a bare device can download packages; it does not require
Internet exposure. Directory listings, writes and private-key retrieval are not
supported. No repository URL supplied by a browser or external package host is
used.

#### Copy and run the enrollment command

1. Open **Settings › Agent repository**.
   Confirm **Ready** for the target OS and architecture.
   A stock authenticated release needs no repository setup.
   Resolve any HTTPS, execution-bootstrap or artifact verification failure.
2. Select **Enroll**.
   Issue a single-use code.
   Select the target OS.
   The platform registry selects APT, DNF, zypper or a separately available pacman path.
   A gated platform explains its missing packaging prerequisite.
3. Read **What this does** before running the command.
   Copy the command privately to the target device.
   Run it with administrative privileges.
   It verifies server and signer trust before adding this server's repository.
   It installs the agent and checks bootstrap trust.
   It enrolls the device using a protected code file.
4. Confirm **Enrolled** in the console.
   Command acceptance or package installation alone does not prove completed enrollment.

Keep the shown-once command private: it contains the bearer enrollment code.
Never paste it into tickets, shared shell transcripts or chat.
Never save the code in images or browser storage.
Revoke an exposed unused code.
Issue a new code.
A trust or signature failure requires corrected configuration or publication, never disabled checks.

Before installing, verify the downloaded primary signing key's complete fingerprint
against the authoritative deployment value. APT must use a dedicated `Signed-By`
keyring, not global trusted keys. DNF requires signed packages **and signed repository
metadata**, with `gpgcheck=1`, `localpkg_gpgcheck=1` and `repo_gpgcheck=1`; do not disable
verification when the configured publisher lacks signatures.

The response also contains the exact installed-agent `grant_command`,
`provisioning_command` and `resume_command` templates, without credentials. The
grant template reads `/run/lindm-enrollment/grant`; the unattended template reads
`/etc/lindm/provisioning-token`. Create their containing directories with protected
root ownership, and credential files with mode 0600. The templates use
`bootstrap -root /etc/lindm/execution-root.json -bundle /etc/lindm/bootstrap.dsse.json`
and exactly one of `-grant FILE` or `-provisioning-token-file FILE`, then
`resume -wait-seconds 3600`. Only `-grant -` supports stdin. These template strings
do not establish that repositories or authenticated bootstrap prerequisites exist.
Native declarative platforms must use their installed package executable path
while preserving these actual CLI flags and protected credential-file boundaries.
Never place bearer credentials in arguments, environment variables, URLs, shared
images or logs. Keep installer inputs private and remove them only after durable
success; removal does not promise forensic erasure of installer/WAL copies.

#### Automatic enrollment from an installer

For unattended device installation, issue a **provisioning token** instead of a single-use code.
Keep **Require another admin to approve each device** selected unless the site explicitly accepts direct enrollment.

1. Select the **Installer format** in the token result.
   Supported formats include cloud-init, Kickstart, Ubuntu autoinstall and AutoYaST.
   Select the **Operating system**.
   The registry lists only releases whose installation media support that format.
   NixOS shows its design-only gate.
2. Copy the snippet privately.
   Merge it into the complete configuration for the selected installer.
   The snippet contains the reusable token and every trust pin.
   Do not preinstall lindm in the image or installer.
3. Provide working name resolution and access to this server's HTTPS origin where the snippet runs.
   Kickstart and AutoYaST run it in the installer.
   Kickstart requires an active installer network, such as `network --activate`.
   Cloud-init and autoinstall run it on the installed system's first boot.
4. Find the device under **Devices waiting to enroll** after first boot.
   Obtain approval from another administrator through the approval inbox.
   Execute that approval as the token's creator.
   The provisioning unit waits at most one hour.
   It completes after approval.
   Confirm **Enrolled** in the console.

Kickstart fails the installation on any install or trust error. AutoYaST only
reports a failed chroot script, so when an AutoYaST device does not appear, read
`/var/adm/autoinstall/logs/` on it. On a timed-out approval, approve and then run
`systemctl restart lindm-provision.service` (or
`/usr/libexec/lindm/lindm-agent resume -wait-seconds 3600`) as root on the same
device; never reinstall to retry. Delete retained installer copies of the token
listed in the [enrollment contract](agent-enrollment.md#console-enrollment-operator-flow).

### Offline owner execution delegation

`lindmctl execution delegation sign` is an offline owner operation, not an admin
login or a server-side capability upgrade. It makes no network requests and never
loads development keys. Run it on the owner's isolated signing workstation with
the real deployment's authenticated execution root, associated quorum-signed
bootstrap, and sufficient distinct offline root signers. Private keys remain
offline; do not copy them into the server, executor, lab, or command arguments.
The software signer decrypts encrypted custody only in locked memory. It does not
accept plaintext private-key files or claim HSM custody.

The public root/bootstrap and declaration inputs must be singly linked regular
files owned by the invoking user with mode `0600`, in
directories owned by that user with mode `0700`. Directory ancestry is checked
without following symlinks; untrusted owners and non-sticky directories writable
by other users are rejected. The output has the same protected-directory and
file-mode requirements. Provision the authenticated public inputs through the
owner's trusted channel, not from an unverified declaration or online server
response. The root, bootstrap, CA certificates and release trust must be currently
valid. This command does not rotate roots or invent a historical bootstrap
acceptance time.

Prepare `delegation.json` as strict protobuf JSON for
`lindm.agent.v1.ExecutionDelegation` in
`api/lindm/agent/v1/execution_trust.proto`. Unknown fields are rejected. Explicitly
set `deploymentId`, `rootVersion`, the next deployment-global `version`,
`minimumRecoveryEpoch`, `notBefore`, `expiresAt`, and `delegates`. Each delegate
contains its public `key` (`keyId`: lowercase SHA-256 of DER SubjectPublicKeyInfo;
`publicKey`: base64-encoded 32-byte Ed25519 public key), one `role`
(`EXECUTION_SIGNER_ROLE_PLAN` or `EXECUTION_SIGNER_ROLE_START`), and its exact
`capabilities` array. A key has only one role. Plan and start keys must be distinct
from offline root, transport, device-CA and release keys. Production admission
also reserves deployment-local keys such as the server TLS leaf.

Select only the capabilities the owner approves, independently for each role:

| Operation                    | Exact capability               |
| ---------------------------- | ------------------------------ |
| Rotate escrow                | `device.escrow-rotate.v1`      |
| Bind TPM2                    | `device.tpm2-bind.v1`          |
| Lock sessions                | `device.lock-sessions.v1`      |
| Release lock                 | `device.release-lock.v1`       |
| Quarantine                   | `device.quarantine.v1`         |
| Release quarantine           | `device.release-quarantine.v1` |
| Crypto erase                 | `device.crypto-erase.v1`       |
| Sanitize                     | `device.sanitize.v1`           |
| Restart                      | `device.restart.v1`            |
| Shut down                    | `device.shutdown.v1`           |
| Refresh inventory            | `device.refresh-inventory.v1`  |
| Managed local-admin password | `device.local-admin-rotate.v1` |
| Patch now                    | `device.patch-now.v1`          |
| Offline enrollment           | `enrollment.offline.v1`        |
| Device capability policies   | `agent.capability-policy.v1`   |
| Systemd services             | `systemd.service.v1`           |
| Systemd unit definitions     | `systemd.definition.v1`        |
| Native packages              | `package.native.v1`            |
| Managed files                | `managed.file.v1`              |
| Local users                  | `local.user.v1`                |
| Local groups                 | `local.group.v1`               |
| Password policy              | `password.policy.v1`           |
| Kernel parameters            | `sysctl.v1`                    |
| Firewall zones               | `firewall.zone.v1`             |
| OS update policy             | `os.update.v1`                 |
| Encryption compliance        | `encryption.compliance.v1`     |
| SSH login banner             | `ssh.server.v1`                |

Resource capabilities are accepted exactly for the kinds with an agent provider
(`resource.ExecutableKinds`); server-side native qualification still decides which
rows are dispatched.

For example, selecting only `["device.refresh-inventory.v1"]` on both plan and
start delegates permits that protocol without granting restart or shutdown.
`agent.capability-policy.v1` is meaningful only on a PLAN delegate: that key signs
per-device capability policies (DSSE payload type
`application/vnd.lindm.agent-capability-policy.v1+protobuf`) that let the executor
enable registry-derived package, file, account, OS-update, kernel and firewall
providers without editing `executor.json`. A START delegate holding it authorizes
nothing. Without it the server issues no policy (`capability_policy_not_delegated`)
and devices keep only local providers; revoking it makes every accepted policy
INERT at the device's next trust update. A device owner can refuse remote policies
outright with `"capabilityPolicy": {"refuseRemote": true}` in `executor.json`.
No capability defaults, wildcards, prefixes, unknown versions, or arbitrary script
authority are accepted. Omission never grants permission. An explicitly empty
`delegates` array revokes all online signer authority; the review labels it as
such. Adding new software support never modifies an existing signed delegation.

After reviewing the complete declaration, sign it with the root quorum. This
example advances recorded delegation version 7 and retains recovery epoch 3;
replace those counters with the authenticated deployment state. Both counter flags
are required, even when their explicitly approved initial value is zero:

```sh
lindmctl execution delegation sign \
  -root /offline/lindm/execution-root.json \
  -bootstrap /offline/lindm/bootstrap.dsse.json \
  -declaration /offline/lindm/delegation.json \
  -custodian-identity-file /offline/lindm/custodian-identities.age \
  -custodian-identity-passphrase-fd 3 \
  -signer-custody /offline/lindm/root-key-1.age \
  -signer-custody /offline/lindm/root-key-2.age \
  -previous-version 7 -minimum-recovery-epoch 3 \
  -out /offline/lindm/delegation-v8.dsse.json
```

Supply descriptor 3 as a private anonymous pipe containing the custodian
passphrase, not an argument, environment value, regular file or named FIFO.
Offline encrypted inputs must be singly linked, caller-owned mode-0600 files.
The command locks current and future memory and disables dumps before decryption;
grant the offline process sufficient memory-lock authority, never bypass it.
Generated quick-start custody can instead use `-custody-export-file` with
`-custody-passphrase-fd`; its encrypted export contains the root ciphertexts.
Plaintext PKCS#8 signer flags are not supported. The root and bootstrap remain
independently authenticated public inputs, not learned from the encrypted export.

The command checks the typed declaration and supported capability set, signs using
`trust.Authority`, then proves the result with the production DSSE execution
verifier, including quorum, key-domain separation, root binding, version/epoch
fences and validity. It also checks the production trust-update envelope bound.
Only then does stdout list the deployment, root/delegation versions, recovery
epoch, validity, quorum count, envelope SHA-256 and every exact key ID, role and
capability. It never prints private key material or input contents on parse errors.
Review these public facts before approving distribution.

Output is synced and atomically published without replacing any existing path,
including a symlink. A failed verification publishes nothing. An output/reporting
error after publication may leave the complete file present: inspect the file and
its reviewed digest rather than blindly retrying or removing existing authority.
The command does not install or mutate server/device trust. Transfer only the
public DSSE envelope through the authenticated `UpdateExecutionAuthority` admin
workflow; admission and device synchronization retain their independent root,
rollback, authorization and key-custody checks. Owner delegation permits specific
online signers, not a bypass of RBAC, step-up, human approvals, fresh start grants,
native preflight, or recovery safety.

### Device management capabilities

A stock console-installed agent's `/etc/lindm/executor.json` enables no providers.
Provider authority additionally comes from a server-signed per-device capability
policy drawn from the closed `lindm.agent.v1.ManagementCapability` catalogue:
packages, files under the release's standard roots, the kernel-module blocklist,
local accounts, firewall zones, OS updates and kernel settings. Password policy and
custom file roots are local only: a signed policy can never grant them; set
`password_provider` or `file_provider.allowed_roots` in `executor.json`. A policy
carries only catalogue values, sysctl key names and the deployment's firewall
endpoints and connectivity guard; paths, repositories, vendor keys and account
ranges come from the platform registry inside the agent binary, and every provider
deny list and protected-path check still applies.

Policies exist per scope: the deployment (all devices), a static group or a dynamic
group. A device's grant is the union of the deployment policy and every group whose
membership definitely includes it; a dynamic group with stale inventory does not
grant. New installations start with packages, files, local accounts and OS updates
for all devices. The kernel-module blocklist and kernel settings (exactly the listed
keys) are opt-in per scope. Firewall can be enabled, at any scope, only after the
deployment policy carries firewall settings (management endpoints and a connectivity
guard); those settings cannot be removed while any scope still grants the firewall
(`capability_firewall_settings_required`).

Enable or disable a capability by replacing the scope's complete policy with
`SetCapabilityPolicy` (or `Organization.capability_policies` through
`lindmctl apply`, applied after groups and unchanged when equal). It requires
unrestricted `execution_trust.manage`, a fresh directory authorization and the
scope's current revision; a stale revision is refused as
`capability_policy_revision_conflict` and nothing changes. An empty group policy is
removed; an empty deployment policy grants nothing. Each change is audited in the
same transaction as `capability_policy.set` with the scope, the capabilities before
and after, the sysctl key count, whether firewall settings are present and the
reason. `ListCapabilityPolicies` requires unrestricted `fleet.read`.

Devices pick the change up on their next management cycle. The server signs a new
version for a device only when its effective grant changed and audits each issued
version as `capability_policy.issue`. Signing requires the offline owner to delegate
`agent.capability-policy.v1` to the online plan key; until then nothing is signed and
the settings page, device page and device poll report
`capability_policy_not_delegated` (no delegation at all:
`execution_authority_unconfigured`). The executor verifies every policy under its
own trust root and delegation, binds it to its enrolled device and generation, and
treats an accepted policy as inert, granting nothing, once the current delegation no
longer authorizes its signer. Revoking `agent.capability-policy.v1` therefore
withdraws remote grants at the device's next trust update.

A device owner can refuse remote capability policies entirely by setting
`capability_policy.refuse_remote: true` in `/etc/lindm/executor.json`; provider
authority then comes from that file only. This is the local ceiling: no server,
delegation or console action can override it.

A profile row the executor refuses because its capability is not effective is
BLOCKED with reason `capability_<name>_not_enabled` (for example
`capability_packages_not_enabled`). Such rows and releases are dispatched again
when the device's signed grant changes or its reported capability status changes;
a row refused because an existing unowned object needs an approved adoption is
BLOCKED `adoption_required`.

A row refused for the device's own tool or package state is dispatched again
when the device reports changed packages, without an administrator retry. This
covers `native_tool_outdated`, `native_tool_missing`, `unit_not_installed`,
`existing_package_unverified` and `existing_package`. "Changed packages" means a
committed package snapshot that differs from the previous one. An unchanged
periodic snapshot releases nothing.

What a stock console-installed agent manages, per qualified resource kind, on the
two natively qualified desktop releases (the delegation must include
`agent.capability-policy.v1`; "default" means the seeded all-devices policy):

| Kind                    | Ubuntu 24.04                                                                                                                                                                                                                                                                         | Fedora 44                                                                                                                                                                                                                                                                                                                                                                                                                    |
| ----------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Systemd service         | Works out of the box; a unit that is not installed is BLOCKED `unit_not_installed`                                                                                                                                                                                                   | Same                                                                                                                                                                                                                                                                                                                                                                                                                         |
| Systemd definition      | Works out of the box                                                                                                                                                                                                                                                                 | Works out of the box                                                                                                                                                                                                                                                                                                                                                                                                         |
| Encryption compliance   | Works out of the box (read-only)                                                                                                                                                                                                                                                     | Works out of the box (read-only)                                                                                                                                                                                                                                                                                                                                                                                             |
| Native package          | Default (PACKAGES): Ubuntu archive `noble`, `noble-updates`, `noble-security`; OS-preinstalled packages are adopted with an approved adoption once their provenance is proven against the archive (create-only: BLOCKED `existing_package`), otherwise `existing_package_unverified` | Default (PACKAGES): Fedora `fedora` + `updates` metalinks; OS-preinstalled packages are adopted with an approved adoption, as on Ubuntu; dnf5 older than 5.4.6.0 (the release image) is refused `native_tool_outdated` (console: apply all OS updates once); one OS update run that installs all updates raises it, security-only runs do not ([Fedora](platforms/fedora.md#capability-policy-facts-signed-provider-grants)) |
| Managed file            | Default (FILES) under `/etc/motd.d` and `/etc/issue.d`, created when absent; other paths need the local `file_provider.allowed_roots`                                                                                                                                                | Same                                                                                                                                                                                                                                                                                                                                                                                                                         |
| Kernel-module blocklist | Opt-in per scope (KERNEL_MODULE_BLOCKLIST)                                                                                                                                                                                                                                           | Opt-in per scope (KERNEL_MODULE_BLOCKLIST)                                                                                                                                                                                                                                                                                                                                                                                   |
| Local user and group    | Default (LOCAL_ACCOUNTS): IDs 1000–59999, homes under `/home`; creation needs explicit IDs, home and shell (`explicit_account_identity_required`)                                                                                                                                    | Same                                                                                                                                                                                                                                                                                                                                                                                                                         |
| OS update policy        | Default (OS_UPDATES); needs `unattended-upgrades` plus `needrestart` or (stock desktop) `update-notifier-common`; `native_tool_missing` names the one to install                                                                                                                     | Default (OS_UPDATES); needs only `dnf5` and `rpm`. Without `dnf5-plugin-automatic`/`dnf5-plugins` (the stock image) window runs use `dnf5 upgrade [--security]` and an rpm reboot oracle; an enabled `dnf5-automatic` timer is refused                                                                                                                                                                                       |
| Firewall zone           | Opt-in (FIREWALL) after the deployment's firewall settings exist                                                                                                                                                                                                                     | Same                                                                                                                                                                                                                                                                                                                                                                                                                         |
| Kernel setting          | Opt-in per scope with exact keys (KERNEL_SETTINGS); approved adoption                                                                                                                                                                                                                | Same                                                                                                                                                                                                                                                                                                                                                                                                                         |
| Password policy         | Local only: `password_provider` in `executor.json`; approved adoption                                                                                                                                                                                                                | Same                                                                                                                                                                                                                                                                                                                                                                                                                         |
| SSH login banner        | No capability; base-files ships `/etc/issue.net`, so a create-only row is BLOCKED `existing_banner_file` until an approved adoption                                                                                                                                                  | No capability; the stock `/etc/issue.net` is a symlink, BLOCKED `existing_banner_symlink` until a native administrator replaces it                                                                                                                                                                                                                                                                                           |

Ubuntu 22.04, Rocky Linux 9/10 and AlmaLinux 9/10 derive the same defaults where
their registry rows qualify the provider (see the platform pages). Package-source
defaults on the other Tier 1 releases are:

| Release                        | Default PACKAGES source                                                                                                          | Prerequisite or gate                                                                                                     |
| ------------------------------ | -------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------ |
| Debian 12                      | `bookworm`, `bookworm-updates` (`deb.debian.org/debian`) and `bookworm-security` (`security.debian.org/debian-security`), `main` | Exact registry-pinned `debian-archive-keyring` bytes and archive signing fingerprints                                    |
| Debian 13                      | `trixie`, `trixie-updates` (`deb.debian.org/debian`) and `trixie-security` (`security.debian.org/debian-security`), `main`       | Exact registry-pinned `debian-archive-keyring` bytes and archive signing fingerprints                                    |
| RHEL 9/10                      | Device's entitled RHSM-managed BaseOS and AppStream repositories                                                                 | Register this device with Red Hat; pinned Red Hat release key required                                                   |
| Linux Mint 22.3, Pop!_OS 24.04 | Ubuntu `noble`, `noble-updates`, `noble-security`, `main` and `universe`                                                         | Ubuntu archive keyring pins; own vendor archives excluded because their package-source keys have no registry digest pins |

RHEL entitlement and TLS credentials remain on the device. The server grants a
catalogue capability, never receives subscription secrets and cannot supply an
arbitrary entitled repository ID or replace the vendor key. Only the registry's
BaseOS/AppStream IDs are approved; third-party repositories, including EPEL, are
not included. Consequently `git` is a vendor-source row on RHEL, while `htop`
requires a separately approved source and is not promised by this default.
Signed capability derivation is implementation, not native qualification: see the
[verification ledger](verification.md) for exercised platforms and architectures.

In the console, **Settings → Device capabilities** (`/settings/capabilities`,
readable with unrestricted `fleet.read`, editable with unrestricted
`execution_trust.manage`) lists the catalogue in plain words, the policy for all
devices and one row per static or dynamic group policy. Every change names its
audited reason, carries the scope's revision (a stale revision is refused as
`capability_policy_revision_conflict` and the editor offers a reload, never a blind
retry) and passes the fresh directory check; a `directory_unavailable` outcome keeps
the exact request for retry. The editor states which capabilities it turns on and
off and for whom before saving. Firewall stays disabled until the all-devices policy
has management endpoints and a connectivity check, entered as endpoint rows and the
pasted `connectivity_guard` protobuf JSON, validated in the browser with the
server's own rules and read back as a probe summary. Password policy and custom file
roots are listed as device-only (`password_provider`, `file_provider.allowed_roots`
in `/etc/lindm/executor.json`). When `issuance_unavailable_reason` is set the page
and each device page say that the owner must delegate `agent.capability-policy.v1`
with `lindmctl execution delegation sign`. The device page's **Services** tab shows
each capability's granting scopes, the executor-reported status (Enabled, Set
locally, Not enabled, Unavailable with its cause) and the issued versus applied
policy version; a profile item blocked by `capability_*_not_enabled` says how to
enable it, or that the device reports it unavailable, and adoption refusals link to
Rollouts.

### Agent directory custody

Privileged agent configuration, execution inputs and runtime paths share the
`internal/custody.TrustedDirectory` policy at every checked directory, including
the filesystem root: UID 0 is required, other-write is forbidden, and group-write
is permitted only for GID 0. Thus a vendor root directory with mode `0775` and
owner `root:root` is trusted, while `0775 root:users`, `0777` and non-root owners
are not. Membership in group zero is a privileged custody grant; never place the
network account or another untrusted account in it. This admits Fedora's vendor
image layout without chmodding the host or weakening protection for other groups.
Configuration rejects a network account with primary or supplemental group zero
membership, querying the account database rather than checking its primary GID
alone. At connection establishment the executor independently checks the actual
Unix peer's primary group (`SO_PEERCRED`) and supplemental groups
(`SO_PEERGROUPS`), rejecting non-root peers in group zero. Missing or incomplete
kernel group evidence fails closed. This uses kernel-snapshotted connection
credentials, not a race-prone `/proc/<pid>` lookup; root provisioning remains
root-authorized.

Path walks pin directory descriptors and open components with `O_NOFOLLOW`;
symlink metadata is never accepted as directory metadata. Systemd's separately
bounded, descriptor-pinned vendor-link resolver lives in `custody.OpenResolved`
and retains its existing checks on both source and resolved ancestry.
Private state/spool and temporary-parent APIs
retain their separate caller-ownership and sticky-directory protections; their
final private directory still requires its exact owner and mode `0700`.
Configuration files, secret files and executable files retain their stricter
file-specific permissions; the group-zero exception is only for directories.
Native providers, recovery boot state and native executables use the stricter
`custody.OpenRoot` walk instead, which admits no group write at all (see
architecture "Native process and file custody policy").

Recovery secrets use envelope encryption with per-record data keys and a separately
protected wrapping key. The API never returns them in inventory, exports or routine
logs. Reveal requires a dedicated permission, recent step-up, reason, and audit;
policy may require a second approver. Responses are no-store and auto-dismiss in UI.
Rotation establishes and verifies the replacement recovery path before retiring the
old one. A failed escrow cannot remove the only working unlock key.

Inventory, recovery escrow, LUKS validity and an actual cold-boot unlock are different
facts. Track all four. Qualify each encryption owner independently, including ordinary
LUKS2 versus vendor-managed TPM encryption. Never modify slots behind the owning
vendor interface. A valid recovery key retained in escrow/backups or a recoverable
LUKS header invalidates a simplistic "delete the local keyslot = secure erase" claim.

### Vendor RPM metadata trust

Owner decision (2026-10-12): an approved RPM source may waive repository
metadata signatures (`RpmRepository.require_metadata_signature=false`) only
because Fedora signs no `repomd.xml` (no `repomd.xml.asc` for releases/44 or
updates/44, [fedora.md](platforms/fedora.md#capability-policy-facts-signed-provider-grants)).
The trust model is then: repository metadata is verified via Fedora's HTTPS
metalink (MirrorManager over TLS publishes the `repomd.xml` checksums librepo
checks against whichever mirror serves it), and every package is verified with
Fedora's signing key (`gpgcheck=1` always). The key file is pinned in the
agent's registry by SHA-256 of its exact bytes and by primary-key fingerprint;
any other bytes leave PACKAGES unavailable (`vendor_key_unrecognized`).

The waiver is admitted only when every repository of the source is an HTTPS
metalink on a host the running release pins in the registry
(`mirrors.fedoraproject.org` for Fedora 44): configuration load, the package
provider's source check and the root package helper all refuse anything else.
A base URL without signed metadata is never accepted, signed-metadata sources
keep `repo_gpgcheck=1`, and the protocol requires a metalink for every
repository whenever metadata signatures are waived
(`rpm_repository.metadata_authenticity`). Residual risk: whoever controls
`mirrors.fedoraproject.org`'s TLS identity can serve stale or withheld (but not
forged) package sets; packages still need Fedora's signature.

The waiver is Fedora's alone. Rocky Linux and AlmaLinux 9/10 publish
`repomd.xml.asc` for BaseOS, AppStream, CRB and extras, so their
registry-derived BaseOS and AppStream sources use HTTPS base URLs with
`repo_gpgcheck=1`
([alma-rocky.md](platforms/alma-rocky.md#capability-policy-facts-signed-provider-grants)).

### Recovery escrow provisioning and incident procedure

Configure `escrow.transport_key_file` with one unencrypted PKCS#8 RSA private key
(3072–4096 bits) and `escrow.wrapping_key_file` with exactly 32 CSPRNG bytes. Both
files must be owned by root or the server service identity and mode `0600`; paths
are resolved from the configuration directory. Use different files and keys from
TLS, device CA, execution signing, integration credentials and backup encryption.
Mount these files read-only into the server process. All replicas serving the same
escrow records require the same wrapping key. Back up custody separately from the
database and exercise restoration with an isolated record before relying on it.
Losing the wrapping key loses access to previously stored recovery keys; replacing
it with a new random key does not rotate or recover old envelopes.

Before the first rotation, record the exact LUKS UUID, native device identity,
independent owner recovery slot and supported encryption owner in the executor's
root-owned `action_provider` configuration. Install the generated per-target
systemd exception using `lindm-agent action-sandbox -install`, then explicitly
reload systemd and restart the executor. This root-only provisioning command owns
`/etc/systemd/system/lindm-executor.service.d/50-device-actions.conf`; packages do
not guess fleet-specific disk identities. The exception retains `PrivateDevices`,
binds only the qualified block devices and required mapper/TPM nodes, and admits
only their required device access. The native qualification lane must install
this same exception and run the packaged executor, not an unrestricted substitute.

Create the rotation through the encryption panel/API. Supply the existing unlock
credential locally as root using `lindm-agent action-credential -action UUID`
with a protected stdin pipe. The command consumes exact bytes: an appended newline
changes the credential. Never put a passphrase in shell arguments, history,
environment variables, a temporary file or the console action specification.
The local RPC retains it only for its one prepared action and short validity.
Its omission or expiry cannot authorize fallback keyslot removal.
The packaged executor disables core dumps and swap with `LimitCORE=0` and
`MemorySwapMax=0`; qualified hosts must enforce cgroup-v2 swap accounting.
Credential retention and anonymous helper descriptors are additionally locked
and excluded from process dumps. Run the root credential-upload command in an
equivalent no-swap/no-core transient systemd unit (`systemd-run --pipe --wait`
with those two properties) so its RPC encoding buffers share the same protection.
Neither memory locking nor deleted temporary files protects plaintext that was
already copied into unencrypted swap, crash dumps or a shell transcript.

After adding and locally verifying the new slot, the executor reports only
server-encrypted key material. Wait for durable escrow acknowledgment and the
final attested rotation result. If a crash, storage failure or network partition
occurs, preserve the current slots and journal; do not manually delete an
apparently duplicate slot or rerun the same irreversible effect. Inspect the
action's persistent phase and independently test retained recovery paths before
authorizing any new cleanup. An unknown outcome is not a failed transaction whose
effects may safely be repeated.

Recovery reveal requires `recovery_keys.read`, a reason and recent verified
step-up, and follows the reveal approval rule below. The device Encryption tab
states the rule that applies next to Reveal. The returned 64 hexadecimal characters are
the literal unlock passphrase, not a hex encoding to decode into binary. Reveal
responses are no-store; the console dismisses its memory-only display and never
caches secrets. Record the actual cold-boot unlock separately from escrow status.
A same-boot key test does not qualify cold-boot recovery or TPM PCR behavior.

Suspected key disclosure requires a new recovery rotation and custody incident
handling, including backup/header-copy disposition. Deleting an escrow database
row cannot revoke a key copied from a backup. Do not claim crypto erase when a
retained header plus retained key can still recover the data.

### Managed secrets and local-admin passwords

Managed secrets and local-admin passwords reuse the recovery escrow custody
above: without `escrow.transport_key_file` and `escrow.wrapping_key_file` every
secret and local-admin RPC fails with `escrow_unconfigured`, and nothing is stored
unencrypted. Losing the wrapping key loses every managed secret version and
escrowed password, exactly as for recovery keys; back it up with the same custody.

`secrets.manage` (owner, admin) creates and rotates deployment-global secrets and
sets per-device local-admin policies; `secrets.reveal` (owner, admin) reveals
them. Secret create, rotate and reveal need an unrestricted principal because a
secret is not device-scoped. Reveal additionally needs a reason and a local
browser session signed in or re-verified within five minutes (password plus
passkey); OIDC and CLI sessions never satisfy step-up. When the window has
passed, the console's refusal offers an in-page check (`POST
/auth/local/step-up/begin` with the password, then `/finish` with a passkey
assertion bound to the same session) that records `stepped_up_at` on that
session and resends the same request; a wrong password counts toward lockout and
no new session is issued. Every attempt is audited before any plaintext
leaves the server, and responses are `no-store`.

Enter a password-hash secret as a crypt(3) string, never the password: for
example `mkpasswd -m yescrypt` (Debian/Ubuntu `whois`) or
`openssl passwd -6` on an offline workstation, without placing the password in
shell history. A profile's `HashedPasswordPolicy` must name the secret's exact
`secret_id`, `version`, purpose and `subject_binding_id`, and the algorithm must
match the hash prefix. Rotating a secret appends a version; publish a new profile
revision that references it to deliver it. Delivery also requires the assigning
administrator to still hold `secrets.manage` and the device to have registered
its encryption key; otherwise the assignment shows the blocking reason.

Local-admin rotation requires the device's root-owned
`action_provider.local_admin_accounts` to list the exact existing, non-root
account; a remote policy cannot add accounts. Delegate
`device.local-admin-rotate.v1` to both plan and start keys. After changing the
list, rerun `lindm-agent action-sandbox -install`, reload systemd and restart the
executor: a nonempty list adds `ReadWritePaths=/etc` (chpasswd atomically
replaces `/etc/shadow`), `CAP_IPC_LOCK` and `LimitMEMLOCK=infinity`, because the
generated password is held only in locked memory. The executor generates a 26-character
base32 password (at least 128 random bits), escrows it, and sets it with
`chpasswd` only after the server acknowledges durable storage. A rotation that is
interrupted while setting the password is `UNKNOWN`: reveal it and the previous
`CURRENT` password, test them, then request a new rotation. Never retry by hand
with another tool. After a reveal the policy schedules a rotation after its
post-reveal delay, so a revealed password stays valid only that long. Rotation
changes only the local password: it does not end existing sessions, change SSH keys,
sudo rules or directory accounts.

Suspected disclosure of a managed secret requires a new version, a profile revision
delivering it and, where the secret authenticates elsewhere (Wi-Fi, VPN,
repository), rotation at that service. Suspected disclosure of a local-admin
password requires `RequestLocalAdminPasswordRotation`. Devices that received a
secret keep its native effect (for example a shadow hash) until a later
revision or release changes it.

### Reveal approval rule

Recovery-key (`recovery_keys.read`), local-admin password and managed-secret
(`secrets.reveal`) reveals need a second human's approval of the exact reveal
request whenever another human could give it. The server decides on every
reveal request, from current database state, never from the console's copy:

1. `escrow.reveal_approval_required: true` always requires approval. It is an
   override for deployments that want two people even when only one admin can
   reveal; with a single eligible admin, nobody can then approve.
2. Listing the reveal permission in the authorization policy's
   `approval_required_permissions` always requires approval.
3. Otherwise approval is required exactly when at least one **other eligible
   approver** exists; a deployment with one eligible admin reveals alone.

An eligible approver is a principal other than the requester that could decide
the request: enabled and not deactivated in its last committed state (local
account setting or last directory observation, however old), holding both the
same reveal permission and `approvals.manage`, with each grant reaching the
device (recovery keys and local-admin passwords) or unrestricted
(deployment-global secrets). These never count: service accounts; local accounts that have
not enrolled a sign-in credential; break-glass accounts, including local accounts
designated break-glass in local-primary mode, because they hold no standing
authority outside an audited emergency session and routine reveals must not
depend on unsealing one; and the requester's own browser or CLI sessions, which
are the same principal. A break-glass account whose emergency allowlist grants the
permission and `approvals.manage` may still decide a request during an active
emergency session.

The console shows the result beside Reveal: "Needs approval: another admin can
approve" or "You're the only admin who can reveal this, so no approval is
needed" (or that the server setting or role policy requires approval). Approval
decisions are still fenced at decide and reveal time: an approver disabled, demoted
or descoped after the request is created can no longer approve, and an approval they
gave is refused at reveal. If that leaves the requester as the only eligible admin,
a new reveal without approval succeeds. The requester can never approve their own
request. There is no opt-out of the default rule; a single-admin deployment needs
none. Disabling, demoting or descoping another admin so that one can reveal alone
is an account or directory change, audited as such.

### Declarative organization apply

`lindmctl apply -f FILE [-dry-run] [-secrets-out NEW_FILE] [-o table|json]`
uses the existing pinned CLI login and AdminService authorization. `-config FILE`
selects the same protected credentials as other CLI commands. No database access,
alternate API key or browser-session bypass is introduced.

```sh
lindmctl apply -f lab/demo/org.json -dry-run
lindmctl apply -f lab/demo/org.json -secrets-out /private/org-secrets-001.json -o json
```

Review the dry-run first. It reads current server state but does not publish,
issue credentials, create target previews, refresh/promote rollouts or activate
assignments. Rollout planning uses the authorization-equivalent read-only
projection. The table has kind, name, ID, status and reason columns; JSON contains an
`outcomes` array with `kind`, `name`, optional `id`, `status` and optional `detail`. Table cells escape
terminal control characters. Statuses are `created`, `updated`, `unchanged`,
`pending` or `unsupported`; in a dry-run, created/updated describe proposed changes,
not completed work. Successful apply is control-plane acceptance, not proof of
device compliance. Pending and unsupported objects remain visible even when other
objects can be applied.

The operation is not an atomic transaction. It stops on errors, returns a failing
exit status and preserves outcomes and secrets from earlier successful operations.
Mutations are never automatically retried. The one exception is an assignment's
rollout review the server rejected with `targeting_revision_conflict` or
`targeting_impact_stale`: a concurrent membership or head change committed first
and nothing was recorded. Apply reviews afresh up to three times, then reports
that assignment `pending` instead of failing. A rollout still starts only from the
exact review that was returned.
Audit reasons are derived as
`Apply organization NAME`; request IDs bind the organization, object identity and
completed request, including observed compare-and-swap versions. Review current
state before a fresh apply after a conflict or ambiguous transport failure.
Omitting an object never deletes it.

Target activation consumes an exact retained preview hash. Pending approval reuse
requires the authenticated requester, unchanged membership/input digest and unexpired
retained evidence; another administrator's approval is never adopted. Changed or
expired evidence requires a fresh independent review, not a weakened activation.

Secrets are **never printed by apply**, including with JSON output. When the plan
would issue a provisioning token or grant, `-secrets-out` is required. The command
reserves this new file before mutations using exclusive creation and mode 0600;
existing files and symlinks are refused. Use a private parent directory. The file
contains a JSON array of issued credentials with `kind`, `name`, `id`, `secret` and
optional `expires_at` (protobuf timestamp fields). Keep it out of source control,
logs and backups that are not approved for credentials. Even when a later operation
fails, earlier issued secrets are saved. A file-write failure may make issued
secrets unrecoverable; do not retry issuance blindly. Existing unrevoked credentials
are not renewed or revealed again, including after consumption or expiry. Explicit
revocation releases the name; a subsequent apply binds its issuance request to the
latest revoked predecessor and returns a new secret once. A new declarative name is
also an explicit replacement. `-dry-run` rejects `-secrets-out` and creates no file.

#### Organization specification

The only schema is
[`lindm.org.v1.Organization`](../api/lindm/org/v1/organization.proto), loaded as
strict protobuf JSON with unknown fields rejected recursively. The engine validates
the composition and completed product API templates before mutation. The maintained
example is [`lab/demo/org.json`](../lab/demo/org.json).

| Section                        | Meaning                                                                                                                                           |
| ------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------- |
| `name`                         | Stable organization namespace, also used for enrollment names and audit reasons                                                                   |
| `groups`                       | Stable UUID/name pairs for static, RBAC-capable device groups; apply does not replace memberships                                                 |
| `dynamicGroups`                | Product targeting expressions; dynamic groups never grant RBAC membership                                                                         |
| `profiles`                     | Stable UUID plus a typed `ResourceProfile` in `spec`; changed content publishes an immutable revision                                             |
| `assignments`                  | Declared `profileId` plus a product target assignment; omit `profileRevisionId`, which the engine resolves                                        |
| `rollouts`                     | Product rollout specifications with stable IDs; existing specifications are immutable                                                             |
| `provisioningTokens`, `grants` | Stable names plus product request templates; omit engine-owned request IDs, reasons and names                                                     |
| `advisoryExceptions`           | Exact hostname/advisory/package selectors plus the product acceptance reason and absolute expiry; omit engine-resolved request/device/finding IDs |
| `accounts`                     | Product account requests; CLI directs the operator to Accounts → Import organization in a browser session without creating accounts               |
| `authorization`                | Complete runtime role/group/approval policy, read and replaced through AdminService with an observed revision and durable request replay          |

The demo declares Engineering, Finance, IT/Helpdesk and Contractors static groups
and matching label-based dynamic groups. Each group's provisioning token applies
both static membership and a `department/...` label. Dynamic groups select those
labels for profile targeting; they do not substitute for authorization groups.
The one-time grant carries no group or label, so assign its device deliberately
after enrollment. Company baseline targets all four dynamic groups at priority 0;
department profiles have priority 100 and override the same canonical
firewall-zone or update-policy resource where applicable. Every declared resource
row is one the server dispatches under its qualified ownership operations (checked
by a unit test); the rows removed for that reason are listed under
[gaps](#declarative-organization-gaps).

Company baseline and Engineering tools contain `OWNERSHIP_MODE_APPROVED_ADOPTION`
rows, so `apply` reviews each of their assignments and leaves the rollout
`pending` with the one `resources.rollout` approval it requested. Nothing is saved
or sent to a device until a second human with `approvals.manage` and unrestricted
`resources.assign` approves it in the console (Approvals). A group with no enrolled
device has nothing to approve; its assignment is saved and rolls out after review
on a later apply. An unapproved request expires after an hour, and the next apply
requests a new one. Each rollout is reviewed against the devices' current heads.
When two pending rollouts cover one device (Company baseline with Engineering tools
or with a department profile), the later activation finds the device changed and
holds it for review instead of applying a stale plan. After the approved rollouts
start, run `apply` again. It rolls held devices out in a follow-up rollout, which
needs its own approval when it adopts. Repeat until no assignment is `pending`.
A review lists an enrolled device that has not reported inventory yet, but neither
counts nor plans it, so it never makes an unchanged apply start another rollout;
the first apply after it becomes active rolls it out.
The persistent lab demo and the console review seed have their independent
approver account approve these requests through the same API, in the same rounds.

Declared rollouts are stage plans, not stored objects: an assignment that names
one rolls out through its stages on each `apply`, and an unreferenced one creates
nothing. An assignment that names none rolls out in one stage to every reviewed
device, never pausing on failures. Its approval covers the adoption rows too. The
declared Engineering stage plan is not yet referenced by an assignment:
Pilot admits 25% (at least one canary), then Fleet admits 100% after explicit
promotion. Both rings require at least one observation, a 24-hour soak and health
evidence no older than one hour. Failure, unknown and unavailable thresholds remain
enforced. The shared organization example leaves it unlinked because synthetic
executors cannot establish native rollout health; linking their unsupported head
would correctly pause it before dispatch. Real-device operators may explicitly
link a qualified assignment to the rollout without weakening these gates.

Company baseline sets deny-by-default ingress with TCP/22 allowed
for both IP families, `/etc/motd.d/50-company`,
disabled/stopped `cups.service`, and daily security-update starts between 02:00 and
04:00 Europe/London. Reboots use `SCHEDULED` within an independent daily
05:00–07:00 Europe/London reboot window, at most 360 minutes after the update, with
up to two 30-minute employee deferrals. An already-running update is not killed at
window end. It adopts `net.ipv4.conf.all.accept_redirects`,
`net.ipv4.conf.default.accept_redirects` and `net.ipv6.conf.all.accept_redirects`
(persistent `0`; none is a key the kernel-settings provider protects). The
organization's deployment capability policy grants KERNEL_SETTINGS for exactly
those keys. A deployment request replaces the whole deployment policy, so it also
repeats the default PACKAGES, FILES, LOCAL_ACCOUNTS and OS_UPDATES. Release
restores each captured value. Company baseline also adopts the local password
policy (`system/local-auth`: 14 characters, 3 classes, history 10, 90-day maximum
age, lockout after 5 failures for 15 minutes, root included). PASSWORD_POLICY is
local-only, so a device applies it only where root sets `password_provider` in
`/etc/lindm/executor.json`. Elsewhere the row is blocked
`capability_password_policy_not_enabled`, and the console names that field.
`/etc/motd.d` is a registry standard root on Ubuntu 22.04/24.04,
Debian 12/13, Fedora 44, Rocky Linux 9/10 and AlmaLinux 9/10, so the default
FILES capability covers it there; approving `/etc` is not a substitute.
When `/etc/motd.d` is absent (stock Ubuntu 24.04) the file provider creates it
root:root 0755 and removes it on release only if it created it and it is empty.
Creating or removing the root needs its parent in the transient effect unit's
write set, so that one effect may write `/etc` (as the SSH banner and password
helpers do); the native code only `mkdirat`/`unlinkat`s the held name below a
root-protected parent descriptor. The host must use pam_motd to display that
directory.

Engineering adds git, htop and podman (DEB `arm64` for the demo's Ubuntu 24.04
aarch64 laptop), the typed SSH login banner, plus the local
`developers` group and a `developer` user with a locked password, not an embedded
login secret. The banner row is an approved adoption: Ubuntu's base-files ships
`/etc/issue.net`, which create-only would refuse as `existing_banner_file`, so the
approved rollout captures it as the release baseline. On Fedora, the stock
symlink remains `existing_banner_symlink`. The Ubuntu `deb/git` and `deb/htop`
rows are approved adoptions too: the Ubuntu image already installs both, and
create-only would refuse them as `existing_package`; the same rollout approval
adopts them once preparation proves them against the archive, and release
never removes them. Finance blocks USB storage
(`usb_storage`, `uas`) through the typed kernel-module template and removes the SSH
firewall exception. Contractors deny ingress and default egress, permitting only outbound
TCP 80/443/53 and UDP 53 for both IP families, with a nightly 02:00–02:30 update
start window. This restriction requires a compatible firewall backend and may block
nonstandard control-plane ports. Preserve the executor's connectivity guard; do not
bypass a refused network change. Other rows use create-only ownership, so existing
unowned native state may require the normal explicit adoption workflow rather than
being silently taken over; service rows retain native state on release.

**Executor native repository approvals:** Engineering's package rows name each
package once per package family and leave the architecture to the device: the
executor resolves its native package architecture from dpkg or rpm and records the
resolved architecture in its evidence. The DEB rows apply only to Ubuntu 24.04 and
use repository UUID `8053e72a-44e8-53fc-9472-825c068cf9b5`; the RPM rows apply only
to Fedora 44 and RHEL 9/10 (htop to Fedora only, because RHEL ships it in EPEL) and
use `12e3a0eb-c710-58d9-bd79-a491c614754c`. Rows outside a device's platform show as
not applicable and are never sent. In each executor's approved package sources,
bind that UUID to the host's own official HTTPS archive (Ubuntu: `archive.ubuntu.com`
on amd64, `ports.ubuntu.com` on arm64), suite/components and authenticated signing
key/digest through the existing native-package provider configuration. These are
explicit operator approvals, not repositories created or trusted by apply.

Configure `demo-helpdesk` with `fleet.read`, `remote_assistance.view` and `actions.lock`;
configure `demo-security-analyst` with `fleet.read`, `advisory_exceptions.manage`,
`approvals.manage` and `actions.lock`. Set `approval_required_permissions` to include
`actions.lock` in the runtime authorization policy. Organization apply installs this
policy before accounts; no server-file edit or restart is required. Helpdesk and
analyst are scoped to the demo's Engineering, Finance and IT/Helpdesk device groups.
Helpdesk requests a lock; a different analyst can approve it because they have both
approval and lock authority. The requester cannot approve their own action.
Owner and auditor use their built-in roles. Import the organization from Accounts
in the console to create these accounts and save their shown-once enrollment secrets;
the CLI bearer deliberately cannot do this.
The helpdesk example is view-only: it grants neither control nor clipboard, files
or unattended access. Remote assistance still requires device-user consent.

Advisory exception examples select `demo-engineering-01` and `demo-finance-01`.
Their expiries are 45 and 60 days after 2026-10-11; review the dates and reasons
before use. These are illustrative selectors, not a claim that either host is
vulnerable. Missing or ambiguous hosts/findings remain pending; no finding is
fabricated and no unrelated finding is accepted. Planning scans every page of
the selected device's findings (a real desktop has tens of thousands) but keeps
only declared matches; a scan beyond 1,000,000 findings fails rather than
resolving from a partial list.

Set `authorization.approvalRequiredPermissions` to include
`advisory_exceptions.manage` to require two-human risk acceptance. The policy is
optional; it never makes a service account a human approver. An approval binds the
requester, exact device and finding, request identity, reason and absolute exception
expiry. A different human needs both scoped exception and approval permissions.
Both people's authority is refreshed and fenced again when the requester creates
the exception; approval consumption and the exception commit in one transaction.
Changed payloads, self-approval, expired approvals and revoked authority are refused.
Approvals report `evidence_state`: once the device's current evaluation no longer
reports the exact finding (resolved, or superseded by newer inventory), the request
reads as unavailable and approving it is refused with `approval_evidence_unavailable`;
it can still be rejected. An expiry that has already passed is refused when the
acceptance is proposed or accepted.

Any approval's requester can withdraw it while it is still pending
(`WithdrawApproval`, with an audited reason); withdrawal records no approver and
the request can never be approved or used afterwards. Once approved, only the
requester can run it: the inbox lists those first as **Ready for you to run**, the
dashboard counts them (`ready_to_run`), and a device page shows its open
revocation request with **Revoke now** for its requester.
An exact retry retains the same request and approval; it does not create a second
exception or bypass fresh authority.
Returned exceptions use the database's microsecond timestamp precision, so the
acceptance receipt, later finding reads and declarative apply agree. Approval
digests still bind the original exception payload, including expiry nanoseconds;
normalizing the displayed/stored expiry never permits a changed request to reuse
approval. Apply compares canonical microseconds exactly, not an expiry tolerance.
Downgrade refuses while retained advisory approval records require the new action;
it does not delete approval audit history.

The console proposes from the selected finding, reviews its package/version,
device, reason and expiry in the approval inbox, and lets the original requester
accept the approved risk. Acceptance is not remediation and never overrides stale
inventory/feed evidence. The finding card labels the recorded timestamp
“Acceptance expiry” independently of finding freshness; unknown evidence does not
mean the exception has expired. The demo's `proposeApproval: true` entries make
`lindmctl apply` create proposals only, returning pending approval references;
another human reviews and the requester accepts in the inbox. Apply never approves
its own proposal. Omitting `proposeApproval` attempts the normal acceptance API,
which still refuses when policy requires approval. Do not put an approval ID into
an engine-resolved exception template.

#### Runtime authorization and browser account import

`GetAuthorization` and `UpdateAuthorization` require fresh unrestricted
`accounts.manage`, including for exact historical replay. CLI PKCE credentials may
use these AdminService operations; they do **not** become browser credentials.
The Accounts import workflow posts the typed organization to
`/auth/organization/apply`, requiring a live browser-kind session, exact Origin and
CSRF token. The server runs the same `internal/orgapply` planner and applier used by
`lindmctl`. Review binds the document, observed CAS heads and named account state;
changed review inputs require a new preview. It applies authorization before
accounts so new custom roles are available. Existing profile, scope, approval and
secret-delivery boundaries remain authoritative.

The import is not atomic. Earlier outcomes and issued secrets remain visible when
a later operation fails. Secrets stay only in component memory, never browser
storage, URLs or query caches. Download or copy them privately before leaving.
Omitting accounts never deletes them. An account entry creates or enables that named
account and replaces its role, device scopes and emergency designation; updating
access revokes its existing sessions. Account creation/reset has no durable secret
replay, so a lost response needs explicit recovery, not a new automatic issuance.
The browser capability is rechecked between mutations. If a runtime replacement
ends the importing session, the import stops with its committed outcomes rather
than continuing through in-process server calls.

`ServerConfig.authorization` is bootstrap-only after the first runtime write.
Persisted runtime policy replaces it completely, including when the saved policy is
empty. There is no merge, fallback-on-error or reset-to-config switch. Restart and
other replicas read the persisted policy; stale configuration cannot overwrite it.
Authentication source, emergency restrictions and built-in grants remain in the
authority fingerprint. Source changes still require valid server configuration
and owner-recovery checks.

Each accepted replacement atomically advances the policy revision and all actor
authorization versions, fences pre-change directory observations, ends non-owner
browser and CLI sessions, and records `identity.authorization_updated` with the
operator reason, old/new revisions, policy digest and revoked-session count.
Unrestricted built-in local owners and the pinned deployment owner retain recovery
sessions; their old worker grants are still invalid. Restoring a policy does not
restore revoked sessions or earlier approvals. Mutations lock policy before
principals and evaluate optional approval requirements from the same immutable,
fresh authorization snapshot fenced at commit. Exact request replay returns its
historical result, not the current policy; a changed payload with that request ID is
rejected, and a stale expected revision requires review.

Directory group bindings are active only under directory-primary authentication.
Local accounts use direct roles and device scopes; static device groups are never
substituted for directory identity groups. The console selects known configured
bindings. New external groups require a source-issued path/reference in Advanced
setup because there is no directory catalog API; no extra provider OAuth scopes or
fabricated group names are introduced. Keycloak uses an exact group path, Entra an
immutable tenant group object ID, and Okta/Google their immutable group references.
The provider-specific reference-entry limitation remains a design-owner decision,
not a claim of searchable upstream catalog coverage.

#### SSH login banner

`SSHServerDesired.banner_text` is public, exact UTF-8 pre-authentication text, not
MOTD, a template, a shell fragment or a secret. The task-shaped **SSH login banner**
profile field and `lindmctl apply -f org.json` use the same typed resource. The
Engineering example declares `bannerText: "Company managed device. Authorized use only.\n"`.
The protobuf bounds it to 8 KiB, disallows terminal control characters except
tab/newline, and rejects empty text. Removing the resource releases its owned
state; an omitted field is not permission to erase an existing banner.

This qualification admits **banner-only** SSH desired state on Ubuntu 24.04 and
Fedora 44, not arbitrary SSH authentication, listener or `Match` policy. Combining
the banner with those controls remains `resource_executor_not_available`.
An already-running OpenSSH service, the globally included
`/etc/ssh/sshd_config.d/*.conf` path, a local Ed25519 host key and a loopback
listener are prerequisites. The provider owns only
`/etc/ssh/sshd_config.d/00-lindm-banner.conf` and `/etc/issue.net`; it does not
install, enable, start or restart SSH, change its authentication policy, or open
a firewall.

Create-only refuses a pre-existing unowned `/etc/issue.net`, including stock
distribution notices, as `ADOPTION_REQUIRED` (detail `existing_banner_file`). Use
the normal explicit adoption approval to retain a regular file's baseline before
replacing it. Symlinks (detail `existing_banner_symlink`, the stock Fedora
notice) and hardlinked managed files are refused as preconditions even with
approval; a native administrator must first prepare an independent regular
file. The reserved drop-in is never silently adopted (detail
`existing_banner_dropin`). An inactive SSH unit (`ssh_service_inactive`) and a
failing `sshd -t` (`ssh_config_invalid`) are named preconditions. Any other
`Banner` directive, including one in a different `Match`
context, is a visible collision; ambiguous includes, unsafe paths and unsupported
file metadata also fail closed. The normal resource claim graph reserves both
native paths against other assignments.

Include search directories must already exist, use canonical non-symlink paths
and have root-owned ancestry without group/other write access. Filename wildcards
are supported; directory wildcards are not. Empty matches still require protected
search directories, so files cannot be planted just for reload. Vendor file
symlinks are followed only through protected original **and** resolved ancestry.
Read-only configuration dependencies may be hardlinked; that exception never
authorizes adoption or mutation of a hardlinked managed file.

Every effect is CAS-bound to observed native bytes, inode generation, root custody
and security metadata. Filesystem identity and birth-time proofs bind the file
and every ancestor across reboots, so neither inode reuse nor replaced protected
parents transfer ownership. Syntax is checked before effects and again before reload.
Effective configuration, a fresh locally host-key-verified SSH banner exchange
and independent post-helper observation must agree with the exact content hash.
That unauthenticated exchange proves the public notice and continued SSH
connectivity, **not** account authentication. Native qualification additionally
uses a fresh authenticated lab login. The reconciler repairs in-place content
drift while refusing replaced files or changed ownership/security attributes.
Release restores the adopted baseline or removes only unchanged files created
by lindm; administrator edits prevent destructive restoration. A failed effect
attempts custody-checked rollback and remains outcome-unknown rather than being
blindly replayed. See [native records](verification.md#ssh-login-banner).

#### Declarative organization controls

- USB-storage blocking uses the typed `managedFile.kernelModuleBlocklist` template,
  never arbitrary content at a forbidden path. The device needs the
  kernel-module blocklist capability (a group or deployment capability policy, or
  the root-local `fileProvider.kernelModuleBlocklist`); the demo's Finance profile
  blocks `usb_storage` and `uas`, and `org.json` grants the capability to the
  Finance group only. Releases whose registry names no qualified initramfs tooling
  report the capability unavailable. The only path
  is `/etc/modprobe.d/99-lindm-blocklist.conf`, root:root 0644.
  Applying rebuilds installed initramfs images, independently reads their embedded
  stanza and observes native modprobe settings and loaded/built-in modules.
  Loaded modules require a restart; built-in modules are not applicable. No driver
  is unloaded automatically, and a restart is never implied by profile publication.
  Known failed reconcile rebuilds remain failed and require reconciliation; lost
  helper outcomes retain the existing ownership-unknown hold. Owned release
  restores the protected baseline and rebuilds boot images, refusing externally
  changed files. Release retains an unknown hold until its boot-image postcondition
  is proven, even if the native updater exits zero without rebuilding.
  See [module qualification and limits](verification.md#typed-kernel-module-blocklist).
- OS-update profiles carry an independent signed `rebootWindow` and bounded
  `employeeDeferral` policy. Restart scheduling never stops an update transaction.
  A deadline without an eligible restart instant is reported rather than bypassing
  the window. Employee deferrals use the authenticated local desktop session,
  retain the original pending-reboot policy/deadline across executor restarts and
  later update policies, and cannot replace a foreign logind schedule. Accepted
  schedules remain separate from unresolved native attempts; reconciliation never
  replays a mutation. Assistance invalidates employee prompts.
  Native qualification and its limits are recorded in `docs/verification.md`.
- Advisory exception two-human approval is the optional `advisory_exceptions.manage`
  approval gate described in the
  [organization specification](#organization-specification); native qualification
  is recorded in [verification](verification.md#l11-distro-advisory-classification).
- SSH banner text has a dispatchable banner-only typed resource, drift repair
  and ownership-safe release; see [SSH login banner](#ssh-login-banner). The managed
  MOTD remains a separate post-login facility.

#### Declarative organization gaps

Every remaining item is either pending or an explicit gate with its closing
condition.

- **Gate: remaining assistance capability qualification.** Screen viewing requires
  `remote_assistance.view`; control additionally requires `remote_assistance.control`
  in the intersection of both grants' device scopes. Clipboard uses its own scoped
  `remote_assistance.clipboard` grant. The helpdesk example is view-only. Files and
  unattended capability APIs, independent grants and native qualification remain
  owned by the assistance roadmap; the mode-permission cutover alone does not close
  that remaining gate.
- **Gate: password policy on stock devices.** The Company baseline password row
  is an approved adoption and rolls out under its rollout's one approval, but
  PASSWORD_POLICY is local-only: a signed capability policy never grants it, and
  `capabilityPolicies` rejects it. Every stock device therefore reports the row
  blocked `capability_password_policy_not_enabled`; the console names
  `password_provider` in `/etc/lindm/executor.json`. The gate closes per device
  when its root sets that field. A remotely grantable password capability would
  need its own design and qualification first. The example keeps the row as this
  explicit gate rather than omitting it. Its sysctl rows use only keys the
  kernel-settings provider does not protect (`kernel.kptr_restrict` and
  `kernel.dmesg_restrict` are protected and stay out).
- **Pending: platform-scoped resource rows.** Dispatch refuses any row carrying
  `applicability` products or features (`resource_capability_evidence_unavailable`)
  until capability evidence is qualified, so the example declares only the arm64
  Engineering packages, without applicability.
- **Lab constraint: Finance keeps `sshd.service`.** The persistent demo manages its
  guests (TPM cold-boot evidence, resume, assistance responses) over guest SSH, so
  the example does not stop and disable `sshd.service`. A real organization can add
  that service row; on a demo device it would sever the lab's management channel.
- **Gate: membership-safe static group rename.** The existing replacement API
  rewrites membership without compare-and-swap. Automatically repairing name drift
  could restore revoked RBAC access, so apply reports it as unsupported. Closing
  this gate requires a rename-only or revision-checked mutation and a concurrent
  membership-change regression test; do not replay a stale membership snapshot.
- **Gate: deleted static-group identity reuse.** Retained creation receipts make
  replay of the original creation distinguishable from creating a new object.
  Apply returns a conflict when that receipt outlives the live group. Use a new
  stable group ID and migrate its references. Reusing the deleted ID remains
  gated on an explicit new-incarnation API and tests that prevent old receipts or
  authorization references from reviving deleted authority.
- **Gate: in-place rollout specification changes.** Rollout specifications are
  immutable; changing one under the same ID would change the meaning of existing
  deployment history. Use a new stable rollout ID and update its assignments.
  In-place changes remain gated on a versioned rollout contract that preserves
  historical specifications and verifies concurrent deployment behavior.
- **Gate: concurrent account edits and uncertain enrollment issuance.** Console
  import is implemented, and runtime authorization has audited CAS and exact
  replay. Account endpoints intentionally retain browser-only, last-writer-wins
  updates and non-replayable issuance. The reviewed import digest detects changes
  before apply, but does not serialize a concurrent authorized account writer
  after that check. Coordinate account edits; after a lost response, refresh
  accounts and reset enrollment deliberately if needed, never automatically retry
  issuance. Closing this residual gate requires per-account revisions and
  secret-free issuance receipts with explicit recovery, not a claim of atomic
  account apply or promotion of CLI credentials to browser authority.

## 3. Dangerous actions

Destructive plans freeze exact device identities/generations, media identities,
method, prerequisites, artifacts, rollback limitations and expiry. Two distinct
humans authorize the digest with fresh step-up. Changes invalidate approvals. Before
execution recheck current authorization, target ownership, device/hardware capability,
maintenance policy, recovery state and online authorization. Unused plan approval
expires after 15 minutes by default; the executor-verifiable one-use start authority
expires within 30 seconds as specified in architecture. No offline destructive start.

Expose distinct operations and results:

- Session lock: authenticated local logind D-Bus `LockSessions`, observed through
  graphical-session `LockedHint`; optional `TerminateSession` is irreversible for
  those sessions. Local recovery and alternate boot may bypass it. It is not boot
  lock or theft protection.
- Local account restriction: explicit usernames or non-system human accounts,
  excluding root and the executor's protected break-glass/admin list. The native
  shadow mechanism locks passwords and expires accounts; it does not delete data
  or claim directory-account control. Configure `allow_account_lock` and
  `protected_accounts` locally, then regenerate/install `action-sandbox` and restart
  the executor. The fixed native tools are `/usr/sbin/usermod` and `/usr/bin/chage`.
  That opt-in grants `/etc` writes because native shadow tools need directory locks,
  backups and atomic renames; file-only binds are insufficient. Native tools run
  against a private staging root and publish only the exact expected shadow row
  under the local shadow writer locks. Root-owned journal-derived stages and
  matched dead-process locks can be reclaimed by an explicit fresh release;
  unrelated lock files are never removed. The protected account ledger retains at
  most 128 historical locks; exhaustion refuses new account restrictions.
- Release lock: separate `actions.release-lock` authority, referencing the original
  lock. Only unchanged, journal-owned account state is restored. Admin changes and
  previously expired accounts are retained, and screens stay locked. A crashed
  action remains unknown rather than being silently repeated. A fresh explicit
  release can restore still-owned unchanged state after interruption, with new
  authority; the previous action keeps its unknown audit outcome.
- Quarantine: the tested network/access policy with an explicit management/recovery
  channel. Validate reachability and automatically restore on a failed checkpoint.
- Retire: cleanup/revocation according to resource ownership, not storage sanitization.
- Sanitize: a qualified firmware/recovery-environment workflow for exact media and
  hardware. Plan multi-disk, RAID, removable storage, swap, headers, escrow, caches,
  snapshots and previously unencrypted areas. Reject an incomplete target scope.

Never overwrite or discard a mounted live root filesystem. LUKS live-root
**crypto erase** is a narrower, separately qualified operation: after the exact
two-human authorization, fresh executor challenge and durable grant consumption,
erase every approved encrypted volume's slots/tokens and complete header/keyslot
area. The active device-mapper mapping remains temporarily usable; it is not
closed while the executor verifies the raw media and sends its signed result.
The executor closes journals before the first header mutation and retains its
signer and terminal evidence in locked memory. No post-erase journal write is
required or treated as proof of durability.

The agent package installs `lindm-live-root-poweroff.service` without enabling or
starting it. Only the verified live-root path arms this fixed, independent helper
before erasure, waiting for its ready notification. Its non-cancelable 120-second
boot-time deadline forces power-off whether or not the report succeeds; stopping
the executor or losing the network does not cancel it. The opt-in executor
drop-in adds locked-memory authority and an unlimited memlock allowance for this
mode. Do not interpret helper readiness as proof that erasure finished.

Full media sanitization instead runs in the signed original-device recovery
environment or an explicitly identified external-operator environment. Secure
Boot trust, boot configuration, power failure, firmware behavior and reinstallation
are physical qualification inputs. Record method, manufacturer/model/firmware,
serials, evidence and anomalies; separately record operational verification and
organizational validation following NIST SP 800-88r2. A missing post-action report
remains `outcome_unknown`, not `verified_sanitized`; disappearance from the fleet
is never sanitization evidence. RAM remanence, previously exported volume keys,
header backups and storage snapshots remain separate residual-recovery risks.

Automated recovery-media handoff has a separate least-privilege protocol. Before
reboot, register a one-action recovery key generated in a qualified TPM or protected
off-target medium, and an expiring recovery credential bound to enrollment generation,
action/plan/media identities and the signed recovery-image digest. It can only fetch
that plan, request its fresh start authorization and submit its checkpoints/evidence;
it cannot act as a general device or admin credential. Boot image authenticity is
necessary but not authorization. Establish protected proof of the handoff key,
revalidate actual storage/controller identity and eligibility after boot, and obtain
a new executor-verifiable online start challenge before erasure begins.

The recovery environment writes authoritative execution checkpoints to protected
off-target storage and the server before destructive transitions. Credentials, journal
and sole evidence copy cannot reside only on media being erased. On restart, reconcile
with both stores and the device's reported sanitize status; never blindly restart an
ambiguous sanitize operation. A firmware operation may continue after network loss;
keep the outcome unknown until evidence arrives, rather than retrying it. If a target
has no qualified off-target durable state/identity path, automated wipe is unsupported
and the separately attributable external-operator method is required. Physical gates
exercise compromised/replayed handoff, wrong media, power loss, expired authority,
recovery-image changes and return to a clean installed state.

If original-device recovery reports **unsupported: ESP capacity**, retain the
signed-image digest and the displayed allocation-rounded needed/available bytes;
do not submit a wipe approval or change the ordinary boot image to make it fit.
The external-recovery-media alternative requires an on-site operator and a
separately qualified, trust-verified recovery image booted from external media.
Provide protected off-target identity and journal storage, observe the exact
approved whole-disk/controller identity again in that environment, and obtain a
new image-and-target-bound two-person approval and fresh execution grant before
any destructive command. An approval for the rejected original-device image is
not transferable to a different image or media scope. Retain independent
post-action verification and the server's scoped result; absent a qualified
external path, report unsupported rather than improvising an erase. This path
cannot satisfy remote wipe for a lost or stolen device.

Deleting escrow now does not remove historical key copies from immutable backups.
A crypto-erase claim requires a demonstrated key hierarchy and retention design that
renders every recovery path unusable; otherwise choose qualified media sanitization
or destruction. Legal hold blocks conflicting destruction and is visible at approval.
Physical test evidence cannot establish behavior for untested SSD firmware/models.

## 4. Connected and air-gapped deployment

Single host: signed OCI server image, PostgreSQL, durable local artifact volume,
configured TLS and explicit secrets, health/readiness checks, resource limits and
systemd-managed Compose deployment. The IdP may be external or a local OIDC service.
No Redis, public object store or Internet call is necessary for normal operation.
Provide a native server package/service installation for operators who do not run
containers, using the same binary/config/migration contract. Root is required for
installation, not routine server execution.

Replicated topology: L4/TLS-aware load balancer, at least two API instances, separately
scalable workers from the same binary, supported PostgreSQL HA and shared S3-compatible
storage. No in-memory session/job ownership or local artifact assumptions. Kubernetes
packaging may use this topology, but is not the definition of scalability. A single
physical host is an availability single point of failure; never market it as HA.
The implemented and laboratory-qualified subset (replicas, balancer, synchronous
PostgreSQL standby and single-leader jobs) is specified in "Replicated topology
and HA operation" below; shared artifacts and worker-only processes remain open.

Configuration is typed, validated and documented. Secrets may come from protected
files or approved secret managers, not command-line flags. Startup refuses ambiguous
listener trust, default credentials, unsupported schemas and unsafe production TLS.
Readiness covers DB/migration/key/artifact availability; liveness does not depend on
a remote IdP being online. Metrics/admin diagnostics are private and authenticated.

### Remote assistance relay

Graphical assistance is optional. It is enabled by `ServerConfig.assistance`, and
without that section the server refuses requests with `assistance_unconfigured`.
`lindmd` embeds the relay-only TURN service; it has no public STUN/TURN dependency.

Live viewing requires `remote_assistance.view`. Requesting or continuing control
requires both `.view` and `.control` on the same device; the scopes of separate
grants are intersected, never combined into wider access. Configure helpdesk with
`.view` alone when support must remain view-only. No clipboard, keyboard, file or
unattended grant implies either base permission. Custom roles and emergency
allowlists must explicitly select the new permissions; no legacy permission alias
is accepted. Existing immutable audit rows are not rewritten.

Creator checks, fresh authorization, per-session consent and native capability
negotiation still apply. Losing a control grant ends its control session rather
than silently reusing it as view-only. An operator with view authority in scope can
always request Stop for either mode, without requiring an extra control grant.

- `relay.listener`: the TURN UDP and TCP listener (for example port 3478). It
  must not overlap the admin, device or profiling listener.
- `relay.relay_address`, `relay_port_min` and `relay_port_max`: the specific IPv4
  address and UDP port range that relay allocations bind and advertise. Peers may
  send only to allocations on this address, so the relay is not an open proxy.
- `relay.urls`: the exact `turn:` URIs given to devices and consoles. Both must
  reach the listener, and both peers must reach the relay address through it.
- `max_concurrent_sessions`: the admission budget, default 16 and at most 256.
  Each credential may hold at most 8 allocations, and the relay as a whole at most
  `2 × 8 × max_concurrent_sessions`.

Firewalls must admit the listener ports and the relay UDP range from managed
desktops and operator browsers only. Media is DTLS-SRTP end to end; the relay sees
ciphertext and fingerprints, not screen content.

Credentials are TURN REST HMACs under a per-process random secret, valid until the
session's `ends_at`. They are never stored. A restart invalidates them and ends
live sessions, which recover only by a new invitation.

There is no per-session bandwidth cap. The encoder targets about 2.5 Mbit/s of
VP8 at 15 frames per second; size the relay range and uplink for
`max_concurrent_sessions` concurrent streams.

TURN-over-TLS, RFC 6062 TCP allocations and cross-replica credential
verification are not implemented. The replicated topology therefore cannot offer
assistance until a shared or external relay contract exists.

Managed devices also need `AgentConfig.remote_assistance.enabled`. The packaged
executor configuration leaves it disabled.

Interactive capabilities additionally require explicit server/executor policy
ceilings, per-device policy and requested/local grants. Unspecified and off deny.
The owner/admin defaults for `remote_assistance.clipboard`, `.keyboard`, `.display`,
`.message` and `.policy.manage` do not bypass the employee's consent or portal.
Other roles need scoped grants; metadata access is not live-screen or clipboard
authority. Policy and operator authority are rechecked during the session, with
bounded directives that cannot extend an expired identity observation.

Clipboard text and operator messages use bounded authenticated RPC state exchange,
not the encrypted media track. TLS/mTLS protects each hop, but the control-plane
process necessarily sees those command bodies in short-lived memory; do not
describe this path as end-to-end encrypted against the server. SQL retains
operation identity/outcome, not bodies, and ordinary audit/logs exclude bodies
and low-entropy clipboard-content hashes. Ephemeral-state loss produces an
explicit unavailable/unknown result, never a replay of the side effect.
Ordinary live input remains on the authenticated peer data channel; named
special-key actions have their own content-free audit. On the device, a
message appears inside the in-progress notice, which keeps its Stop action.
GNOME shows no other banner while that critical notice is on screen. The
message carries the authenticated operator name and the "Message from your
support operator" label. Only after the employee dismisses the notice (until
it is reposted) is a message its own 30-second notification.
GNOME shows one banner at a time. It kept an idle seat's "Remote assistance
ended" banner on screen, and a new request, even a critical one, queued behind
it unseen until the request expired. So every new request first withdraws the
previous "ended" notice, and a request's own banner is withdrawn when it is
answered, expires or is cancelled. The `rerequest` lab scenario asks again
right after a session ends and fails unless the new request is on screen
within 15 s.
The same rule holds during a session: the critical in-progress notice stays the
shown banner until the employee acts on it, so a separate in-session notice
(the incoming-file consent, elevation guidance, the pointer controls, the sound
controls) would wait behind it unseen. Each such notice therefore takes the
indicator's place. While one is posted, the indicator is withdrawn, and the
notice carries the indicator's disclosure (who is viewing or controlling, and
recording) plus the indicator's Stop as its last action, at most three actions
in all. When the notice is answered, dismissed, withdrawn or fails to post, the
indicator is posted again at once; Stop on the notice ends the session
`USER_STOPPED` like the indicator's Stop, and nothing is reposted for an ended
session. A second in-session notice waits behind the first. The file-received
note is shown inside the indicator, like a message.

The [capability contract](product-specification.md#remote-assistance-capabilities)
defines the separate file, reconnect, recording and unattended boundaries. File
approval/selection must pause all remote injection before a local user acts.
The fail-closed property for outgoing files is that nothing leaves without an
explicit local selection. Cancelling the chooser and closing it (Escape, which
GNOME 46's portal reports as response 2) both carry no URI, so each ends only
that request (`file_dialog_dismissed` / `file_dialog_closed`), resumes input and
keeps the session. A refusal that still names files, an unknown response or a
malformed reply ends assistance.
Unattended policy is never an unlock, login-screen or consent bypass.

#### Reconnect and recording operations

Reconnect and recording are off unless the deployment ceiling, the device policy
and the request all enable them with explicit limits. Grant
`remote_assistance.reconnect` and `remote_assistance.record` only to operators who
may resume or record support. Reconnect remembers workflow metadata for at most
the configured window (60 s to 4 h) and attempt count (1 to 8); each new login
still needs the employee's consent, and a remembered workflow is never unattended
access. Lowering the device policy ends waiting workflows.

Recording requires `assistance.recording` in the server configuration:
`key_file` holds exactly 32 CSPRNG bytes (for example
`umask 077; head -c 32 /dev/urandom > recording.key`), owned by root or the server identity,
mode `0600`, distinct from the escrow and every other key, and identical on all
replicas. `max_storage_bytes` bounds all retained ciphertext; when it is full,
optional recording stops and required recording ends its session. The server can
decrypt a recording only through an authorized retrieval and keeps plaintext only
in request memory. Back up the key separately from the database: losing it loses
every retained recording, and replacing it makes earlier recordings and sessions
still recording unavailable (required sessions end `RECORDING_FAILED`). There is
no re-encryption or key rotation of retained recordings.

Policy `recording_limits` bounds each recording's size (1 MiB to 1 GiB) and
retention (1 to 365 days); the `assistance-maintenance` job deletes expired
archives and their keys and records `assistance.recording.retention`. Retrieval
(`remote_assistance.recordings.read`) and deletion
(`remote_assistance.recordings.delete`) are separate scoped grants that never allow
live assistance; auditors see metadata and audit only unless granted retrieval.
Every retrieval is audited with the operator's reason and expires after ten
minutes; playback holds the decrypted WebM only in the reviewer's browser memory.
Recording is disclosed to the employee before capture and continuously during it,
including the organization's later archive access. Ordinary audit and logs never
contain recording content, keys or ciphertext.

#### Unattended, password guidance, pointer and sound operations

These Tier 3 capabilities are off unless the server and executor ceilings, the
device policy and the request all enable them; they are supported only where the
platform registry marks them (GNOME Wayland on Ubuntu 24.04 LTS and Fedora 44) and
remain unqualified until their native scenarios pass.

Unattended access needs three independent facts: the employee's local opt-in
("Allow and enable unattended" in an attended session, which also asks GNOME to
remember the screen-sharing grant), an access period approved by a second person,
and the device policy (`unattended_limits` bound the approval length, opt-in days
and connection length; ON additionally requires a weekly schedule). Grant
`remote_assistance.unattended` to operators who may request and use periods and
`remote_assistance.unattended.approve` (with `approvals.manage`) to different
people who may approve them; the requester can never approve. The device keeps
the portal restore token only in the employee's
`$XDG_STATE_HOME/lindm/assistance-unattended.json` (mode 0600); the server never
receives it. Each connection shows a critical banner naming the operator and
approver with Stop and "Stop and turn off unattended"; a locked or signed-out
seat, another user, an expired period, a missing opt-in or a portal dialog in place
of a silent restore refuses. Revoking the period or the opt-in, lowering the
policy, or the operator losing scope ends a live connection. Revoking an opt-in on
the server does not delete the device file; the next connection is refused by the
server, and the file expires or is removed when the employee turns access off.
Audit actions: `assistance.unattended.request`, `.approve`, `.reject`,
`.authorize`, `.enroll`, `.start`, `.stop`, `.revoke`.

Password guidance (`remote_assistance.elevation_guidance`) is an audited request
that pauses every remote pointer, key, shortcut, clipboard and file path; the
employee can also choose "Pause for password" locally. Only the employee's local
"Resume remote control" resumes input. lindm never detects, answers or relaxes a
polkit prompt and never receives credentials. Audit: `assistance.elevation.request`,
`.pause`, `.resume`.

The pointer overlay (`remote_assistance.annotate`) is the packaged GNOME Shell
extension `lindm-overlay@lindm.dev` in `/usr/share/gnome-shell/extensions`; it
draws only and takes no input. GNOME Shell discovers it at the employee's next
login after installation; the session helper enables it through GNOME Shell only
for a session that uses the pointer and disables it afterwards. Without it, or
when its bus name is not owned by GNOME Shell itself, the capability is refused.
The extension draws only for the one session-bus connection that claimed it and
whose bus-daemon credentials show the shell's own Unix user and the packaged
`/usr/libexec/lindm/lindm-agent` process; every other sender is refused. This
is not a boundary against the employee's own account running the packaged
helper binary, which is already the session helper; the live bus connection
pins the checked process.
Audit: `assistance.annotation.enable`, `.disable`, `.clear`.

Sound (`remote_assistance.audio`) uses PipeWire `pw-dump` and GStreamer Opus on the
existing encrypted peer connection. The employee chooses the output, and under ON
separately the microphone; Mute and Stop are local. Audit:
`assistance.audio.consent`, `.mute`, `.source`, `.stop`. Recordings never contain
sound, and audit never contains audio, marks, guidance text beyond its length, or
restore tokens.

#### KDE Plasma and X11 desktop gates

GNOME and COSMIC on Wayland need no desktop setting. Sessions on KDE Plasma
(Wayland) and on **any** X11 session are refused before the employee's prompt
unless the server ceiling, the executor ceiling and the device policy enable
`kde_plasma` or `x11`. These gates are device policy only: an operator request
never chooses or widens a desktop, and no new permission exists. Existing
capability permissions apply unchanged, and `.policy.manage` changes the gates.

- **Limited** admits VIEW with only the displays, messages, reconnect and recording
  capabilities that desktop qualified; CONTROL ends `UNAVAILABLE`
  (`kde_plasma_control_not_permitted` / `x11_control_not_permitted`), never a view.
- **On** also admits CONTROL, keyboard, clipboard and files, still only as
  qualified for that desktop.
- The session helper's qualification table (built into the agent) withholds every
  unqualified capability with `desktop_capability_unqualified`. An X11 desktop
  without a qualified row ends `x11_desktop_unqualified`. Portal and lock gaps keep
  their own details (`portal_screencast_unavailable`,
  `session_lock_state_unreported`) and are reported first.

X11 never falls back to Xlib, XTest or xclip: it uses the same desktop portal
session, consent prompt and persistent local stop as Wayland. The X11 protocol
does not isolate one client's input or pixels from another client of the same
display; enabling `x11` accepts that the consenting user's own X clients share
that display. GNOME on Xorg shows no screen-sharing icon in its top bar, so the
persistent notification with **Stop** is the only local sharing indicator there.
On KDE the RemoteDesktop dialog approves sharing of every monitor together with
input, so the employee's prompt says so. The consent audit records the admitting
`desktop_profile` and portal interface versions; see the
[desktop qualification records](verification.md#tier-3-kde-plasma-and-x11-desktop-qualification)
for which desktops and capabilities have native evidence.

#### Retired permission names on upgrade

Upgrading needs no administrative transition. Releases before `c793dfef` granted
viewing and controlling a device together as `remote_assistance.run`; the current
server replaces it with **both** `remote_assistance.view` and
`remote_assistance.control` in the same position of the same list, which grants
exactly what it granted. No capability permission (clipboard, keyboard, display,
message, files) is added and no scope changes; reducing a role to view-only
remains a deliberate policy edit. The role and emergency-allowlist bounds are 25
entries so that a full 24-entry list of the previous release still fits.

- **Persisted runtime policy.** When the server starts on a persisted policy
  naming a retired permission, it rewrites the custom roles and approval gates
  under the policy row lock before validating the policy, stores the result as
  the next revision, and records one `identity.authorization_upgraded` audit
  event without an actor. Its details name the previous and new revisions and
  policy digests, the rename applied and each rewritten list. Group bindings and
  account role assignments name roles, not permissions, and are unchanged. Every
  principal re-resolves its authority under the new digest; sessions are not
  revoked because no grant changed. A later start finds nothing to rewrite.
  Historical request receipts and audit events keep the names they recorded.
- **Configuration file.** Bootstrap `authorization` roles and approval gates and
  the `break_glass` allowlist get the same replacement at load, with a warning
  naming the lists. Update the file to the current names to silence it.
- **New input.** `UpdateAuthorization`, the console and declarative organization
  apply reject retired names. `orgapply` names the replacement in its error
  rather than rewriting the operator's source document.

These transitions predate the first turnkey release. The installer refuses
pre-turnkey manual and lab deployments rather than adopting them.
Historical fixtures in `internal/identity/testdata/upgrade/` cover these states
through `TestUpgradeFromEarlierReleaseState`.
Managed releases that change persisted authorization names must declare a
contract migration. Never restore older authorization data for package rollback.

### Fresh-host deployment laboratory

`lab deploy` is the maintained single-host lifecycle proof for Ubuntu 24.04 and
entitled RHEL 9 on fresh local x86 KVM guests. It reserves the original server,
console-enrolled device and fresh restore server together through the ordinary
four-slot FIFO; nested operations do not acquire a second reservation. Signed
release N must be a managed turnkey installation and N+1 must be strictly newer.
This does not adopt or upgrade an unmanaged historical installation.

Supply independently pinned release attestation and TUF public inputs, protected
age backup recipient/encrypted identity, a numeric anonymous-pipe identity
passphrase descriptor, matching consolidated operator binaries and an explicit
new private evidence directory. RHEL uses an available protected entitlement token
path, never a token argument or printed token. No release artifact is publicly
hosted and TLS browser trust is limited to the owned laboratory CA.

Before reading or generating fixture passphrases, the admitted lab process raises
only its own memory-lock allowance through authorized `sudo prlimit`, disables
core dumps and locks current and future memory. A failed gate stops the lane;
it never writes plaintext recovery passphrases to host swap or evidence.

The lane runs actual generated first-run password/passkey setup, root-protected
SSH recovery export transfer and scoped owner custody confirmation. Separate
source and fresh database passphrases are encrypted directly from memory to the
explicit lab operator recipient in private off-host evidence; these fixture
custodians are not independent humans. After encrypted backup, signed upgrade,
fencing and independently authorized higher-epoch recovery, the fresh database
CA custody survives separately from canonical source authority. A new owner
step-up acknowledges every current required ciphertext using the composite
confirmation digest. This is an owner attestation, not machine verification of
off-host storage. The original enrolled guest must then complete a fresh live
inventory/manage action through the restored console.

After installation, upgrade, fresh target provisioning and restore, the lane
asserts both persistent database URL files are regular, singly linked,
root:root mode 0600 and unreadable by either service account. It checks the native
units' distinct `LoadCredential=` sources while the actual server is active.
These filesystem/credential gates enter the private nonsecret workflow record;
database passwords never enter browser configuration or published evidence.

For a release producer's single-bundle install/first-owner timing, use the separate
`lab deploy setup` subcommand. It reserves one fresh native guest, uses the same
signed install, owned PostgreSQL, root-only database credential and CA-trusted
password/passkey browser gates, and requires only independently pinned public
release/TUF trust, a backup public recipient and explicit lab-only custody escrow
public recipient. Its encrypted quickstart export and passphrase escrow remain
private off-host lab evidence, not release, server-backup or support inputs.
It does not attest custody or enroll, back up, upgrade, restore or manage a device.
Even a successful result is scoped `first-run-install-only` with
`lifecycle_qualified: false`; it cannot substitute for the full deployment proof.
The default three-guest workflow and all four root-credential assertions above
remain unchanged.

For native air-gap **server installation**, add `-airgap` to `lab deploy setup`.
The fresh server guest has external QEMU networking denied, and the real installer
must consume the bundle's authenticated host-platform offline add-on. It receives
no online RHEL entitlement token. An absent or invalid add-on fails rather than
falling back to vendor repositories. The record identifies `airgap_server_install`
and retains the first-run-only scope; this does not qualify an air-gap device
enrollment or backup/upgrade/restore lifecycle.

Use `lab deploy audit` with an immutable pre-feature signed release lacking
`install.sh` to measure the historical native runbook separately. Its recorded
terminal invocations and visible decisions are observed counts, not estimates
from seven high-level headings. Raw failed records remain failures; use new
record/evidence paths for corrected fresh-host attempts. Exact invocation and
input contracts are in [engineering](engineering.md); qualification boundaries
and observed friction are in [verification](verification.md).

### Native single-host installation

The turnkey path is the customer's private signed release bundle on Ubuntu 24.04
or RHEL 9 x86-64. After independently authenticating the bundle and release
signer's SPKI SHA-256 through the release custodian, run `sudo ./install.sh`.
The wrapper prompts for the independently supplied public-key file and pin,
public console HTTPS origin, and offline backup custodian's age public-recipient
file when flags are absent. A bundled public key is never its own authority.
Host-maintained OpenSSL checks the signed installer asset inventory before any
bundled executable runs; the Go verifier then checks full release DSSE,
attestations, canonical bundled agent-repository provenance and exact package
digests. Native RPM verification imports exactly one signed-fingerprint-approved
public key into a disposable private database, never the host trust database.
Only that same immutable, independently verified server RPM is installed without
repeating its signature lookup; vendor dependency signature checks remain enabled.
The wrapper snapshots bytes into root-only custody before these operations.

Connected installation is the default. It installs PostgreSQL, OpenSSL and native
prerequisites from the host's configured distribution repositories with package
signature verification enabled. HTTPS repositories retain certificate and host
verification. RHEL needs its normal Red Hat entitlement or an entitled repository.
No external identity provider is needed.

For `--airgap`, obtain the authenticated offline add-on for the host's platform.
The installer imports only that retained vendor-authenticated dependency closure;
it refuses a missing platform snapshot and digest before generating custody or
changing services. It never falls back to a network repository. Both modes retain
the exact signed agent repository inside `lindmd`. Release DSSE does not replace
vendor or agent package signatures.

The installer creates a private native PostgreSQL cluster, distinct restricted
database-owner migrator and non-owner runtime roles, SCRAM credentials and
verify-full database TLS. Ubuntu uses `/var/lib/postgresql/lindm` and loopback port
15432; RHEL uses `/var/lib/pgsql/lindm`, standard SELinux labels and loopback port 5432. It never adopts an existing cluster or disables SELinux. A collision fails
closed. Defaults are 64 database connections, 256 MiB shared buffers, 16 device
pool connections plus the separate console pool, bounded statements and cgroup-v2
swap/core-dump protection. Runtime credentials cannot create schemas or mutate
Goose, schema-compatibility or server-recovery metadata.
The local database CA uses ECDSA P-256/SHA-256 signatures so PostgreSQL
SCRAM-PLUS can bind authentication to the server certificate. Device and console
authorities remain separate. TLS verification and channel binding are not disabled
to accommodate a certificate algorithm. The database CA private key is sealed
directly to the PKI custodian, never saved as plaintext.
Generated runtime and migrator URLs set `channel_binding=require` and
`require_auth=scram-sha-256`. With the pinned pgx driver these together require
SCRAM-SHA-256-PLUS; plain SCRAM, trust and other authentication methods cannot
satisfy the local policy. An omitted or empty `channel_binding` also defaults to
`require` for external URLs. `channel_binding=disable` is refused.
An external pooler that cannot support PLUS, such as PgBouncer, requires an
explicit `channel_binding=prefer` choice. This retains verified TLS but permits
unbound SCRAM. Startup logs one redacted downgrade warning, and **Server status**
keeps the database check at **Needs attention** while the connection is healthy.
A connection failure still reports **Failed**. Prefer a PLUS-capable connection;
do not use the pooler exception to work around a broken certificate.
On Ubuntu, the installer preseeds `create_main_cluster = false` before the vendor
PostgreSQL transaction and temporarily denies native service starts through
`policy-rc.d`. It removes only its own unchanged temporary policy. Existing operator
configuration is never overwritten: an existing cluster switch must already be
disabled (`off`, `false`, `no` or `0`, case-insensitive); an existing foreign service policy is refused rather than executed,
replaced or assumed to deny every maintainer-script invocation. Vendor
configuration preservation remains enabled; no default `16-main` cluster is
created or started as a side effect.
Pre-transaction validation reads the protected policy without `pg_conftool`,
so an operator-created disabled policy works before `postgresql-common` is
installed. A standalone, unique `create_main_cluster` assignment is required.
Includes, duplicate creation switches and unsupported syntax fail closed rather
than guessing an effective value. The file is not changed. The authenticated
dependency transaction supplies PostgreSQL's native tools after start fencing.

Server/device trust and deployment identity are generated automatically with
maintained Go X.509 and existing signed execution-authority libraries. Execution
quorum and generated transport/database CA private keys exist only in locked,
non-dumpable process memory before encryption; no plaintext copy is written to
disk. `/etc/lindm/offline` contains exactly the three individual execution-root
`.age` artifacts and `sealed-pki-ca.age`, root:root 0600 under root-only ancestry.
Online plan/start keys and the device issuer have separate identities.

Supply up to three **distinct** age X25519 public-recipient files using repeated
`--execution-root-recipient-file /ABSOLUTE/FILE`. None may equal the backup
recipient. Each execution root is sealed to its assigned recipient; generated CA
keys are sealed to the first PKI custodian. Missing recipients are generated in
memory. When any identity is generated, the installer asks for a strong unique
20–1024-byte passphrase twice on the private terminal and writes one encrypted
export to `/var/lib/lindmd-operations/recovery-custody.age`. Automation may supply
the two newline-terminated values through `--custody-passphrase-fd FD`, an
owner-protected anonymous pipe, never a regular file, argument or environment
variable. Private age identities and the passphrase are never persisted in
plaintext. The export is root:lindmd 0640 solely to permit ciphertext-bound status
checks; it has no browser download route. It contains the generated identities,
public deployment/origin/root bindings and already encrypted custody artifacts.
Its strict public digest-bound metadata is at
`/var/lib/lindmd-operations/recovery-custody.json`.

One passphrase-protected export **does not** create three independent human
custodians. Transfer it through authenticated root SSH or private external media,
authenticate its SHA-256 through the protected operator channel, and keep the
passphrase separately off-host. For root-mounted, root-only approved external
media, copy the ciphertext with `sudo install -o root -g root -m 0600 --
/var/lib/lindmd-operations/recovery-custody.age "$PROTECTED_EXTERNAL_DIRECTORY/recovery-custody.age"`.
The destination is supplied by the operator, not a browser or public host.
The console retains the custody-transfer task until the owner confirms the current
deployment and ciphertext digest with fresh user verification; this attestation
does not prove storage or deletion. With three supplied custodians, transfer the
individual ciphertexts and retain their private identities off-host instead.

Encrypted backups contain only these inner custody ciphertexts, not plaintext
root/CA keys or generated identities. **The backup decryption key alone cannot
decrypt inner custody ciphertexts**; an operator who also holds the custody
passphrase/identity may have root authority. After host loss, retain both the
encrypted server backup and independently protected custody export/identities;
fenced restore still requires recovery reconciliation and offline quorum approval.
The signed initial delegation is admitted only in the first owner's successful
password plus user-verifying WebAuthn transaction, never merely at daemon startup.
No private release-signing or backup-decryption key enters the bundle or server.

Runtime files are under `/etc/lindm`, with separate `/etc/lindm/migrate` credentials.
Root stages only validated database resources to issue the protected setup code
using the migrator database login. The final code is
`/var/lib/lindmd-operations/setup/code`, root:root 0600 under root-only ancestry,
and is shown only on the private terminal. `--setup-code-file /ABSOLUTE/NEW_FILE`
provides a create-only root:root 0600 destination for automation, never secret
stdout, argv, environment, journal or support output. The installer enables the
native server and encrypted-backup timer, checks actual verified HTTPS readiness,
and prints one console origin and the setup code. Runtime state is separate at
`/var/lib/lindmd`; root operational metadata is at `/var/lib/lindmd-operations`.

The automatically generated private console CA is not silently trusted by a
remote browser. Transfer its displayed CA-file SHA-256 and certificate through
the authenticated operator channel and use the approved workstation trust
process; never bypass a certificate warning or disable HTTPS verification.
Bring-own TLS is explicit: `--tls-cert-file`, `--tls-key-file`, and `--tls-ca-file`
provide a protected key, chain covering both console/device names and independently
approved roots. The listeners remain unprivileged (18444/18445 by default);
`--admin-port`, `--device-port` and `--device-origin` are explicit overrides.
An origin without an explicit port uses console port 18444; an explicit public
proxy port is preserved. Console and device listener ports must remain distinct.

For explicit ACME, use the maintained distro Certbot client on the certificate
custodian, with its dependencies carried in the custodian's authenticated private
OS closure. A connected HTTP-01 issuance is:

```sh
certbot certonly --standalone --preferred-challenges http \
  --server "$ACME_DIRECTORY" --non-interactive --agree-tos \
  --email "$ACME_EMAIL" --domain "$ADMIN_DNS" --domain "$DEVICE_DNS"
```

The custodian supplies those actual directory/account/DNS values and authorizes
the terms; both names must resolve to its temporary port-80 challenge listener.
Copy the resulting full chain and private key into root-owned non-symlink 0600
files under root-only ancestry, and separately authenticate the issuer root file.
Pass those files through the three bring-own TLS flags above. Never use Certbot's
`live/` symlinks directly as installer inputs or download a replacement trust root
from the unverified server. Renewal must preserve both names and the bootstrap's
admitted root trust; validate `lindmd check-config` as the runtime identity before
an explicit restart. The installer does not silently contact an ACME service.
An isolated site uses its local PKI or an explicitly reachable internal ACME
custodian; public ACME is not an air-gap fallback.

External database mode uses `--database-url-file` plus `--migration-url-file`;
`--database-url` is a **file-path alias**, never a password-bearing URL argument.
Both inputs must be absolute protected root-owned regular files. For local and
external databases, the persistent runtime and migration URL files are
`/etc/lindm/database-url` and `/etc/lindm/migrate/database-url`, root:root mode 0600.
Neither service account can read these files at rest. Native units use
`LoadCredential=database-url:PATH`; `lindmd` reads the ephemeral credential from
`$CREDENTIALS_DIRECTORY` only when its explicit credential option is present.
Missing or unsafe credentials stop the command; there is no persistent-file
fallback. The normalized configuration retains the original URL-file reference.
Systemd may keep ephemeral credentials root-owned and grant only the service UID
access through a named POSIX ACL. The resulting stat masks are `0550` for the
directory and `0440` for a file, although the owning group has no access.
The credential reader admits only the exact canonical root/service-UID ACL:
no owning-group or other access, no additional readers, and no write grant.
Ordinary group-readable modes are refused. This exception applies only to
`$CREDENTIALS_DIRECTORY`; persistent secrets remain root:root mode `0600`, and
restore preserves that ownership.
The installer copies referenced database CA/client-certificate/key material into
the appropriate service identity's custody and retains strict `sslmode=verify-full`.
The migrator must own the intended database and public schema without superuser,
CREATEDB, CREATEROLE or replication authority. Provision equivalent runtime
CONNECT/USAGE/DML and migrator default grants before using an external database;
the installer audits role separation and denies runtime schema ownership/CREATE.

Native installation also creates `/etc/lindm/integrations.key`: exactly 32 raw
CSPRNG bytes, root:root mode 0600, with no service-account access at rest.
The runtime configuration references it through `integrations.encryptionKeyFile`.
The runtime unit supplies `LoadCredential=integrations-key:/etc/lindm/integrations.key`
and the explicit `-integrations-key-credential integrations-key` option.
The transient runtime check uses the same credential. Migration does not receive
this application key. An absent or unsafe selected credential stops the command;
it never falls back to the persistent file.

A managed upgrade creates this key when integrations have no configured key.
It preserves an existing configured key, including its encrypted destination
credentials. A missing or invalid configured key stops the upgrade; generating
replacement bytes would destroy access to existing secrets.

Release custodians enable the complete installer export with `lab release build`
`-tuf-root-file` and independently supplied `-tuf-root-sha256`. The public TUF root
is the actual custodian-signed update root, never an installer-generated substitute.
The default connected export requires no vendor snapshots. To add Ubuntu air-gap
support, supply `-serverdeps-cache` and `-ubuntu-serverdeps`; for RHEL, supply
`-rhel-serverdeps` with that explicit cache. Either or both add-ons may be selected.
Every supplied closure must bind platform, solver/base inventory, native vendor
authentication and offline replay evidence. RHEL offline redistribution requires
appropriate private customer entitlement and custody; lab development custody is
not production legal authorization. A requested but absent or unauthenticated
add-on fails export. Installer executables are compared across two isolated
captured-source builds. All required bootstrap assets and each optional snapshot
pair are signed and bound to the full `release.json`.

The low-level native package contract below remains useful for independently
managed deployments; it is not the turnkey installation procedure.

The `lindmd` release DEB/RPM contains the embedded-console executable at
`/usr/bin/lindmd`, the signed agent-repository payload at
`/usr/share/lindmd/agent-repository`, `lindmd.service`, and a separate,
operator-invoked `lindmd-migrate.service`.
Installation creates dedicated `lindmd` and `lindmd-migrate` accounts. It does **not**
create credentials, claim an owner, migrate, enable or start the server. Both units
have an empty capability set and `ProtectSystem=strict`; binding ports below 1024
is intentionally unsupported by these units. Use TLS listeners on 18444/18445 and
an explicitly managed layer-4 forwarding arrangement if port 443 is required.
The native and OCI deployments require cgroup v2 and disable swap for the server
(`MemorySwapMax=0`, or container memory+swap equal to its memory limit) and core
dumps (`LimitCORE=0`, or a zero core ulimit). Before loading configuration/secrets,
`lindmd` also sets Linux process dumpability to zero, which blocks piped host core
collectors that ignore resource limits. This protects short-lived plaintext
recovery-secret buffers; it is not protection from a compromised host.

Use the authenticated `lab release build` server artifact, which carries the
matching signed agent repository. Lower-level `lab packages build-server` callers
must supply that verified bundle explicitly; an executable-only developer build
is not a complete stock installation. Authenticate DEBs through the signed APT
repository with a separately obtained pinned `Signed-By` key;
`dpkg -i` is not signature verification.
RPM installations require the pinned release key and `gpgcheck=1`. Development
signers generated by the lab are never production release keys.

1. Install a supported PostgreSQL release; enable TLS with a certificate matching
   the database hostname and restrict `pg_hba.conf` to `hostssl` SCRAM or explicitly
   configured client certificates. Create distinct non-superuser login roles:
   `lindm_migrator` owns the database/schema, and `lindm_runtime` has only CONNECT,
   schema USAGE, table SELECT/INSERT/UPDATE/DELETE and sequence USAGE/SELECT.
   Revoke PUBLIC database/schema privileges. Set equivalent default privileges
   **for the migrator role**, so subsequently created tables are usable.
2. Install `/etc/lindm/server.json` using the protobuf `ServerConfig` schema.
   Set a unique deployment UUID, exact public HTTPS origin, distinct admin/device
   listeners, `authentication: {"local": {}}`, TLS certificate/key, device CA
   certificate/key and database URL-file references. Use the organization's PKI;
   the laboratory's short-lived certificates are not an installation PKI.
   Keep public origin/deployment identity stable across upgrades and restores.
3. Make runtime configuration and TLS/execution key files `lindmd:lindmd` mode 0600 under
   root-owned non-writable directory ancestry. `/etc/lindm` may be root-owned 0755;
   secrets themselves must have no group/other permission bits. The checked loader
   rejects unsafe ownership and file permissions. Store the explicit PostgreSQL
   URL in `/etc/lindm/database-url`, **root:root mode 0600**, including
   `sslmode=verify-full` and `sslrootcert=/etc/lindm/transport-ca.crt`.
   Do not set `PG*` environment variables. Native runtime credentials include the
   database URL and the root-owned integrations key; neither becomes service-owned.
   Retain the installer-generated 32-byte `/etc/lindm/integrations.key` as
   **root:root mode 0600** and set `integrations.encryptionKeyFile` to that path.
   A supervised fresh manual fixture must supply its own protected CSPRNG key.
   Never generate a new key for an existing encrypted integration database.
4. Put a separately validated config at `/etc/lindm/migrate/server.json`, with
   `database.migration_url_file` pointing at `/etc/lindm/migrate/database-url`.
   Own the config and database TLS trust/client material by `lindmd-migrate`
   at mode 0600; keep the directory traversable only by root and that account.
   Own the migration URL file by **root:root mode 0600**, not the migrator account.
   The migration unit receives only this URL through `LoadCredential=`.
   The runtime service cannot access this directory. Migration resolves only its
   database resources; it does not require access to the server/device private keys.
5. Run `systemctl start lindmd-migrate.service` explicitly and inspect its exit
   status/journal. Revoke runtime INSERT/UPDATE/DELETE and sequence privileges on
   migration bookkeeping (`public.goose_db_version`); retain SELECT for startup
   schema checks. Validate complete runtime configuration with a protected
   transient credential, not `runuser` access to the persistent URL:

   ```sh
   sudo systemd-run --wait --collect --pipe \
     -p User=lindmd -p Group=lindmd -p MemorySwapMax=0 -p LimitCORE=0 \
     -p LoadCredential=database-url:/etc/lindm/database-url \
     -p LoadCredential=integrations-key:/etc/lindm/integrations.key \
     /usr/bin/lindmd check-config -config /etc/lindm/server.json \
     -database-url-credential database-url \
     -integrations-key-credential integrations-key
   ```

   This checks configuration/resources, not DB connectivity.

6. Create `/var/lib/lindmd-operations/setup` owned by `lindmd-migrate` mode 0700
   beneath root-owned `/var/lib/lindmd-operations`. Issue the code through a
   protected transient migrator credential:

   ```sh
   sudo systemd-run --wait --collect --pipe \
     -p User=lindmd-migrate -p Group=lindmd-migrate \
     -p MemorySwapMax=0 -p LimitCORE=0 \
     -p LoadCredential=database-url:/etc/lindm/migrate/database-url \
     /usr/bin/lindmd setup-code -config /etc/lindm/migrate/server.json \
     -database-url-credential database-url \
     -output /var/lib/lindmd-operations/setup/code
   ```

   The issuer creates a mode-0600 file; the database stores only its hash. Transfer
   file/directory ownership to root after issuance, or use the installer's
   root-owned staged migration config to issue directly as root. Read the code
   only in a private root terminal. Never put it in a journal, argument or URL.

7. Run `systemctl enable --now lindmd.service`. Verify the actual TLS chain and
   `GET /healthz` and `/readyz` (204), embedded `/` (200), LOCAL `/auth/options`,
   and unauthenticated admin RPC denial (401). Visit `/setup`, enter the setup code,
   choose a username/password and register a user-verifying passkey. Successful
   registration opens the dashboard; a password without a passkey grants no session.
8. Open **Settings › Agent repository**. Confirm **Ready**, the expected agent
   version and the target OS/architecture. There is no repository configuration
   step. Copy and run the console enrollment command on the bare device, then
   confirm **Enrolled**. If verification fails, preserve the exact per-OS cause
   and repair or reinstall the authenticated release instead of disabling checks.

Keep `journalctl -u lindmd -u lindmd-migrate` private. A successful health response
does not certify a login ceremony, device enrollment, dispatch or capacity.

After every explicit migration, remove the broad default DML grants from migration
metadata before starting the server. Execute this as the migrator/database
administrator (substitute the actual runtime role if different):

```sql
REVOKE INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER
ON public.goose_db_version, public.lindm_schema_compatibility,
   public.server_recovery_state FROM lindm_runtime;
DO $$
DECLARE sequence_name text := pg_get_serial_sequence('public.goose_db_version', 'id');
BEGIN
  IF sequence_name IS NOT NULL THEN
    EXECUTE 'REVOKE ALL ON SEQUENCE ' || sequence_name || ' FROM lindm_runtime';
  END IF;
END $$;
```

Retain SELECT so `serve` checks exact applied history and the trusted migrator-owned
compatibility floor. On a local PostgreSQL host, feed this SQL to `runuser -u
postgres -- psql -X -v ON_ERROR_STOP=1 -d lindm`. Schema CREATE denial alone is
insufficient: a runtime credential must not forge migration or recovery metadata.

#### Protected browser setup

First-run setup requires the installer's cryptographically random 256-bit code.
`setup-code` resolves only the migration database resources and never reads runtime
signing keys. Its output must be a **new** file under owned, non-replaceable
directory ancestry; it rejects existing files and symlinks instead of overwriting
another secret. The file contains only the base64url code plus newline; stdout
and structured logs do not contain the code.

The migration identity owns the setup capability table. Migration 50 strips
inherited non-owner table grants, preserving read access and only
`UPDATE(account_id, consumed_at)` for existing writers. Runtime may reserve or
consume a code; it cannot create a code, change its hash/expiry, or remove it.
Code issuance therefore requires the dedicated migration database identity even
when root invokes the staged issuer configuration.

The code expires after 24 hours. The first correct code submission reserves one
username and password hash, not administrator authority. Every restart requires
that same code, username and password. Another holder cannot change the reserved
identity or password. A failed, cancelled or interrupted passkey ceremony creates
no session and consumes no owner capability; restart the form with those same
values. A fresh ceremony replaces its predecessor, so old challenges cannot replay.
Browser code/password/challenge values stay in component memory only, never in
URLs, query caches, persistent storage or logs.

After expiry, explicitly issue a replacement code to a new protected output file.
Rotation invalidates old codes and in-flight challenges while preserving the
reserved account and password. It is not a reset or account takeover mechanism.
If the password is lost before setup completes, preserve the installation state
and investigate through the protected server recovery procedure; the installer
does not silently choose a different owner.

Successful user-verifying registration consumes the code, pins/initializes the
owner, saves its credential and creates its authenticated session atomically.
Configured signed initial execution delegation admission joins that transaction;
refusal rolls everything back and allows the same bound setup to resume.
After initialization, issuance and setup are disabled. Remove the consumed code
file as root; retained consumed copies grant no authority.

Setup requests require the exact configured HTTPS Origin, JSON content type and
the console's non-simple setup header, with an 8 KiB body limit. Durable admission
allows ten attempts per client IP and sixty globally per minute, across replicas
and restarts. Client addresses come from the actual connection, never forwarded
headers. All authentication responses use `Cache-Control: no-store`.

### Upgrade, backup, restore and removal

The first turnkey release, schema version 53 with minimum runtime floor 51, is the
managed upgrade baseline. Pre-turnkey manual/lab installations are refused with a
named unmanaged-installation error: no silent adoption, rekey or configuration
overwrite occurs. Use a fresh turnkey instance and reenroll devices; no historical
automatic migration or pre-baseline backup reader is offered.
The new schema compatibility, first-run, recovery, status and custody migrations
are versions 49–53. They follow the already-landed MCP migration 48 without
renumbering existing history. Online status/custody expansions retain floor 51;
rollback still obeys the declared floor, never an automatic down migration.
Migrations 51–53 are deliberately **one-way**, including on an empty deployment:
their Down commands refuse to discard recovery fences, retained status audit
state or recovery-key custody attestations. Compatible package rollback keeps
those migrations applied. Historical migration tests create a fresh owned schema
at the predecessor version and migrate forward; they do not undo these security
records to arrange test data.

Run the next independently authenticated private bundle's `sudo ./install.sh`;
it refuses same-version installation and unrequested downgrade. It checks the
database version, exact migration history/compatibility policy and free disk
(twice database size plus 4 GiB backup headroom), then requires a successful
encrypted BackupCare snapshot **before** package replacement or migration.
Unattended/direct native package upgrades cannot bypass this path: DEB preinst and
RPM pretrans consume a root-only, version- and installer-process-bound one-use
authorization. An ordinary APT/RPM transaction fails before replacing the server.
The lifecycle lock and inherited operations lease serialize package replacement,
backup, restore and release-feed updates. Timers cannot race the protected
transaction; the installed old CLI makes the pre-upgrade snapshot, while the new
CLI reconciles an already imported release feed after successful replacement.
All entry points acquire the operations lease before the lifecycle lock. Protected
update apply keeps the same lease across imported-release authentication,
configuration staging and installation. The installer validates and reuses that
same-process lease without closing its caller's ownership; timer restart occurs
only after the lease is closed, including failure cleanup.

`schema-check` distinguishes reviewed expand migrations from contract migrations.
For `online=true`, the old runtime continues serving through the consistent backup,
native binary replacement and bounded dedicated-identity expand migration. Its
verified readiness is checked before restarting the new runtime and checking
again. Contract migrations and the initial compatibility-policy cutover stop and
fence runtime traffic before backup/migration. The current recovery-state contract
raises the compatibility floor; an older binary lacking that security fence is
not a permissible rollback. Never blanket-grant DML on existing metadata tables
while the old runtime serves.

Use the previous independently authenticated bundle with explicit `--rollback`
only when its `schema-check` reports compatible with no pending migrations and
its target is at or above the trusted compatibility floor. The installer still
requires encrypted backup, never executes Down migrations, and performs native
replacement plus verified readiness. Previous binary bytes are retained under
`/var/lib/lindmd-operations/rollback/VERSION/lindmd`; this is not an independent
signature substitute. Below-floor rollback requires fenced encrypted-backup
restore with the recovery reconciliation/quorum gates, not a forced package
downgrade. Keep the original signed bundles and offline backup identity separately.

The signed native package contains the maintained `filippo.io/age` v1.3.2
streaming encryption implementation. PostgreSQL snapshots and validation use
the actual supported `pg_dump`/`pg_restore` clients, not a Go database substitute.
No EPEL repository, external age executable or Internet feed is needed.
Installer enablement of `lindmd-backup.timer` schedules a root-only encrypted
backup every fifteen minutes, with a persistent timer and bounded execution.
The backup includes the PostgreSQL custom archive, the original configuration,
every configured resource reference, repositories and durable server state.
Native migrator resources and PostgreSQL TLS configuration are inventoried
without granting the runtime account access to them. Database roles/grants are
recreated on the fresh host, not recovered by importing source superuser roles.

#### Operator backup key custody

Create the **operator backup identity on the offline operator workstation**,
not on the server. `lindmd backup-keygen -identity-file FILE -recipient-file FILE
-identity-passphrase-fd N` writes a passphrase-encrypted standard age identity
and its public recipient. Passphrases must arrive through an owner-private
anonymous pipe; creation consumes two identical LF-terminated lines.
Decryption consumes one line. A numeric descriptor is not a secret. Never put
passphrases in shell arguments, environment variables, plaintext files, terminal
echo, journal output or a support capture. The maintained shared custody helper
rejects regular files, named FIFOs, unsafe descriptors and missing confirmation,
and cancels blocked reads with the command context. Offline private inputs and
outputs require caller-owned mode-0700 directories and mode-0600 files; native
server inputs retain strict root-protected, no-symlink ancestry.

The secret-handling commands lock current memory and disable dumps before
decryption. Grant the offline process sufficient `RLIMIT_MEMLOCK`; do not weaken
that gate when a workstation limit is too low. Private identities/keys are
decrypted only in memory. The server receives only the public recipient, checked
by the installer and retained as `/etc/lindm/backup-recipient`.
Keep the encrypted operator identity, its passphrase and immutable off-host
backup copies under the organization's independent custody policy.

The operator backup identity is **not** execution/PKI authority. Generated
execution-root signing keys and generated CA keys are directly encrypted in
memory to their custodians. The generated passphrase-encrypted custodian export
and its encrypted authority objects are separate from the backup identity.
Scheduled archives retain those ciphertext objects, never root-private keys,
generated CA-private keys or plaintext custodian identities. A backup operator
alone cannot decrypt the inner authority ciphertext. A custodian who possesses
the applicable passphrase/export or recipient identity can; the three generated
execution keys in one export do not constitute three independent humans.
Supplied-custodian mode requires the operator to retain its encrypted CA/root
key inputs separately as well.

For an immediate native backup:

```sh
sudo lindmd backup -config /etc/lindm/server.json \
  -recipient-file /etc/lindm/backup-recipient -output-dir /var/backups/lindm
```

The command publishes only a complete authenticated encrypted archive at
mode 0600 beneath the root-only backup directory. Plaintext custom-dump staging
is private, size-bounded and removed before returning. PostgreSQL credentials
remain in temporary private libpq service files: only nonsecret protected
service-file paths enter subprocess environment; no credential URL is passed
in argv and no subprocess diagnostics are relayed. Retain an immutable off-host
copy. Timer files and backup retention consume storage: monitor capacity and
apply the organization's retention policy rather than assuming automatic purge.

A cancelled backup retains its safe `context canceled` or
`context deadline exceeded` cause. PostgreSQL stderr stays redacted.
Do not treat a cancelled or failed dump as a complete backup.

The encrypted inventory includes the exact integrations encryption key and its
persistent configuration reference. Keep its root:root mode 0600 custody intact.
Restore replaces the fresh host's different key with the archived original before
starting the runtime. It never rekeys existing destination ciphertext. A configured
archive without its complete, valid key stops recovery. The full native restore
drill must decrypt a destination created before backup with the restored key and
prove that the fresh host's different key cannot decrypt that same ciphertext.

Backup completion metadata at
`/var/lib/lindmd-operations/backup-health.json` is root-owned, public operational
information bound to the original deployment, origins and normalized config.
It records attempts, completion and encryption/archive completion, not proof of
restoration. The service-owned state directory cannot replace this record.
A failed attempt preserves a matching deployment's earlier completion; a
different configuration does not inherit another deployment's success.

#### Recovery authority and fresh-host restore

`lindmd restore-drill -archive FILE -identity-file FILE
-identity-passphrase-fd N` is a nondisruptive offline archive check: it verifies
age final-stream authentication, the closed manifest/schema/version inventory,
every file digest, safe archive paths/modes, configuration and trust loading,
and the actual PostgreSQL custom-archive parser. It does not claim live device
management recovery, fresh security state or absence of later revocations.

Safe stale recovery requires a **separately authenticated complete current
checkpoint**. While the source is available, externally fence every admin/device
ingress and stop **every** runtime/HA replica, not merely the local systemd unit.
Drain existing grants on every replica before capture; the persistent database
hold is a startup fence, not a stop command for already-running processes.
Capture with the native backup command plus `-confirm-fenced`. It drains the
real thirty-second start-grant window plus admitted clock skew, fsyncs a source
restore marker, then uses the separately protected migrator credential to
durably commit `server_recovery_state.hold=true` before `pg_dump`. The checkpoint
itself therefore contains the replica-authoritative hold, along with the exact
schema, root digest and capture time. The source cannot be
silently restarted: there is no unsigned clear-hold command. Ordinary scheduled
backups are not complete fenced checkpoints and cannot mint freshness later.
If the source has been lost, a stale archive or possession of signing keys alone
cannot prove current revocations. Recover only from an independently retained
complete checkpoint through the loss fence, or remain fenced and follow the
organization's reprovision/re-enrollment recovery process.

On the offline custody workstation, `lindmd restore checkpoint-sign` takes
`-archive`, `-security-archive`, `-identity-file`,
`-identity-passphrase-fd`, an independently authenticated `-root-file`,
`-recovery-epoch`, `-output` and `-confirm-fenced`. Generated authority is supplied
using `-custody-export-file FILE -custody-passphrase-fd N`; external authority uses
`-custodian-identity-file FILE -custodian-identity-passphrase-fd N` plus repeated
`-key-custody FILE`. Signers attest the complete newer snapshot, original archive
digest, exact deployment/origins/root, package version and newer epoch. The
archive cannot select its own trusted root. Use the maintained offline
`lindmctl execution delegation sign` command to create the same-root
`UpdateExecutionTrustRequest` with a strictly newer quorum-approved recovery
epoch; generated encrypted authority uses the corresponding custody-export
and descriptor flags. No serving-key or unsigned epoch bypass is accepted.
There is no plaintext root-key `-key-file` checkpoint-signing path: encrypted
custody inputs must be mode 0600 even when the offline caller is root. Public
root JSON and on-host status-readable ciphertext metadata retain their separate
protected read policy; they are not private decryption inputs.

Provision a fresh authenticated host/database on the checkpoint's exact
compatible package/schema, with separate restricted runtime/migrator identities,
verify-full TLS, matching public origins and empty management data. Keep
all ingress and replicas externally fenced and the runtime stopped. Run:

```sh
sudo lindmd restore -config /etc/lindm/migrate/server.json \
  -archive EARLIER_ARCHIVE -security-archive AUTHORITATIVE_CHECKPOINT_ARCHIVE \
  -security-checkpoint SIGNED_CHECKPOINT -execution-update SIGNED_EPOCH_REQUEST \
  -root-file INDEPENDENT_PUBLIC_ROOT -identity-file ENCRYPTED_OPERATOR_IDENTITY \
  -identity-passphrase-fd N -confirm-fenced -reason 'Approved recovery drill'
```

Place the encrypted operator identity and public approval inputs under a
root-protected temporary directory, then remove those transient inputs after
the drill. Never copy custodian private keys to the fresh server.
Restore first validates both archives, their bindings and the fresh target,
then durably fences that target before database mutation. Partial failures stay
held. It restores the **complete authoritative checkpoint**, not earlier data
pretending to be current; report the checkpoint time and any externally accepted
loss interval. Old certificates/revocations and device journals are retained
from that snapshot. Fresh database credentials/TLS remain fresh; preserved URL
files are republished to the target's original stable paths, root:root mode 0600,
with references to preserved target TLS resources. Native credential units need
no path change. Source application/device trust and configured runtime secrets
are restored intact.
Runtime metadata privileges are narrowed after `pg_restore --no-acl`: schema,
migration and recovery state stay SELECT-only, and first-run state keeps only
its existing account/consumption column updates.

Restored browser/CLI sessions, challenges and setup codes are invalidated.
Pending destructive/resource work and assistance are cancelled/blocked and
require fresh authorization/consent. A quorum-verified same-root newer epoch is
applied transactionally and checkpoint acceptance is audited. Only after exact
schema/trust/config/target checks, authority invalidation, ciphertext custody
publication and private staging cleanup succeed is the database/filesystem hold
released. Validation, transactional reconciliation and protected-file publication
are distinct fail-closed stages; none owns an early hold-release path. Then start the
runtime, reconcile devices, obtain fresh owner authentication/approvals, and
prove a newly authorized real managed action before removing the external fence.
Archive validation alone is not this full maintained fresh-VM/device drill;
record actual lane evidence in verification rather than claiming an unrun result.

After restore, retain **both** the canonical source authority export and the
fresh database CA export. `sudo lindmd custody-status -config
/etc/lindm/server.json` reads the bound public provider record and prints each
required ciphertext path/SHA plus `ConfirmationSHA256`, the composite required
export-set digest. Copy each required ciphertext off-host and check its actual
individual SHA before owner confirmation. A composite is not a file checksum.
Source-only old confirmation cannot acknowledge the fresh database CA. Runtime
status never decrypts authority exports or prints their private contents.

#### Support, private offline updates and removal

`sudo lindmd support -config /etc/lindm/server.json -output NEW_FILE` produces a
root-only bounded tar of structured allowlisted platform/version, counts,
configuration/schema/recovery and public backup/release facts, with an explicit
omission manifest. It does not collect raw configuration, database rows,
journals, free-text operator reasons, URLs, sessions/challenges/setup codes,
passwords, keys, backup identities or backup contents.

Server release discovery is distinct from agent TUF. Import a customer-delivered
private signed release export with `sudo lindmd update import -bundle DIRECTORY
-release-key-file INDEPENDENT_PUBLIC_KEY -release-key-id SPKI_SHA256`.
The pinned signature authenticates the exact release bytes and optional typed
server notice; imported exports cannot roll the discovered release backward.
`sudo lindmd update check` re-verifies the retained signed bundle and records
version/security notice validity. The enabled hourly release-check timer refreshes
only an existing import, never contacts a public feed. Missing/expired notice
metadata is not a current security feed. `sudo lindmd update apply` invokes the
native installer with full and supplemental signature checks, stops the runtime,
takes an encrypted pre-migration backup and retains the verified previous binary.
One exclusive operations lease spans imported-bundle re-verification, config
staging and the whole installer call. Lifecycle locks are acquired after that
lease consistently, and stopped timers are restarted only after its final close.
The backup identifies the running schema-compatible pre-upgrade release, not the
new installer process. Old binaries cannot serve below the recovery schema floor.

Removal/purge stops runtime/backup/release timers and removes package-owned
binaries/units only. Operator `/etc/lindm` configuration/keys, PostgreSQL data,
encrypted authority exports, independently protected operational state, backups
and dedicated accounts are retained deliberately. Their irreversible deletion is
a separate documented operator retention decision, never a package lifecycle hook.

### OCI and Docker Compose

`deploy/server/Dockerfile` packages a statically linked, embedded-console `lindmd`
into a digest-pinned distroless non-root image. Build the console before the Go
binary; do not substitute a dev server or mount frontend source into production.
Publish and verify the organization's signed image digest before installation.
The checked-in base-image pin is not a signature on a locally built Lindm image.

`deploy/server/compose.yml` is a **laboratory single-host topology**, not a
supported turnkey container installer. It has digest-pinned PostgreSQL 18.6 with
TLS and a named persistent volume, separate explicit migration/setup operations
and an unprivileged read-only server. PostgreSQL has no published host port.
It does not provide the native installer's authenticated dependency/image import,
automatic local PKI/role provisioning, protected upgrade backup/compatibility
gates or full restore rehearsal. OCI release exports currently cover application
images, not an independently signed PostgreSQL dependency image. The Dockerfile's
public base-image pulls are build inputs, not an approved deployment download
path. No container deployment may pull a public registry as an air-gap fallback.
Equal-guarantee bundle-loaded Compose/Quadlet delivery is therefore not claimed.
For the narrower lab topology, set `LINDM_IMAGE` to a locally loaded,
independently authenticated released digest and `LINDM_CONFIG_DIR` to a protected
absolute directory.
Default runtime UID/GID is 65532; own its mode-0600 bind-mounted input files by
that numeric identity. Configure public origins/listener addresses for the
deployment (inside the container bind listeners to `0.0.0.0`). The runtime URL uses
hostname `postgres` and `sslmode=verify-full` with the separately mounted CA.
The runtime does not mount the migrator credential.
Set `LINDM_SETUP_DIR` to a separate absolute mode-0700 output directory owned by
the operation's numeric UID. Only `setup-code` mounts it writable; the runtime
never mounts either that directory or the migration credential.

Prepare the files listed by the Compose bind mounts, including separate runtime
`server.json` and migration-only `migrate.json`, PostgreSQL TLS server certificate
with DNS SAN `postgres`, protected key/password and a reviewed first-start
`database-init.sql` defining the two restricted roles/default privileges above.
Use a fresh random PostgreSQL administration password. All service keys remain
external to the image. Add individually mounted files and corresponding config
references for optional execution-signing or external-directory resources.

```sh
docker compose -f deploy/server/compose.yml up -d --wait postgres
docker compose -f deploy/server/compose.yml run --rm migrate
docker compose -f deploy/server/compose.yml exec -T -u postgres postgres \
  psql -X -v ON_ERROR_STOP=1 -d lindm <<'SQL'
REVOKE INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER
ON public.goose_db_version, public.lindm_schema_compatibility FROM lindm_runtime;
DO $$
DECLARE sequence_name text := pg_get_serial_sequence('public.goose_db_version', 'id');
BEGIN
  IF sequence_name IS NOT NULL THEN
    EXECUTE 'REVOKE ALL ON SEQUENCE ' || sequence_name || ' FROM lindm_runtime';
  END IF;
END $$;
SQL
docker compose -f deploy/server/compose.yml run --rm setup-code
docker compose -f deploy/server/compose.yml up -d lindmd
```

Read `$LINDM_SETUP_DIR/code` only from a private operator terminal and complete
`/setup` with your username, password and passkey. Remove the consumed code file
after completion. Explicitly choose `LINDM_BIND_IP` and firewall policy before
exposing the admin/device ports (default bind is loopback). Verify the HTTPS chain
and readiness from the real access path.
Upgrade by stopping `lindmd`, backing up, selecting the next immutable image,
running the explicit migration and recreating `lindmd`. For Compose backup/restore,
run the same PostgreSQL tools through `docker compose exec -T -u postgres postgres`
and back up the external config directory with preserved ownership. Never run
`down --volumes` during ordinary upgrades/removal: it destroys the database.

`lab server compose -repo . -record NEW_FILE` builds and exercises this exact
topology using a uniquely named disposable project, short-lived LOCAL fixture
keys and dynamically allocated loopback ports. It is a container boot/migration
and isolation proof, not native-host, backup/restore, image-signing or HA evidence.

### Replicated topology and HA operation

The qualified replicated shape is two or more `lindmd serve` replicas behind a
layer-4 TLS-passthrough load balancer, one PostgreSQL primary and one synchronous
streaming-replication standby. TLS terminates at `lindmd`: device mTLS requires
the replica to see the client certificate, so the balancer must not terminate or
re-encrypt either listener. Shared S3-compatible artifact storage and separately
scaled worker-only processes are not implemented; the hosted update repository and
release publisher remain per-replica configuration and are not covered here.

Every replica uses identical configuration except its listener ports: deployment
UUID, public and device origins, server TLS certificate/key, device CA
certificate/key, execution bootstrap and online signing keys, integrations key,
advisory configuration and database URL. A differing value is unsupported.
Sessions, login ceremonies, enrollment, device sessions, challenges, nonces, start
grants and reports are all in PostgreSQL, so no balancer stickiness is required.

Balancer requirements, as qualified with HAProxy 3.2 (`mode tcp`):

- Health-check each replica with TLS `GET /readyz` on its **admin** listener,
  expecting 204, and verify the server certificate. Check the device backend
  against the same replica's admin port (`check port`); the device listener
  demands a client certificate and has no readiness route.
- Enable connection retries with redispatch (`retries 3`, `option redispatch 1`)
  so a connection refused by a draining or crashed replica goes to a peer.
- Keep idle timeouts at least 120 seconds and do not enable
  `on-marked-down shutdown-sessions`: graceful shutdown drains in-flight requests
  for up to 20 seconds and sends HTTP/2 GOAWAY itself.
- `/readyz` pings PostgreSQL. During a database failover every replica is briefly
  unready, and the balancer may have no healthy backend; clients retry.

PostgreSQL requirements:

- `synchronous_commit = on` with `synchronous_standby_names` naming the standby.
  An acknowledged mutation or device report is then durable on the standby before
  `lindmd` answers. Asynchronous replication can lose acknowledged work on
  promotion and does not meet the no-lost-accepted-work contract.
- List every node in the runtime URL with `target_session_attrs=read-write`, e.g.
  `postgresql://lindm_runtime@db1:5432,db2:5432/lindm?sslmode=verify-full&target_session_attrs=read-write`.
  Each node's certificate must match the host name used for it.
- The HA manager (Patroni, pg_auto_failover or an operator runbook) must fence the
  old primary before promotion. With synchronous replication an unfenced, isolated
  old primary cannot acknowledge commits because its standby is gone, but `lindmd`
  does not fence it. The laboratory crashes the old primary instead.
- After promotion the cluster has no synchronous replica. Re-clone or `pg_rewind`
  the old primary as the new standby and restore `synchronous_standby_names` before
  declaring HA restored; until then a second failure loses availability.
- Set server TCP keepalives (`tcp_keepalives_idle = 10`, `interval = 5`,
  `count = 3`) so a partitioned replica's coordination session and its advisory
  locks are released within about 25 seconds instead of the operating-system default.
- Size `max_connections` for each replica's `database.max_connections` device pool
  plus its `database.admin_connections` console pool (default 4), plus one
  coordination session per replica, plus migration and administration sessions.
  The console pool serves identity/session checks, the admin API and the fleet
  summary, so device traffic saturating the device pool cannot queue operators.

Background jobs (inventory in `internal/server/jobs.go`):

| Job                      | Distribution                                                            | Correctness fence under overlap or retry                                                                                                                                                                                                                                            |
| ------------------------ | ----------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `snapshot-cleanup`       | Exclusive, advisory key `0x6c696e646d000001`                            | Per-device row lock; staging/receipt reservations released once                                                                                                                                                                                                                     |
| `advisory-maintenance`   | Exclusive, key `0x6c696e646d000002`                                     | Refresh schedule from durable per-feed `attempted_at`; leased publication generations; SKIP LOCKED cleanup                                                                                                                                                                          |
| `advisory-evaluation`    | Replicated (four workers per replica); key `0x6c696e646d000003` retired | Expiring per-device claims (`advisory_evaluation_claims`, SKIP LOCKED) distribute batches; per-device row lock and exact revision bindings make an overlapping evaluation coherent; one instance builds a missing finding set (transaction advisory lock), others defer its devices |
| `compliance-deadlines`   | Exclusive, key `0x6c696e646d000004`                                     | SKIP LOCKED assignment lock; events emitted only on state transitions                                                                                                                                                                                                               |
| `rollout-promoter`       | Exclusive, key `0x6c696e646d000005`                                     | Scanned rollout revision CAS, targeting fence, unique revision event and current creator authorization                                                                                                                                                                              |
| `integration-deliveries` | Replicated (four workers per replica)                                   | Random token + generation leases; receivers deduplicate the signed `event_id`                                                                                                                                                                                                       |
| `reports`                | Replicated                                                              | SKIP LOCKED schedule and artifact leases with token and database time                                                                                                                                                                                                               |

Each replica opens one dedicated coordination session (never from the pool),
refuses it if it reached a standby (`pg_is_in_recovery()`), and polls
`pg_try_advisory_lock` for idle exclusive jobs every 5 seconds ±20%. A 2-second
heartbeat proves the session is alive and still holds each lock (`pg_locks`); on
loss every led job is cancelled and joined before reconnecting. A job that returns
or fails releases its lock and backs off 1–60 seconds with jitter; replicated jobs
restart under the same backoff. Graceful shutdown unlocks explicitly; a crash
releases locks when PostgreSQL closes the session. Overlap after session loss is
bounded by one heartbeat plus one 5-second probe, which is why every job above
keeps its own row fence. Advisory keys are a compatibility contract between
concurrently running releases. Find the current holder with:

```sql
SELECT to_hex((l.classid::bigint << 32) | l.objid::bigint), a.application_name
FROM pg_locks l JOIN pg_stat_activity a USING (pid)
WHERE l.locktype = 'advisory' AND l.objsubid = 1 AND l.granted;
```

The holder is named `lindmd jobs HOST pid PID`; replica logs record
`background job leadership acquired` and `released`. Job failures and database
failover never stop the serving process.

Rolling schema application is permitted only when the dedicated migrator's
`schema-check` reports `online=true` for every pending, reviewed expand migration
and each participating/rollback binary remains at or above the trusted
compatibility floor with the exact recorded applied history. Otherwise use the
fenced single-host upgrade. The initial policy and recovery-security cutovers are
contract changes, not online claims. For each replica in turn, drain/stop runtime,
use the authenticated gated package installer and successful encrypted snapshot,
then wait until both balancer backends report that replica UP and public
`/readyz` returns 204 before replacing the next replica.
Mixed N/N+1 replicas share the database, advisory keys and protocol during the roll.
Devices reconnect through the balancer on connection loss; protocol state lives in
PostgreSQL, an exact start-authorization retry returns the same grant and an exact
result-report replay is accepted, so a lost reply never repeats an effect.

### Server checks, readiness and alerts

Open **Settings → Server status** with an unrestricted `integrations.manage`
grant. Each row separates the latest check time from the original evidence time.
Unknown means evidence is missing; failed means the check observed a failure;
attention means expiry, stale evidence or an overdue backlog. A page refresh reads
the latest operational observation, not a new probe; custody reads its current
protected creation record separately. Every replica samples operational checks
once per minute, under a 15-second probe deadline; observations older than two minutes
become unknown without advancing their evidence timestamps.

- **Database:** both runtime and console pools must answer over their already
  verified TLS connections. The check does not certify query capacity, migration
  ownership or application transactions; startup still enforces those gates.
- **Certificates:** loaded HTTPS and device-CA certificates need renewal within
  30 days of expiry. Renew under the PKI maintenance plan and restart the replica.
  A valid date range alone does not certify external client trust or revocation.
- **Backups:** read the root-owned redacted
  `/var/lib/lindmd-operations/backup-health.json` record through the backup provider.
  Its directory must remain root-owned and non-writable by the runtime account.
  Records must bind this deployment, its public origins and canonical runtime
  configuration. Missing/unreadable/unbound records remain unknown. A record for
  another configuration supplies no completion timestamp or archive evidence for
  this server; run a backup with this deployment's protected configuration.
  A matching record's failed attempt remains failed. Archive completion requires encryption and
  verification, never implies a restore drill, and needs attention after one
  hour without completion against the 15-minute backup timer. Inspect
  `lindmd-backup.service` and its timer before repeating a failed backup.
- **Offline server release notices:** read the protected
  `/var/lib/lindmd-operations/release-feed-health.json` record produced by signed
  private-bundle import and release checking. Missing/unverified imports remain
  unknown, expired notices need attention, and a comparison against a different
  installed binary requires a fresh release check. A newer authenticated release
  needs review and a fenced backed-up upgrade; security notices explicitly name
  that decision. A signed bundle without an expiring notice can establish a newer
  imported version, but never establishes current security-discovery coverage.
  A confirmed comparison means only that this authenticated import offers no
  newer release, not that the site is globally up to date. Keep importing signed
  notices through the customer's private connected-to-offline transfer process.
  Server releases describe the signed product globally rather than a site's
  backup identity; installed-version comparison remains mandatory.
- **Agent installation:** show the existing signed installation-readiness
  contract and retain its startup verification time. The bundled repository needs
  no separate public hosting or manual repository setup. Review platform coverage
  in Settings; serving still verifies package hashes before returning bytes.
- **Advisory feeds:** report configured acquisition failures, absent evidence
  and expiry separately. Fresh acquisition is not proof of complete native
  package coverage. Restore connectivity or import an authenticated offline bundle.
- **Storage:** inspect the filesystem holding `/var/lib/lindmd`, not PostgreSQL
  or an off-host backup destination. Less than 1 GiB, 10% available blocks or 5%
  available file slots needs attention. Extend the volume or review retention;
  never remove active data to clear a warning.
- **Work:** inspect delivery dead letters, pending delivery age and due reports.
  Ten minutes overdue needs attention. Local worker loop failures are failed;
  waiting for exclusive leadership is not proof that a peer holds the lock.
  Inspect leadership and the service journal using the HA procedure above.

`GET /healthz` returns only process liveness (204). `GET /readyz` returns 204 only
when both database pools answer within a shared two-second deadline, otherwise
a generic 503. Neither exposes a database URL or operational diagnostic.
`GET /metrics` is unauthenticated on the administrative TLS listener and returns
Prometheus text gauges: `lindm_server_status_state`, `_observed_seconds`,
`_evidence_seconds` and `_expiry_seconds`. The only label is a closed component
name. State values are 1 unknown, 2 confirmed check, 3 attention, 4 failed and
5 inactive; timestamp zero means unavailable, not an epoch observation.
Restrict scraping through the site's network policy and trust the actual TLS
chain. Alert on states 1/3/4 and on an observation older than two minutes rather
than interpreting a successful HTTP scrape as a successful component check.

When integrations are configured, degradation transitions insert audit events
and delivery work atomically through the existing webhook/syslog outbox.
Unchanged degradation sends at most one reminder every six hours per component
and replica, including across restarts; recovery sends once, while an initial
successful observation does not manufacture a recovery alert. Event actions
identify unknown, attention, failed, recovered and inactive states. The public
delivery projection contains only action, an opaque replica/component reference,
event identity and timestamp, never diagnostic text, backup names or credentials.
Use **Integrations** to confirm delivery, inspect dead letters and replay after
fixing the receiver. A database outage can prevent the outbox write: pair these
notifications with an independent availability/Prometheus monitor. No configured
destination means no external alert delivery.

Each distinct authenticated server release/security notice emits promptly even
while the previous notice already needs attention. Its stable notification
identity binds release versions, security indication and advisory references,
never polling timestamps, and is not a public metric label.

#### Move recovery keys off this server

When installation or restore generates recovery identities, **Server status**
keeps **Move your recovery keys off this server** visible until the actual
deployment owner records an attestation for the complete required-export set.
Inspect each protected export path and **File checksum** in **Details**. Transfer
every passphrase-encrypted export through the site's authenticated root/off-host
process, and check each file checksum at the destination. Keep each file's
passphrase separately. The **Confirmation digest** binds the entire set; it is
not an individual file checksum. The console never serves these files, and the
runtime never writes privileged custody metadata.

Choose **Confirm off-server custody**, then acknowledge every listed export.
**Record my confirmation** requires a new local-account password and
user-verified passkey ceremony for that exact set. Initial setup/sign-in,
generic step-up, an invited owner-role account and service accounts cannot
substitute for the actual deployment owner's scoped verification. The server
checks current authorization and the live session inside the attestation
transaction, then consumes the scoped verification stamp. Attestation, audit and
configured integration delivery work commit together.

**Owner confirmation recorded** means only that this owner made that assertion;
it proves neither external storage nor removal. Refresh after an uncertain
response before starting another confirmation. A changed required-export set
restores the task and requires new scoped verification. Restore preserves the
source server export and any newly generated target database identity export;
an old source-only attestation cannot clear the target identity task. Each export
has its own passphrase. Missing, unreadable or foreign deployment/origin/configuration
metadata remains unknown. Explicit independently supplied recipients require no
generated-identity attestation; absence never implies that mode. Moving ciphertext
away retains immutable evidence and does not itself clear the task.

### Automatic rollout operations

Rollout progression does not require an open console or a human session. The
`rollout-promoter` leader checks at most 100 active rollouts per 10-second tick
(larger inventories continue by keyset cursor). Observe its advisory lock and
leadership logs using the HA procedure above. A missing leader or repeated
`rollout promotion failed` log is an operational failure, not a reason to refresh
the page repeatedly. Restore database/replica health; never bypass the ring gates.

The console/read API shows the retained ring, pause reason and live health counts.
`next_promotion_at` is the earliest soak completion for an automatic successor,
not a deadline or proof that promotion will occur. `promotion_ready` covers health
and soak only; the worker still needs fresh creator authority and a valid next
cohort. Manual rings require the existing explicit promotion action; the final
ring remains health-monitored and is not a claim that every device completed.

The same leader starts approved rollouts and activates their reviewed devices
(at most 50 devices per tick; see [rollout flow](design-concepts/rollout-flow.md)).
A rollout awaiting approval has saved nothing; it ends `approval_rejected` or
`approval_expired` (no request within an hour, or the approval lapsed) without
changing a device. `lindmctl apply` reports such an assignment as `pending` with
the approval ID and never fails for it; an approver with `approvals.manage` and
unrestricted `resources.assign` decides it in Approvals. A device marked
**needs review** kept its previous head because its fresh preview no longer
matched the reviewed change; review it from Rollouts (roll out again, which
supersedes the remaining devices) or inspect and activate that device's exact
preview. Never edit plan rows to force activation.

For a paused rollout:

1. Inspect the persisted pause reason and `targeting.rollout.pause` audit event.
   Automatic events have no fabricated operator reason; structured
   `details.context` records `failure_threshold`, `unknown_threshold`,
   `unavailable_threshold` or `rollout_authorization_denied`.
2. For health-budget failure, repair the affected devices or observations and
   obtain fresh native verification. Contact alone does not prove healthy state.
   Already authorized unknown effects are not replayed or automatically undone;
   the rollout model has no automatic rollback operation.
3. For authorization failure, restore the original creator's current unrestricted
   `resources.assign` authority through the normal account/scope workflow, or
   create a new human-approved rollout under an eligible creator. A different
   operator pressing Resume does not transfer ownership, and cannot authorize
   future automatic promotions on the original creator's behalf.
4. Explicitly resume with a reason after resolving the cause. Health gates must
   pass the resume check. The next automatic promotion rechecks creator authority
   and will pause again if it still cannot be established.

`lab ha` includes automatic promotion before and after killing the actual promoter
leader, without calling `ListRollouts`. It checks retained stages, promotion
events, receipts and audits for one transition per revision; leadership alone is
not accepted as proof of exactly-once progression.
Its cohort-health rows are explicitly fixture-seeded against current assignment
heads/generations; heartbeat availability and elapsed soak are real. This is a
promotion/HA qualification, not evidence of native device-health execution.

### Air-gap distribution contract

- Ship a complete manifest-addressed bundle: server/agent binaries and OCI images,
  installer packages, migrations, frontend assets, charts/configuration templates,
  trust metadata, dependency/license/SBOM/provenance data and supported recovery media.
- Mirror required OS/application repositories and vendor advisories legally. Track
  origin, snapshot digest, signing identity, acquisition time, expiry and entitlement.
  Do not promise redistribution rights for RHEL/SUSE or commercial applications.
- Import via a local operator workflow that validates signatures, size, digests,
  supported versions, provenance, monotonic metadata versions and expiration before
  atomic publication. Reject partial/corrupt/replayed imports; preserve old valid data.
- TUF root rotation and timestamp/snapshot renewal follow the same verifier online and
  offline. Expired metadata fails closed for new installs/updates. Existing valid
  agent operation continues; do not disable expiry checks to accommodate the air gap.
- A designated offline signing/mirror process refreshes metadata on schedule. Provide
  an expiry forecast and documented secure recovery if the site misses the window.
  Time is supplied by trusted local NTP; clock anomalies block high-risk actions.
- Include local DNS, CA/PKI, IdP, notification relay and repository configuration in
  the reference topology. All assets/fonts are local; no SaaS telemetry or public
  OCSP/JWKS discovery dependency may silently prevent local operation.
- Deny all external egress during acceptance. Prove provisioning, renewal, policies,
  software/advisory import, updates, backup/restore and audit export inside the site.
- Distinguish an air-gapped site with internal networking from a device disconnected
  from that site. The latter cannot receive fresh policies or destructive authority.

#### Native server prerequisite custody

Server dependency snapshots use `lindm.serverdeps.v1.Manifest`, not the
openSUSE-only rolling laboratory snapshot format. The native backend explicitly
distinguishes DEB from RPM. Signed release custody authenticates the snapshot
content address; it cannot substitute a lindm key for a distro package key.
Every closure records distro/version/architecture, authenticated base-image
digest and native installed inventory, installer-requested packages, solver
version, acquisition time and custody, exact file sizes/hashes, vendor metadata,
package provenance, and capture plus fresh-baseline offline replay transcripts.

Ubuntu retains original signed `InRelease` and compressed vendor indexes.
APT still verifies the pinned Ubuntu archive key, index/package digests and
native metadata expiry during offline installation; no synthetic unsigned index
or signature/expiry bypass is permitted. The bootstrap verifier is the distro's
intrinsic APT/dpkg/gpgv runtime, not an assumed preinstalled application service.
RHEL acquisition requires entitled vendor custody and its own RPM backend;
Ubuntu support does not qualify RHEL or grant redistribution rights.
APT uses native `--force-confdef`/`--force-confold` and
`UCF_FORCE_CONFFOLD=1` to preserve existing operator configuration instead of
silently replacing modified files. Those settings do not disable vendor
authentication or stop/start existing services. The privileged installer owns
any default-cluster suppression and service-start policy for its transaction;
the dependency snapshot primitive does not change PostgreSQL host policy.
Native APT configuration and source fragments must use owned empty directories
and an owned empty main configuration file. A literal `-` configuration path
resolves under ambient `/etc/apt/-`; it is not an isolation mechanism.

`lab serverdeps export|import|present|install -cache STORE -sha256 DIGEST` uses
bounded manifest framing followed by exact sorted file bytes. Transfers cannot
express archive links or extra paths. Import rejects symlink traversal, missing
or extra content, digest/count/byte mismatches and unsupported native backends,
then verifies vendor authentication before atomic publication. Snapshot files
are immutable and content-addressed. `install` requires root and denies external
networking; it never configures or falls back to origin repositories.
Development capture is explicitly labelled `development-lab`; production
release export must apply the release's independent custody policy.
Choose a new capture `-record` path under an existing directory. The evidence
writer runs after native capture/replay publication and joined guest cleanup;
a record-write failure is still a failed wrapper command, even when an
authenticated immutable snapshot exists. Retain the manifest and its original
capture/replay transcripts, distinguish those observations from wrapper status,
and qualify the final integrated installer/helper independently.
Use `lab vm serverdeps -replay-sha256 DIGEST` with the retained authenticated
`-manifest`, `-snapshot-cache`, matching `-lab-binary` and `-lab-sha256`, and a
separate new `-record` to qualify a newer consumer against existing Ubuntu
closure bytes. The route refuses another image/backend or changed fresh
baseline, validates vendor trust before transfer and again in the product
helper, and installs under denied QEMU egress plus a network namespace.
It preserves the original capture/replay evidence and observes actual owned
guest cleanup before returning. RHEL acquisition remains a separate entitled
backend; this Ubuntu consumer route neither registers RHSM nor qualifies RHEL.

### Offline bundle operations runbook

An offline bundle moves one release and its update/advisory authority from a
connected **station** into an isolated **site**. The station holds the offline TUF
root/targets custody, the package signer, the release-attestation key and a
dedicated Ed25519 bundle-signing key. The site server holds only the online TUF
roles (rollout, snapshot, timestamp) and independently pinned public keys. Nothing
inside a bundle can add or replace trust at the site.

Layout: `release/` (verified `lab release build` export with per-artifact
CycloneDX SBOM, DSSE in-toto provenance and artifact statements),
`repositories/<amd64|arm64>/{apt,rpm}/` (signed APT and RPM repositories built from
those exact packages; agent, `lindmd` and `lindmctl`), `updates/` (the offline-signed
TUF root chain, targets metadata, every top-level target and paused channel
proposals), `advisories/<feed-id>` (authenticated vendor snapshots) and
`bundle.json` + `bundle.json.dsse`. The strict `lindm.bundle.v1.OfflineBundleManifest`
lists every file's SHA-256 and size, the monotonic sequence, validity (at most 30
days), the release manifest digest and each feed's signed acquisition time.
Every channel artifact must be byte-identical to an attested release agent package.
Arch Linux packages, Red Hat CSAF/VEX archives and other vendor formats without a
single re-parseable snapshot are not carried; those sites still need the separate
connected refresh or a future bundle format.

#### Station (connected)

1. Build and verify the release: `lab release build` then `lab release verify` with
   the independently pinned attestation key.
2. Publish the agent packages with offline custody into the station TUF repository
   (`lab release repository publish -repository TUF -keys OFFLINE_KEYS -channel CHANNEL.json -target packages/lindm-agent/<arch>/<file>=PATH ...`).
3. Export, with a sequence strictly greater than every earlier bundle for this
   bundle key:

   ```sh
   lindmctl bundle export -output /transfer/lindm-bundle-0042 -sequence 42 \
     -validity 336h -release /private/release-export \
     -release-public-key /pinned/attestation.pub -release-key-id ATTESTATION_SPKI_SHA256 \
     -signer-home /private/package-signing -fingerprint PACKAGE_FINGERPRINT \
     -updates /private/station-tuf -updates-root /pinned/tuf-root.json -ring stable \
     -advisories /private/site-advisories.json \
     -key /private/bundle.pem -key-id BUNDLE_SPKI_SHA256
   lindmctl bundle verify -bundle /transfer/lindm-bundle-0042 \
     -public-key /pinned/bundle.pub -key-id BUNDLE_SPKI_SHA256
   ```

   `-advisories` is the site's exact `AdvisoryConfig` protobuf JSON; the site refuses
   a snapshot whose `FeedSource` differs from its configuration. `-development-key`
   is required for development package and bundle custody and is recorded as
   `development` in the signed manifest. Production custody uses an
   operator-provisioned mode-0600 key with a `production-offline-bundle-signing`
   purpose sidecar; `lindmctl bundle development-key` never creates production keys.

4. Transfer the directory by approved media. Integrity comes from the signature, not
   the medium.

#### Site (no external egress)

Configure `offline_bundles` in the server protobuf JSON:
`signing_public_key_file`/`signing_key_id` (bundle key), the release-attestation
`release_attestation_public_key_file`/`release_attestation_key_id`, and a private
server-owned `directory`. A signing `release_repository` (online custody only) and
`execution_bootstrap` are required; the TUF root comes from the authenticated
execution bootstrap. Configure `advisories.feeds` identically to the station and leave
`refreshEnabled` false.

```sh
lindmd bundle-import -config /etc/lindm/server.json -bundle /media/lindm-bundle-0042
```

The command prints a JSON result. Import order: verify the DSSE signature with the
pinned key, the manifest schema, creation (5-minute skew) and expiry; require the
tree to contain exactly the listed regular files; admit the sequence in the
PostgreSQL ledger; copy every file into private staging while hashing it; re-verify
release SBOM/provenance/artifact signatures with the pinned release key; verify the
TUF root chain and offline targets from the deployment root, require a newer targets
version and sign new online metadata; publish advisory snapshots with freshness
measured from the signed acquisition time; atomically exchange `repositories/` and
`release/`; then record completion and an `offline_bundle.imported` audit event.
The first import may run before `serve` and initializes an empty release
repository; `serve` requires that repository to exist once configured.

- An identical resubmission of an imported bundle is a no-op. An interrupted import
  resumes only with the identical signed manifest.
- A lower never-imported sequence is `offline_bundle_replayed`; a different manifest
  at an admitted sequence is `offline_bundle_equivocation`; an expired bundle is
  `offline_bundle_expired`; any byte difference is `offline_bundle_corrupt`. A
  failure leaves previously published repositories, TUF metadata and advisories
  serving.
- Imported channels are staged **paused at 0%**. Start each rollout explicitly with
  the audited `SetRollout` (console or API); import never upgrades devices.
- Agents install and update only from the site: native repositories are served
  read-only at `https://SITE/offline/repositories/<arch>/apt/` and `.../rpm/`, and
  release artifacts at `https://SITE/offline/release/`. Clients pin the package
  signing key and the site CA out of band (for example through
  `enrollment_instructions`); the server does not vouch for package keys.
- Offline targets expire seven days after station signing and imported advisories
  `maxAgeSeconds` after acquisition. Import a fresh bundle before either window
  closes; an expired window fails closed for new updates and reports advisory
  coverage as unknown rather than extending it. Recovery after a missed window is a
  newer station bundle, never a clock change or a disabled check.
- Retain the import JSON, `bundle.json` SHA-256 and the audit event with change
  records. Bundle directories may be deleted after import; the served copy is the
  server's own staged copy.

## 5. Release, update and recovery

Release artifacts are immutable, content-addressed, signed and accompanied by SBOM,
license notices, build provenance and vulnerability disposition. Pin toolchains,
container digests, generators and dependencies; review updates and verify reproducible
build inputs. Signed checksums alone are not a freshness/rollback protocol.

Reproducibility means output equality, not just pinned inputs: two isolated clean
builders with the same reviewed source, dependency lock, toolchain, locale and
`SOURCE_DATE_EPOCH` must produce matching unsigned executable/UI assets, DEB/RPM/Arch
payloads, Nix/OSTree payloads where shipped, and OCI layer/config/index digests.
Normalize archive ordering, ownership and timestamps by construction. Separate
signatures, timestamped attestations and transparency-log receipts from this equality
boundary; verify them independently and publish both payload digests and provenance.
L17/release-check retains the two manifests and comparisons. A nondeterministic
required payload fails the gate rather than being excluded after the comparison.

TUF verifies update metadata and targets from the authenticated bootstrap's pinned
root, role thresholds, signed release channels, bounded metadata/content and
anti-rollback/freeze checks. Execution signing and native package-repository trust
remain separate. Operators inspect canary health and explicitly pause or promote
cohorts through the audited rollout API; no automatic health-based promotion is
claimed. Pause prevents new selection, not an already consumed native transaction.
The opt-in mutable-host updater uses apt, dnf, zypper or pacman. Atomic/declarative
hosts must retain their native deployment/generation owner and must not enable this
mutable-package path. One updater owns the files. A separately supervised root job
and protected known-current executable survive agent replacement and guest reboot.
Recovery checks exact native package state and payload before declaring installation.

Unattended agent downgrades are rejected even when a newer, valid signed catalog
offers an older version. There is no hidden downgrade bypass. Operator-led rollback
requires a separately reviewed native-package and journal recovery procedure.
Server migration is a separate serialized command; normal API startup never runs
DDL. Backups and rehearsal are required before irreversible changes. Application
rollback never implies safe schema rollback: define forward recovery for migrations
that cannot be undone.

Backup covers PostgreSQL/WAL, immutable artifacts, configuration, trust material and
encrypted secret material with keys held separately. Restore to a fenced environment,
verify integrity, enter global dispatch hold, change recovery epoch, reconcile device
journals and revocation state, and require new approval for high-risk outstanding work.
A restored IdP/session table must not resurrect access: invalidate restored sessions
and reconcile directory deactivations before reopening admin access. Restore procedures
must account for key revocations newer than the backup through separately retained
security-event records. Fail closed if those records cannot establish safety.

## 6. Capacity, reliability and resource targets

These are proposed release-test budgets, not benchmark results or paid SLAs. Record
hardware, database/storage configuration, dataset, payload distribution, binaries and
traffic generator with every result; change budgets only by an explicit spec revision.

| Profile       | Initial release gate                                                                                                                                                               |
| ------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Single host   | 10,000 enrolled devices, 8 vCPU, 32 GiB RAM, SSD-backed storage; co-located server/DB, no load generator on the target                                                             |
| Replicated    | 100,000 devices with disclosed sizing, at least two API replicas and independent workers, PostgreSQL HA and shared artifacts                                                       |
| Traffic model | 60-second jittered heartbeat, 30-second long-poll, daily full inventory up to 5,000 packages/device with deltas, 100 concurrent console users, 5% fleet rollout                    |
| Latency       | p95 ordinary admin reads under 500 ms, durable mutation acceptance under 1 s, available online work delivered within 60 s; exclude package transfer and explicit long-poll waiting |
| Stability     | 24-hour representative soak; no lost accepted jobs, unbounded memory/queue growth or unauthorized duplicate effects; 10x heartbeat arrival burst drains within 15 minutes          |
| Agent idle    | Under 80 MiB RSS and 0.5% of one CPU core averaged over 15 minutes; provider scans/installers/desktop processes reported separately, never hidden                                  |
| Recovery      | Reference backup schedule targets RPO at most 15 minutes and RTO at most 4 hours at 10,000-device profile, proven by restore rehearsal                                             |
| HA failover   | Kill one API/worker and fail primary DB during load; preserve durable work/authorization and recover within documented 5-minute target                                             |

### Connected capacity laboratory

`lab load -lindmd artifacts/bin/lindmd -record NEW_FILE` runs the maintained
single-host device-protocol workload. It creates a disposable authority database
and real server process on dynamic loopback ports; shared dev application data and
the normal admin listener are never used. Existing Postgres/Keycloak development
dependencies and verified lab provisioning trust are prerequisites. By default the
generator is co-located, which is **not** the dedicated-target reference profile
above. It has no arbitrary endpoint or production-credential option.

Two-host mode keeps the authority, owner session, sampling and SLO decisions on
the target and runs only the simulated devices elsewhere:
`-listen-address IP` binds the admin/device listeners to one literal local IPv4
address (TLS names and signed origins are unchanged; clients dial the address),
and `-generator-host ALIAS -generator-binary /abs/lab [-generator-ssh-config FILE]`
starts `lab load-generator` over SSH. Only each one-use enrollment-grant secret
crosses that channel; remote RPC histograms are merged bin-by-bin, so
percentiles are exact. `-advisory-feeds FILE` (strict `AdvisoryConfig` JSON)
enables real feed refresh and background evaluation: the workload starts only
after every configured feed has a fresh publication, and each plateau adds an
advisory freshness SLO — after a 5-minute warm-up at least 80% of active
devices must have an evaluation bound to their current snapshot, host and feed
revision (about two minutes of lag at the 10-minute inventory cadence), sampled
every 30 s through `GetFleetSummary`; a failed or timed-out summary read is
recorded and breaches the plateau. `-package-baseline FILE` places a recorded
native `PackageBatch` first in every snapshot (synthetic dpkg padding carries
source identity, as native dpkg does). `-postgres-settings name=value,...`
applies allowlisted capacity parameters to a dedicated nvme/tmpfs cluster and
records them; `fsync`, `synchronous_commit` and `full_page_writes` are never
accepted. Each device continues its inventory cadence from its own previous
collection across plateaus (the server rejects collections closer than its
admission interval).

Scale-out mode adds `-replica-host ALIAS -replica-binary /abs/lindmd
-replica-address DIRECT_IP [-replica-ssh-config FILE] -replica-cpus CPU_LIST`
to the two-host command. It requires owned `-database-storage nvme` and a
literal `-listen-address` for the PostgreSQL host. Two replicas share that
durable database behind pinned HAProxy in TCP/TLS-passthrough mode; `-replicas 3
-third-replica-cpus CPU_LIST` adds a third local replica. This capacity topology
has **one PostgreSQL host**, not a qualified HA database pair. Configuration,
keys and public origins are identical; normal exclusive-job coordination remains
enabled. `-remote-generator-cpus CPU_LIST` pins the remote generator separately
from the remote replica and records every thread's effective affinity.
Thirty-second scale-out samples retain each replica's CPU/RSS, cumulative
balancer connection counts and generator CPU/RSS. Connection counts prove
backend distribution, not per-request round-robin routing through HTTP/2.

The harness also enforces the published ordinary-read and durable-start latency
budgets: `GetFleetSummary` p95 below 500 ms with no failed read, and
`AuthorizeResourceStart` p95 below 1 s. These join the existing sync/work p99,
non-retryable-error, snapshot-completion and advisory-freshness gates; earlier
records that did not enforce these two percentiles must be interpreted against
their retained RPC measurements.

The default ramp is 500, 2,000, 5,000 and 10,000 freshly enrolled identities,
11 minutes per plateau, eight enrollment workers, 2,000 packages per device and a
5% service assignment. Every identity obtains a real one-use enrollment grant,
Ed25519 CSR/certificate and mTLS session. The harness holds only its simulated
devices' private keys, verifies real execution trust/intent/start signatures, and
signs challenges and result attestations. Service effects and host facts are
explicitly synthetic: this measures server protocol capacity, not native executor
correctness or physical-device qualification.
Simulated release/protocol claims come from the running stamped server's
authenticated compatibility identity and are recorded as synthetic claims,
not evidence that a native agent binary ran.

The workload follows implemented service/inventory cadence: `GetSyncState` every 60 seconds,
execution-trust and service-work polling every 20 seconds, and host/full-package
collection every 10 minutes. Scheduling adds ±10% jitter and random initial phases;
`-seed` records reproducible per-device schedules. This is not the proposed
long-poll/delta model above. Every snapshot uses exact-byte hashes and 500-package
batches. Assigned devices complete prepare/challenge/start/attest/report against
the real server; no host service is changed.

Records include per-RPC counts/error codes/reasons/error rates and bounded 1 ms
p50/p95/p99 latency histograms, server CPU ticks/RSS, database size/growth,
PostgreSQL version, explicit configured pool limit and two-second sampled
active/idle/waiting database connections. Full-active sample counts are an
**occupancy proxy**, not an unimplemented pgx acquire-wait queue metric.
Current observer connections are labelled and excluded. Earlier profile records
excluded only the querying connection, so another concurrent diagnostic could
inflate client occupancy by one; their peak nine/eight or 33/32 is not an
application-pool overrun.
Hardware CPU/core/RAM/disk/kernel, Go version and server/generator SHA-256 are
retained. Enrollment and initial inventory timings are separate from each
steady-state plateau; existing simulated devices pause while the next enrollment
batch is prepared, then resume together with jittered phases. This is not a
simultaneous reconnect/rollout qualification. A plateau fails on polling p99 ≥1
second, any non-retryable RPC error, missing device polling, incomplete assigned
work, or less than 99% recurring snapshot completion. The snapshot denominator is
the number of unique periodic host/snapshot cycles, with at least one expected
cycle per device per complete eleven-minute interval. Retryable polling
errors remain visible in the record; unlike the original baseline, they do not
independently fail this SLO.
The ramp stops at the first failure and records both the last passing and first
failing counts; reaching the final stage does not imply the knee was found.

`-stages`, `-stage-duration`, `-packages`, `-assignment-percent` and
`-enrollment-workers` select bounded experiments. Runs shorter than 11 minutes
are protocol smoke measurements, not recurring-inventory capacity qualification.
No result from this lane alone qualifies 24-hour soak, retention-aged datasets,
100 concurrent console users, reconnect storms, storage-full recovery or HA.

The initial five-device protocol run found a real fresh-authority defect:
all five `GetServiceWork` calls returned `execution_signing_rejected` although
enrollment, mTLS sessions, trust synchronization, package snapshots and assignments
had succeeded. The server backdated intents by two minutes outside a newly admitted
delegation's validity. Evidence:
`artifacts/load-signing-window-20261009.json`, SHA-256
`07d1a95bb6aacd99a6dfe537c9a869a41c869a13a22672f684de63a011b77869`.
The correction clamps intent validity to admitted delegation authority and has
a fresh-delegation real-PostgreSQL regression; the harness adds no delay or bypass.

#### Measured baseline: 2,000 devices, eight-connection pool

The 2026-10-09 22:44–23:18 UTC ramp qualified **2,000 devices** for this
11-minute recurring-inventory workload, not a commercial sizing target or soak
claim. The first admission/backpressure knee was bracketed between 2,000 and
5,000 devices; 10,000 was not attempted after that failure. All plateaus had zero
non-retryable errors and all assigned service cycles completed.

| Devices | Sync/work p99 (ms) | Polling rejections | Recurring snapshots | Service cycles | Mean server CPU cores | Peak server RSS (bytes) | DB growth (bytes) |
| ------- | ------------------ | ------------------ | ------------------- | -------------- | --------------------- | ----------------------- | ----------------- |
| 500     | 3 / 3              | 0 / 0              | 500 / 500           | 25             | 0.057                 | 290,025,472             | 153,354,240       |
| 2,000   | 2 / 2              | 0 / 0              | 2,000 / 2,000       | 100            | 0.210                 | 668,762,112             | 622,944,256       |
| 5,000   | 114 / 104          | 796 / 61           | 4,508 / 5,000       | 250            | 0.529                 | 1,492,750,336           | 1,361,453,056     |

Environment: Intel Core i7-13700K, 16 physical cores / 24 logical CPUs,
65,396,600 KiB RAM, Corsair MP600 PRO NH 3.6 TiB NVMe with ext4;
Linux 7.0.0-34-generic x86_64, Go 1.26.9, PostgreSQL 18.6
(`Debian 18.6-1.pgdg13+2`). Server, PostgreSQL, generator and other development
VM/build jobs shared this host; there was no dedicated CPU/memory isolation.
Workload: seed 1, eight enrollment workers, 2,000 packages/device, 5% assigned
devices, 60/20/600-second jittered heartbeat/management/inventory intervals.
Enrollment took 4.07, 11.31 and 20.66 seconds separately from the plateaus.
Database allocated size reached 3,878,819,519 bytes in the final sample.

At 5,000, `resource_exhausted` / `admission_rejected` affected sync (1.45%),
work polling (0.038%), execution-trust polling (1.52%) and inventory ingestion;
low overall server CPU does not establish spare database/lock capacity. The
original telemetry counted background database backends too: its peak of nine
active backends and 20 samples with at least eight active backends **must not**
be interpreted as nine occupied slots in an eight-slot application pool.

Record `artifacts/load-ramp-20261009.json`, SHA-256
`25bb2b1450843ce3fa46143a901bacbc859eb50c0b7baec15e876f5a0af3750b`;
server `20fa96029467a87f0dfd2a878f287139345614941af8fc49288a18caa72b8d65`;
generator `9912f6fac68d19d260d38df8bca4a3fcf645527acc5dd5180eedf9ff214ea6ef`.

A subsequent fresh-database 5,000-device plateau with the same eight-connection
budget passed: zero errors, sync/work p99 4/4 ms, 5,000/5,000 periodic snapshots,
250 signed cycles, 404.18 server CPU-seconds and 1,484,402,688-byte peak RSS.
`artifacts/load-profile-5k.json` has SHA-256
`5122f907ac04d3d471c1c31251d26b822124795cca7ab68f79c6bd21d1d245f6`;
its CPU/mutex/block artifacts are individually hashed in the record.
This is not an optimization before/after claim: no capacity tuning occurred,
the server build and co-resident activity differed, and the earlier sequential
ramp had older inventory. A short fresh-database pass does not qualify retention
cleanup or a long-running deployment, nor establish 2,000 as a structural limit.

#### WAL-bound polling investigation

The release-stamped eight-connection reramp
`artifacts/load-ramp-pool8-v2.json` (SHA-256
`cee4cacccffbedea03305dd23e36229d794f542444850a4dd3dc2840e70057a2`)
passed 5,000 but failed 10,000: sync/work p99 129/130 ms, 2,908/10,000
recurring snapshots, 13,105/1,594 polling rejections and one non-retryable
service-start conflict. CPU averaged only 0.898 cores. The 10,000-device block
profile attributes 2.25 cumulative hours to pgx pool acquisition; PostgreSQL
samples show 284 `WALWrite` LWLock waits and 58 `WalSync` waits, up to 0.665 s,
with no sampled blocker PIDs. These are accumulated concurrent waits, not
wall-clock stage duration. Repeated authenticated polling performed device
tuple locks and trust-poll `last_seen_at` updates, creating durable WAL work
even for unchanged public trust and empty work responses.

Merely widening the pool did not qualify the target:
`artifacts/load-ramp-pool32-v2.json` (SHA-256
`80500e4c9626457d83decec339160bbc80a30a86de44b61dc2e876d15adaf6a5`)
failed its 5,000-device stage with 4,651/5,000 snapshots and sync/work p99
91/73 ms. It recorded 415 `WALWrite`, 59 `WalSync` and 41 inventory-reservation
lock-wait samples. Co-resident load differs, so this is not a controlled
pool-size benchmark; it demonstrates that a larger pool alone is not a
qualified remedy. The record includes a 15-second database-cleanup timeout;
the exact owned database was subsequently dropped without FORCE. An unrelated
owned lab database needed 126.87 seconds to drop under this pressure. Maintained
cleanup bounds lock blockers at three minutes and the whole drop, including its
forced checkpoint wait, at twenty minutes, still never terminating another client.

The product correction makes execution-trust reads and no-assignment/no-open-
action work polls `REPEATABLE READ, READ ONLY`, with the same database-backed
device, generation, certificate, session and compatibility checks. Any assignment,
open action or quarantine uses the existing locked dispatch path. A concurrent
authority change may follow an already-established read snapshot; the next
request rechecks it. These reads never authorize a mutation or cache authority.
`GetSyncState` remains the durable heartbeat; trust polls no longer update
`last_seen_at`. Real PostgreSQL regressions exercise read-only transactions,
held row locks, concurrent authority/assignment changes and subsequent denial.

The harness also retains one admitted service challenge/status/report and one
partial inventory upload per device. Transient admission or lost replies resume
the exact operation at normal cadence instead of issuing conflicting fresh
challenges or replacing an open snapshot. Errors remain measured. Snapshot
qualification counts unique collection cycles, not retry attempts, with a
minimum of one expected cycle per device per complete eleven-minute interval.
The first read-only treatment on the shared cluster is recorded in
`artifacts/load-ramp-readonly-pool8.json` (SHA-256
`8e9ee09264bacf4035f571ed84841cb3ca4701a110d3b29248f924bc4a5b7a78`).
At 5,000 devices, the final sampled cumulative last-seen update count fell from
264,987 to 98,597 (62.8% fewer), consistent with eliminating trust-poll writes.
It did **not** qualify higher capacity: 4,768/5,000 snapshots, sync/work p99
140/85 ms, zero non-retryable errors. Enrollment slowed from 42.09 to 218.13 s
and the initial host load average rose from 2.56 to 9.70; co-resident VM/storage
work prevents attributing latency differences solely to the code change.
The recorded cleanup timeout was followed by successful exact-database DROP.
Dedicated PostgreSQL/storage experiments and a durable soak are required before
publishing an improved single-host limit.

#### Isolated storage experiment, interrupted by lab scheduling

`-database-storage tmpfs|nvme` starts an exact-owned PostgreSQL 18.6 container,
pinned to the same image digest and TLS/role/statement-profiling configuration as
the development fixture. `nvme` creates a bounded owned sparse loop/XFS filesystem
on verified NVMe backing; this is logical isolation, not an exclusive physical
device. `tmpfs` is explicitly labelled **storage: tmpfs (no durable fsync cost)**.
It can diagnose protocol/CPU capacity but must never supply the durable number.
Generator/server/PostgreSQL CPU sets are disjoint; they do not reserve those CPUs
against other workloads. Records include observed thread affinity and host
`iostat`/QEMU samples, rather than claiming the host was idle.

The 2026-10-10 01:02–01:19 UTC tmpfs experiment completed a 5,000-device
11-minute plateau: sync/work p99 3/3 ms, zero RPC errors, 5,000/5,000 snapshots,
250 signed service cycles, mean 0.472 server CPU cores, peak RSS 1,356,881,920
bytes and database growth 1,704,353,792 bytes. Pool size was eight; generator
CPUs 0–3, server 4–11 and PostgreSQL 12–19 were observed as configured.
All 102 host samples retained valid iostat output and matching affinities.
They observed 4–7 QEMU processes; NVMe maximum sampled utilization was 93.4%,
write await 4,332.56 ms and read await 10,853.21 ms. These maxima describe
co-resident storage pressure, not the tmpfs database's durable I/O cost.

Record `artifacts/load-isolated-tmpfs.json`, SHA-256
`8efe8ec08315276197d527618050035deeb4b0147215195ce991ab4fd1e7c193`,
binds server `3979c2aa26397ccace8709525bc274cfdade82478f7820be4a0b251bbee21a85`
and generator `7347f8c26e7ee048b9091f12f41b1b82033b8b38badba21024329a6783053ae6`.
The parent ordered load stopped during the 10,000-device plateau to prioritize
VM qualification. That incomplete plateau has no RPC percentile summary and is
**not qualified**; 20,000 was not attempted. SIGTERM ended the workload, the exact
owned container was removed, and the record preserves cancellation/session-
revocation failure rather than presenting the interrupted run as successful.

Dedicated tmpfs and NVMe TLS/roles/extension/cleanup integration regressions
passed. That co-located lane was superseded by the two-host qualification below.

#### Measured single-host limit: 10,000 devices (two-host, real feeds, 2026-10-11)

**Published single-host limit: 10,000 enrolled devices** for this workload, with
the PostgreSQL tuning below, the default eight-connection device pool and the
default four-connection console pool. 20,000 failed. Not qualified: a 24-hour
soak, 10x heartbeat bursts, 100 concurrent console users, retention-aged data, a
feed-generation change re-evaluating the whole fleet, and heterogeneous fleets.
Every simulated device shares one package set, so the whole fleet binds one
advisory finding set (see architecture).

Topology: lindmd and a dedicated pinned PostgreSQL 18.6 on dgx21 (NVIDIA GB10,
20 Arm cores, 121 GiB; Linux 6.17, Go 1.26.9). Server CPUs 5–8 and PostgreSQL
CPUs 15–18 give 8 CPUs together, the reference profile's vCPU count; memory was
not capped. PostgreSQL ran on an owned NVMe-backed loop/XFS filesystem with
durable fsync. The generator (`lab load-generator`) ran on dgx20 over the
200 Gb/s direct link, with listeners bound to `169.254.40.186` and generator
control SSH also over the direct link.

Each device did real mTLS enrollment, sessions, trust/work polling, signed
service cycles for 5% of devices and 2,000-package snapshots every ~10 min. The
first 664 packages are the recorded native Ubuntu 24.04 inventory
(`artifacts/inventory-ubuntu24-observation-20261009.json`, SHA-256
`d07821f1…8e77709`; extracted baseline
`29be31ff04655de84a0cbd912c08dc126e2ce2b566a05a9a3c794998df003f09`). The server
refreshed the real Ubuntu OSV export
(`https://osv-vulnerabilities.storage.googleapis.com/Ubuntu/all.zip`: 2,157,314
records, 4 rejected) and evaluated every device against it, giving 28,821
findings per device. dgx21 also hosted other agents' KVM lanes; host contention
samples are in each record. Records are under
`~/.cache/lindm-capacity10k-20261011/records/`.

| Run (record, SHA-256 prefix)               | Server                           | Result                                                                                                                    |
| ------------------------------------------ | -------------------------------- | ------------------------------------------------------------------------------------------------------------------------- |
| `before-5k` `6d9fceb4`                     | baseline `e4becbee`              | aborted at 5,000: serial matcher 0.6 devices/s, 28,821 rows written per device, `GetFleetSummary` >30 s                   |
| `ramp-a3` `3ecfe5de`, `ramp-a4` `f24bc8eb` | finding sets                     | 5,000 snapshots complete; advisory coverage 70%, and `GetFleetSummary` >30 s from WAL contention with PostgreSQL defaults |
| `ramp-t1` `7c2ceb16`                       | + tuning, archive fix            | 10,000 passes (sync/work p99 48/46 ms) but `GetFleetSummary` p95 679 ms                                                   |
| `soak-10k` `acdb2eb9`                      | same                             | 2 h steady state clean, harness-failed: the cold evaluation drain took 6.5 min                                            |
| `ramp-v2-retrystorm` `c65987f4`            | single-flight sets               | cold drain throttled by 40001 retries during enrollment                                                                   |
| `ramp-v4` `3e859f09`                       | busy-skip `75f784cd`             | 10,000 passes, cold drain 150 s; `GetFleetSummary` p95 1.41 s                                                             |
| `soak-v4` `bf9009cb`                       | recent actions cached `11bf452d` | 2 h at 10,000 **passes**; `GetFleetSummary` p95 still 1.24 s                                                              |
| `ramp-v6` `7ae52f51`                       | console pool `997577e8`          | **10,000 passes, `GetFleetSummary` p95 236 ms**; 20,000 fails on device admission                                         |
| `ramp-v7-pool16` `a7370cf4`                | same, pool 16                    | 20,000 fails: protocol clean, but cold drain 390 s, `GetFleetSummary` p95 4.8 s, `AuthorizeResourceStart` p50 3.6 s       |
| `soak-v5` `05dd9534`                       | console pool `997577e8`          | **2 h at 10,000 passes** (final code)                                                                                     |

Passing 10,000 plateau (`ramp-v6`, final code): sync/work p50/p95/p99 13/60/79 and
10/57/82 ms; zero non-retryable errors; 9,937 of 10,000 recurring snapshots
(99.4%); 500 signed service cycles. The whole cold-enrolled fleet was evaluated
210 s into the plateau, and coverage afterwards stayed ≥98.2%. `GetFleetSummary`
p50/p95/p99 was 207/236/466 ms, within the 500 ms ordinary admin-read budget.
Mean server CPU was 0.95 cores, peak server RSS 3.21 GB and database growth
4.4 GB per 11 minutes. Retryable `admission_rejected` affected 5.1% of trust
polls and 5.1% of syncs; agents defer and retry on their normal cadence.

Two-hour soak at 10,000 (`soak-v5`, final code, pool 8 plus console pool 4,
tuned):

- 115,301 of 115,663 recurring snapshots (99.69%), 4,000 signed cycles and zero
  non-retryable errors.
- Sync/work p50/p95/p99: 16/61/74 and 12/56/75 ms.
- `GetFleetSummary` p50/p95/p99: 213/298/423 ms over 240 reads, with no failed
  read.
- The fleet was fully evaluated 180 s into the plateau, and coverage stayed
  ≥98.2% for the remaining two hours.
- Server CPU averaged 0.95 cores. RSS was flat after warm-up (3.29→3.32 GB).
- The database grew from 14.7 to 15.6 GB over the second hour.

Record SHA-256 `05dd9534ca8b725868b0ff89da056811dbddba8de1a339ed490d6bf42f380a33`,
server `997577e81e841d95a7f3cd2c774f9d5a6c065adc8fffe0ec7927e9b51dbeac3f` and
generator `60db3bff4469265ff7ff7b2241f6fa4451ee612a5ae9b28547ce3785a6169286`
(main `252d0163`). Full record hashes: `ramp-v6`
`7ae52f51e6b9be7b5088699f73c682330d0b5843a50fb05dc21c42d81cdb8601`,
`ramp-v7-pool16` `a7370cf4fdddf1f2b4054a92e967e6297e62b4aeba363c9287e531f850e2459e`,
`before-5k` `6d9fceb40452a1bea0c8fc430a03033761465ee7211ece6a1efb00b00900c0f5`.

20,000: at pool 8, device admission (64 in flight) rejected 48% of syncs and
snapshots reached only 73.5% (`ramp-v6`). At pool 16 (`ramp-v7-pool16`, 128 in
flight) the device protocol itself held: 100% snapshots, sync/work p99
42/41 ms and all 1,000 signed cycles. It failed elsewhere:

- The cold evaluation of 20,000 simultaneous enrollments finished 390 s into the
  plateau, past the 300 s warm-up.
- The four-connection console pool's background refresh fell behind, giving
  `GetFleetSummary` p95 4.8 s and one 10 s timeout.
- `AuthorizeResourceStart` p50 was 3.6 s.

The knee is therefore between 10,000 and 20,000. Above 10,000 use the
scale-out profile below (measured to 20,000).

Fixes, each with regressions:

1. Advisory finding sets (migration `00019`) replace per-device materialized
   findings.
2. Missing sets are built once (single-flight) outside device transactions. The
   previous design livelocked a cold mass enrollment and starved the pool.
3. The evaluator skips devices whose row is being updated (`FOR UPDATE SKIP
LOCKED`) instead of failing with 40001. It runs four workers with jittered
   retry and continues past isolated failures.
4. A refresh interrupted by shutdown no longer counts as an attempt; previously
   it suppressed every refresh for the 6 h interval.
5. OSV archive downloads have no two-minute whole-request cap; the 780 MB export
   failed twice on dgx21. They report watchdog progress instead.
6. Device admission scales with the pool, 8 per connection within 64–512, with
   a 16-request admin reserve. The agent treats `admission_rejected` as a
   deferral and stops the current flush.
7. `GetFleetSummary` serves a ≤30 s background population for unrestricted
   readers, including recent actions.
8. A separate console/identity pool (`database.admin_connections`). Each admin
   RPC made about seven sequential pool acquisitions, which queued behind device
   traffic.
9. Harness corrections: dpkg source identity, per-device inventory phase, upload
   retry at the agent's flush cadence, and recorded summary failures.

**Tuning guidance (8 vCPU / 32 GiB single host).** Keep the database pool at 8
and the console pool at 4. Pool 16 admitted 20,000 devices' traffic but made
console reads and signed starts slower. Configure PostgreSQL with at least the
qualified settings:

- `shared_buffers=8GB`, `effective_cache_size=20GB`, `wal_buffers=64MB`
- `max_wal_size=16GB`, `min_wal_size=2GB`, `checkpoint_timeout=15min`,
  `checkpoint_completion_target=0.9`, `wal_compression=lz4`
- `work_mem=16MB`, `maintenance_work_mem=1GB`,
  `autovacuum_vacuum_cost_limit=2000`
- `effective_io_concurrency=200`, `random_page_cost=1.1`

Keep `fsync`, `synchronous_commit` and `full_page_writes` on. With PostgreSQL
defaults, `GetFleetSummary` exceeded 30 s at 5,000 devices on WAL contention.
Size `max_connections` for both pools per replica. Budget about 3.3 GB of server
RSS and about 16 GB of database at 10,000 devices with 2,000-package
inventories. A cold enrollment of the whole fleet is evaluated within about
four minutes at 10,000 devices. Above 10,000 devices use the scale-out profile.

#### Measured scale-out limit: 20,000 devices (three replicas, two hosts, real feeds, 2026-10-12)

**Published scale-out limit: 20,000 enrolled devices with three `lindmd`
replicas and one PostgreSQL**, sized as below, for the same workload, feeds and
SLO gates as the single-host limit. Each replica keeps the default device pool 8
(admission 64) and console pool 4. This is a capacity topology, not database
HA: the single PostgreSQL is a single point of failure, and failover under this
load is not qualified (see the replicated failover laboratory below). Also not
qualified: more than 20,000 devices, rollout-bound dispatch at this rate (it
keeps the exclusive targeting fence; the workload used direct assignments), a
24-hour soak, and the other exclusions of the single-host limit.

| Devices | `lindmd` replicas                                    | Pools per replica                                                                              | PostgreSQL                                                                       | Measured                                                                                |
| ------- | ---------------------------------------------------- | ---------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------- |
| 10,000  | 1 × 4 vCPU (single-host profile above)               | device 8, console 4                                                                            | 4 dedicated vCPU, tuned as above, durable NVMe                                   | `soak-v5`: 2 h pass                                                                     |
| 20,000  | 3 × 4 vCPU on ≥2 hosts behind TCP/TLS-passthrough LB | device 8, console 4 (`max_connections` ≥ 3 × 13 plus admin); `inventory_budget_bytes` ≥ 20 GiB | 4 dedicated vCPU, same tuning, durable NVMe with ≥1,400 synced writes/s headroom | ramp + 2 h soak pass; ≤1.2 cores and ≤2.3 GB RSS per replica; ~33 GB database after 2 h |

Topology: PostgreSQL 18.6 on dgx21 CPUs 15–18 on an owned NVMe-backed loop/XFS
filesystem with durable fsync; replica1 on dgx21 CPUs 5–8 and replica3 on dgx21
CPUs 9–12; replica2 on dgx20 CPUs 5–8, connected to PostgreSQL over the
200 Gb/s direct link (verified TLS, `169.254.40.186`). Pinned HAProxy
(`haproxy:3.2@sha256:89c31eab…`, 3.2.25) on dgx21 balances admin and device TLS
connections without terminating them; backend connection counts stayed equal
(15,667/15,666/15,666 at 20,000). Normal leader-only jobs remained exclusive. The
generator ran on dgx20 CPUs 0–4,10–14. The `advisory-maintenance` leader
refreshed the real Ubuntu OSV export of the single-host run and all replicas
evaluated against it. Records are under
`~/.cache/lindm-scaleout-20261011/records/` (copied from dgx21).

| Run (record, SHA-256 prefix) | Server                                  | Result                                                                                                                                |
| ---------------------------- | --------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| `ramp-before-2r` `5f48cfe3`  | baseline `101460a8`, 2 replicas         | 10,000 fails: `AuthorizeResourceStart` p95 3.0 s; cold fleet evaluated 120 s into the plateau by the leader alone                     |
| `ramp-after-3r` `88c4dd9b`   | + claimed replicated evaluation         | fleet evaluated before the plateau began; 10,000 still fails: start p95 1.9 s on the assigning actor's principal row and console pool |
| `diag2-10k` `c55b4c3d`       | + shared authority fence (instrumented) | start p95 1.24 s; fresh directory observations still queued one principal write each                                                  |
| `diag3-10k` `0eb55e5c`       | + observation rounds (instrumented)     | **10,000 passes**; start p95 382 ms                                                                                                   |
| `ramp-final-3r` `8efc08c1`   | uninstrumented                          | 10,000 passes; 20,000 fails: start p95 1.9 s on the global targeting fence, one 10 s `GetFleetSummary` timeout                        |
| `ramp-final2-3r` `804c66dd`  | + shared targeting fence                | 20,000 fails narrowly: start p95 1.22 s, audit-chain head held through relock statements                                              |
| `ramp-final3-3r` `8e14dc9e`  | + audit last, `7ea79bab` (`9ec9c2e1`)   | **10,000 and 20,000 pass**                                                                                                            |

Passing 20,000 plateau (`ramp-final3-3r`): sync/work p50/p95/p99 7/34/104 and
1/21/95 ms; zero non-retryable errors; 21,903 of 21,903 recurring snapshots and
all 1,000 signed service cycles; `AuthorizeResourceStart` p50/p95/p99
473/870/1005 ms; `GetFleetSummary` p50/p95/p99 194/261/263 ms over 22 reads with
no failure. The fleet's cold evaluations completed during enrollment (19,958 of
20,000 at the first plateau sample) and coverage stayed ≥99.67%. Retryable
`admission_rejected` affected 2.7% of syncs and 6% of start requests; agents
defer as designed. At 10,000 the same run gave sync/work p99 20/11 ms and start
p95 110 ms with no admission rejection.

Two-hour soak at 20,000 (`soak-final3-3r`, same binary and topology, cold
enrollment of all 20,000 devices in 690 s):

- 233,757 of 234,652 recurring snapshots (99.62%), 8,000 signed cycles and zero
  non-retryable errors.
- Sync/work p50/p95/p99: 10/22/58 and 1/13/40 ms. `AuthorizeResourceStart`
  p50/p95/p99: 117/705/952 ms over 8,137 calls.
- `GetFleetSummary` p50/p95/p99: 255/432/2,244 ms over 240 reads (max 4.96 s),
  with no failed read.
- 19,969 of 20,000 devices were evaluated at the first plateau sample; coverage
  stayed ≥99.30%.
- Replica CPU averaged 0.64, 0.64 and 1.16 cores; RSS was flat over the second
  hour (2.25–2.27 → 2.27–2.29 GB). The database grew from 31.9 to 32.7 GB over
  the second hour.
- The default 10 GiB `inventory_budget_bytes` filled: 62,714 snapshot starts
  (21%) were deferred with retryable `inventory_budget` and completed later.
  At 20,000 devices set the budget to at least 20 GiB; that larger value was not
  measured.

Record SHA-256 `69077bcdfbbd762f77d0db4c8fdebcf8d01777222ced407d8d6e8e25a472cb05`,
ramp `ramp-final3-3r`
`8e14dc9e1d93929b21a55925782f963dc326b07c0d981b6afed4838e8979ade6`, server
`7ea79bab564af53aa3a7b5187655d45721a7a4001ceec33c6df108e9e1acc2be` (all three
replicas), generator
`3bf4b620731ab829062616a056d274b900881a71b577ac12e01df3387b1ed86b` (worktree
commit `9ec9c2e1` on `101460a8`). dgx21 also ran other agents' work, with a load
average up to 16 during the soak; host samples are in each record.

Product fixes, each with regressions:

1. Advisory evaluation is a replicated job (key `0x6c696e646d000003` retired).
   Replicas claim disjoint batches in `advisory_evaluation_claims` (migration
   `00032`, `FOR NO KEY UPDATE SKIP LOCKED`, 165 s expiry); claims only
   distribute work. A transaction-scoped advisory lock lets one replica build a
   missing finding set while others defer its devices.
2. The evaluator's device binding runs `READ COMMITTED` and appends its audit as
   the last statement, so a committed unrelated audit no longer aborts it with 40001. The hash chain and its head lock are unchanged.
3. Fresh authorization joins only a later observation round per actor and
   replica: one directory read and one principal write serve all callers that
   arrived before the round started.
4. Resource minting and starts hold the actor's principal `FOR SHARE`, and
   unchanged observed groups are not rewritten.
5. Non-rollout dispatch holds the targeting fence `FOR SHARE`; rollout-bound
   dispatch and targeting writers stay exclusive.
6. Mint and start append their audit as the last statement before commit.
7. Harness: owned three-replica topology, remote replica custody without
   reading a non-dumpable process's executable link, and IPv4 link-local direct
   links.

At 20,000 the next limits are visible: the NVMe loop device carried
1,200–1,400 synced writes/s at 93–96% utilization, and the remaining lock waits
are the global `inventory_reservation` row and the audit-chain head, both held
through a WAL flush. More replicas do not raise this limit; faster durable WAL
storage or sharding those two counters would.

#### Advisory refresh sizing and reproducible measurement

Feed refresh is CPU, temporary-storage and PostgreSQL write work, separate from
steady-state device evaluation. Only the `advisory-maintenance` leader runs the
scheduled refresh. It processes at most two sources concurrently; OSV archives
use at most four file workers per source, capped by `GOMAXPROCS`. Results reach
publication in archive order. Leadership cancellation joins all source/file
workers and does not postpone the next leader's attempt.

Publication uses COPY batches of at most 4,096 claims or 8 MiB of encoded
payload, plus at most one 64 KiB claim, with one reusable payload buffer per
active source. PostgreSQL still deduplicates exact claims and atomically switches
the verified generation. Per-record/archive/product-index limits, disk-backed
Red Hat reconciliation, the five-minute no-progress watchdog and two-hour
overall ceiling remain enforced. Allow temporary space for each concurrently
active archive and its bounded reconciliation stage; increasing worker count
does not authorize a larger archive or remove the database's write budget.

Use the maintained real-recording benchmark, not synthetic JSON throughput:

```sh
go test ./internal/devlab -run '^$' -bench '^BenchmarkRecordedFeed$' \
  -benchtime=1x -count=1 -timeout=3h -args \
  -feed-cache /private/feed-cache -feed-manifest /private/manifest.json \
  -feed-sources /private/sources.json
```

`lab feeds sources` emits an explicit six-family source configuration.
`lab feeds record -repo REPO -lindmd BINARY -sources SOURCES -cache CACHE
-manifest-out NEW_MANIFEST -record NEW_RESULT` acquires vendor HTTPS bytes,
verifies and publishes them into an owned disposable database, then records
their immutable URL/size/SHA-256 identities. SUSE's default is one real signed
CSAF document, not its complete ecosystem; Arch remains partial coverage.
The shared development PostgreSQL fixture and protected credential files are
required; never supply a DSN in arguments or environment variables.

For before/after comparisons use `lab feeds replay` with the same arguments,
replacing `-manifest-out` with `-manifest`. Build both `lab` and a stamped
`lindmd` from each checkout. Replay is digest-checked local recording delivery
over verified loopback TLS, with no vendor requests; it is **not current
freshness or vendor TLS evidence**. It exercises the real parser, reconciliation,
COPY, deduplication and fenced publication. Compare `publication_sha256_v1`
for every feed, not just counts: the digest includes exact stored claim bytes,
their indexed fields, source configuration, artifacts, rejection metadata,
signed snapshot time and completeness, excluding random generation IDs and
refresh-clock timestamps. A digest mismatch fails the performance qualification.
The Go benchmark reports parsing/encoding allocations separately from the
full-refresh command's database timing. Keep `/usr/bin/time -v` results alongside
the JSON to disclose process-tree CPU/RSS; PostgreSQL resources are separate.

Measured on 2026-10-11 (Go 1.26.9, `GOMAXPROCS=8`, shared dev PostgreSQL, two
interleaved rounds over one real recording of all six source families:
4,301 Fedora, 1,932,865 Ubuntu, 2,157,314 RHEL, 2,512 Debian, 66,813 SUSE and
7 Arch claims). Refresh duration fell from 1,023.9 s / 658.1 s to
307.2 s / 194.1 s (3.33x / 3.39x); process-tree peak RSS rose from about
336 MB to 378 MB. Every feed's `publication_sha256_v1` was identical between
the two implementations in both rounds. Size advisory-maintenance hosts for
two concurrent sources and roughly 400 MB of lindmd RSS during refresh.

Profiling is explicitly operator-enabled through protobuf `profiling`
configuration and a separate literal-loopback HTTP listener, disabled by default.
Only bounded CPU/mutex/block captures are exposed, not the public/admin/device
muxes. Mutex sampling restores its previous runtime setting; this listener is
the sole block-sampling owner and disables block sampling on shutdown.
`lab load -pool-size N -profile-dir NEW_DIR` records private profile artifacts and
owned-database query/lock diagnostics. The development PostgreSQL must preload
`pg_stat_statements`; the harness creates its extension only in its owned database.
Long plateaus repeat CPU/mutex/block captures approximately every 30 minutes
after the initial nine-minute inventory-window capture, preserving separate
elapsed-time-labelled artifacts so retention-age failures remain diagnosable.
Top-query records contain query IDs, cumulative counters and bounded sanitized
normalized DML, never utility statements or raw bind values. Comments, quoted
identifiers and literals are removed or redacted; malformed, unsupported and
oversized statements report explicit text omissions. Activity retains safe sqlc
query names where available. PostgreSQL may discard leading sqlc comments from
`pg_stat_statements`, so those comments are not used to identify top queries.
`-stage-duration 2h` selects a soak; lab signing authority lasts four hours.
Profiling and optimization must retain before/after evidence rather than infer
a higher limit by widening admission alone.

Observability: request/error/latency, job age and lease churn, enrollment/auth denials,
renewal failures, last-seen/freshness, provider outcomes, rollout error rate, database
pool/query/lock pressure, disk/artifact growth, backup lag, certificate/TUF/feed expiry,
and offline-import status. Use structured redacted logs and OpenTelemetry. Device IDs
belong in logs/traces, not unbounded metric label cardinality.

Default retention proposal: 30 days detailed observations, 90 days action outputs,
365 days security audit, and configurable device-record retention after retirement.
Recovery secrets live only while required by approved policy. Audit/legal hold takes
precedence over ordinary purge, with encryption and restricted access. Capacity sizing
must use these retention settings, not a nearly empty demonstration database.

Active logind session usernames, session class/type, seat and remote flag are
personal data. They are collected only as bounded current host inventory, not
login history, and are visible only through device-scoped `fleet.read` access
like other inventory. Collection and per-field availability remain explicit;
an unavailable read must not be interpreted as no logged-in users. Retention
follows inventory snapshot retention, including applicable backup and legal-hold
policy, with no independent longer-lived session-identity store. The current
host snapshot replaces these fields on the next accepted report, including a
failed collection; inventory does not retain earlier successful identities as
fallback values. Limit fleet-read scopes and backup access accordingly.

Incident runbooks are release artifacts: credential/release-key compromise, malicious
package/policy, lost recovery key, mass lockout, failed migration, ransomware/restore,
expired offline trust, package-manager failure and overloaded reconnect storms. Each
has detection, blast-radius containment, break-glass, recovery and evidence preservation.

### Replicated failover laboratory

`lab ha -repo FIXTURE -lindmd RELEASE_N -upgrade-lindmd RELEASE_N1 -record NEW_FILE`
is the maintained HA lane. It owns every resource it starts: two pinned
PostgreSQL 18.6 containers (primary plus a `pg_basebackup` standby with
synchronous commit, verify-full TLS replication, durable Docker volumes), a pinned
HAProxy 3.2.25 LTS container configured exactly as in §4, two `lindmd` replicas
with LOCAL password/WebAuthn authority, integrations and reports enabled, and a
fresh multi-host database. Everything binds dynamic loopback ports; development
trust in `FIXTURE` is read-only, and no endpoint or credential override exists.
`-devices` (4–256, default 24), `-phase-duration` (20 s–30 min, default 1 min) and
`-seed` bound the run. The two releases must differ in digest and version.

Devices are the capacity lane's real-protocol simulated agents: enrolled with
one-use grants and Ed25519 mTLS identities, verifying real intent/start
signatures and signing challenges and attestations through the balancer. Effects
are a journal, not host changes: each device records a restart or service
execution **before** reporting it and never repeats a journaled action, as the
protected executor does. Throughout every phase the administrator stream issues
one restart per second to an idle device and spreads each device's first service
assignment across the run; ambiguous mutation outcomes are retried with the exact
same request ID until the server answers definitively.

Phases, in order: steady load; **crash** — wait until restarts are executing but
unreported, SIGSTOP replica `a` for three seconds so requests routed to it are in
flight, then SIGKILL it; restart `a` on release N; **database failover** — wait for
in-flight restarts, SIGKILL the primary container and `pg_ctl promote` the standby;
**rolling upgrade** — SIGTERM, start N+1 and wait for both balancer backends to
report the replica UP, first `a`, then `b`; quiesce until every accepted restart
finishes. A run passes only if all checks hold:

- the crash interrupted device RPCs while restarts were executing;
- the standby was a streaming synchronous replica before the primary failed;
- both replicas finish on N+1 and neither exited without a laboratory signal;
- no restart or service action executed twice and the server lists no action no
  request accepted;
- every accepted restart is server-verified SUCCEEDED with the device's new boot
  ID and every accepted assignment is the device's head with a converged resource
  whose every authorized start the device executed exactly once;
- no protocol violation and no definitive administrator rejection;
- exclusive-job leadership, reconstructed from replica logs and orchestration
  events, never overlaps outside the database-failover window or longer than
  10 seconds, every exclusive job is held at the end and the 1 Hz `pg_locks`
  samples show no unheld gap above 2 minutes.

Records include binary/generator SHA-256 and versions, image digests and HAProxy
version, every event, per-phase RPC counts/codes/latency, the failover timeline,
leadership intervals, timestamped HAProxy health transitions and, on failure,
bounded ERROR messages of replicas that exited.

#### Observed result, 2026-10-11

Source: checkpoint `a98feef` plus private-worktree patch SHA-256
`7aee9b016e272f7defb9fb65adc7f47308dab880332ce4eb28a41497b7c61f1d`. Static
`lindmd` 0.1.0 SHA-256
`b7b92115ec6a3320b22600a98997860c7fce117f5eb40a7dfdd13dac39687949`, 0.1.1
`b86e36de0d2c63911191cdb9df557f2f0300ac128d21764579ce3fc4c9a70d57`, `lab`
`2059ce3377453f9d52fcec5c8294882a05b0735adbfef2f2384003e8aa359144`. Host:
i7-13700K (24 logical CPUs), 62 GiB, Linux 7.0.0-34, Docker 29.5.0, shared with
other laboratory work; all components co-located on loopback. The patch and all
five executables (including the negative-control pair) are retained under
`artifacts/ha-20261011/`.

`artifacts/ha-failover-20261011.json`, SHA-256
`2e08c0ca74a23d7e7bc77a403b7b03cd68868d507bcab5e1df4b4d80d818390d`, **passed** all
eleven checks with 24 devices and one-minute phases (9,744 device/admin RPCs after enrollment):

| Fault                         | Observed                                                                                                                                                                                                                          |
| ----------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Replica crash during dispatch | 3 restarts executing at SIGSTOP; 12 device RPCs (`unavailable`) interrupted by SIGKILL and retried through `b`; `b` took all four exclusive jobs 1.5 s after the kill; 63 restarts accepted and finished in that phase            |
| PostgreSQL failover           | Synchronous standby promoted and writable 384 ms after the primary SIGKILL; 22 RPCs failed `internal` and were retried; both replicas kept serving; exclusive jobs re-led 0.7–2.6 s after session loss; 60 accepted / 62 finished |
| Rolling upgrade 0.1.0→0.1.1   | Zero RPC errors in both steps; leadership handed over by explicit unlock; both replicas on 0.1.1 at the end                                                                                                                       |
| Totals                        | 279/279 accepted restarts server-verified SUCCEEDED with exactly one device execution; 24/24 assignments converged exactly once; 303 admin requests, 0 rejections; 0 duplicate effects; longest unheld job gap 4 s                |

Negative control: the same `lab` against checkpoint `a98feef` without this
change (0.1.0 `a024e7a6dff2bcfb105a25ba8b73b86a39843f0a9420cdfc44c1bbb27e584c2d`,
0.1.1 `5311a174b203f0d03c333153389e85539d04d744a7d8d5e438ea5fba19fc4d64`),
`artifacts/ha-failover-baseline-a98feef-20261011.json`, SHA-256
`faf1ccf116a3d2a5f976fc5a7688a1eedd54dbc1e6a6a5450b44136fc7e6afd8`, **failed**:
both replicas exited with `integrations: delivery store unavailable` when the
primary died, every RPC in the failover phase failed and the rolling upgrade
could not start. That was the defect: background-job store errors terminated the
process, and every replica ran every background job. Superseded tuning records
are retained under `artifacts/ha-superseded-20261011/`.

This is laboratory evidence for the replica, balancer, synchronous-standby and
job-leadership contract, not a capacity, soak or 100,000-device result. It does
not cover network partitions or an unfenced old primary, re-attaching a standby
after failover, shared artifact storage, worker-only processes, schema-changing
rolling upgrades, native agents (devices are simulated), separate hosts or the
dedicated reference hardware. Recovery here is seconds against the five-minute
target; a production claim still needs the replicated L18 load/failover gate.

## 7. Agent updates from your server and release compatibility

The customer's `lindmd` also serves its signed TUF update repository on its
administrative TLS origin at `/updates/`, separately from native first-install
metadata at `/repo/`. Add the following to the strict protobuf JSON server config
and apply the normal `lindmd migrate -config FILE` before starting the server:

```json
{
  "releaseRepository": {
    "directory": "/var/lib/lindm/releases",
    "signing": {
      "directory": "/var/lib/lindm/release-online-signing"
    }
  }
}
```

For native systemd hosting, provision the repository and online custody as
`lindmd:lindmd`, directories `0700` and key files `0600`; never give the daemon
offline root/targets keys. The default unit is read-only. If enabling online
rollout publication, create an operator drop-in
`/etc/systemd/system/lindmd.service.d/releases.conf` with:

```ini
[Service]
ReadWritePaths=/var/lib/lindm/releases
```

Then run `systemctl daemon-reload` and restart after validating configuration.
The directory must already exist. Keep `ProtectSystem=strict` and all other
confinement; grant only this server's release-content subtree, never `/etc`, key custody
or all of `/var/lib`. Read-only serving needs no writable drop-in. With OCI, mount
the release-content directory as a dedicated writable volume only for online publication,
and online signing files separately read-only; retain the read-only rootfs and
nonroot identity. Back up published metadata/targets and custody separately.

The TUF subtree contains only non-secret `metadata/` and `targets/` material;
native first-install repositories occupy `repo/`. Signing custody must resolve
outside that directory. The optional signing directory holds
distinct protected PKCS#8 `rollout.pem`, `snapshot.pem` and `timestamp.pem` files.
`root.pem` and `targets.pem` stay offline and must not be present in the configured
online directory; startup rejects either filename, including a symlink. Do not
mount or grant the server access to offline custody. The five roles are root,
top-level targets, delegated rollout, snapshot and timestamp. Offline targets
authorize package/native-signature bytes and the exact release identity,
architecture, native version and compatibility contract. The rollout delegation
is restricted to `channels/*.json`; online custody can change pause/cohort and
select already authorized releases, not add packages or rewrite their contracts.
Omit `signing` for read-only hosting. The handler permits GET/HEAD only, has no
indexes, and rejects symlinks, private filenames and path traversal.
It does not require an agent session:
unsupported agents must still be able to retrieve a verified update. TLS is
transport protection, never a substitute for the agent's pinned TUF root.

The generated `lindm.releasemanagement.v1.ReleaseManagementService` is mounted on
the same administrative origin. Use a normal authenticated session and CSRF
header, with unrestricted `release_updates.manage` permission (owner/admin by
default). This permission is independent of execution-root custody. There is no
unauthenticated mutation endpoint.

- `GetRollout` reads the real signed channel and any pending publication request.
- `SetRollout` accepts `requestId`, `ring`, `expectedGeneration`, `paused`,
  `eligiblePercentage` and an audit `reason`. It commits authorized intent and an
  audit event before asking the TUF publisher to sign new metadata. Only a
  completed real publication is returned as the published channel. An interrupted
  or failed call leaves a pending intent; repeat the exact request ID and payload
  to reconcile its signed publication token. Changed payloads conflict. A pending
  ring serializes other changes. Do not run an independent publisher against that
  ring while a management request is pending.
- `RegisterReleaseSeries` accepts `requestId`, `reason`, and a `series` containing
  `major`, `minor`, `releasedAt`, `supportUntil`, `minimumProtocol` and
  `maximumProtocol`. History and protocol bounds are immutable; support dates may
  only be extended. New records need at least 90 days of announced support.
- `GetCompatibility` returns the actual server linker stamp and implemented
  protocol, plus durable released-series history. The current and previous two
  released minor series remain supported; older series remain supported through
  their recorded end date. Registering a newer minor gives the former three
  series at least 90 additional days before retirement.

Register the actual server and agent released series before enabling executable
work. Production always enforces this gate; unknown/development stamps and missing
agent reports do not become supported by inference. The executor signs its own
release/protocol into session acquisition, and a same-boot package replacement
acquires a new session when that protected build identity changes. A claimed
release must have a registered minor and a compatible implemented protocol.
Inventory, renewal, update retrieval and already-issued action/result recovery
remain available; new service/device intents and start authority are denied for
unsupported sessions. Compatibility admission is not native capability evidence.

Native laboratories use `devlab.OpenReleaseAuthorityFixture` for a disposable
local-auth server, five isolated TUF role keys and a privately re-signed bootstrap.
Full lab custody remains in `release-custody` for explicit offline-authorized
publication and adversarial helpers. The server receives only the three online
keys in the separate `release-online-custody` directory.
It never modifies `.cache/dev` trust. Ordinary `AuthorityFixture` setup registers
the actual stamped server through the real API; unstamped server binaries fail
with the linker-stamp prerequisite. `fixture.RegisterRelease(ctx, version)` (or
`OwnerSession.RegisterRelease` for an explicitly owned shared development session)
registers the actual agent series under test. The returned release publisher
publishes initial artifacts; `fixture.SetRollout` exercises the audited API.
