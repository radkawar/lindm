# Security, deployment and operations

Status: required design and acceptance targets, not measured service guarantees.
See [architecture](architecture.md) for identity, authorization, protocol and journal
invariants, and [verification](verification.md) for the required evidence.

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

### Offline owner execution delegation

`lindmctl execution delegation sign` is an offline owner operation, not an admin
login or a server-side capability upgrade. It makes no network requests and never
loads development keys. Run it on the owner's isolated signing workstation with
the real deployment's authenticated execution root, associated quorum-signed
bootstrap, and sufficient distinct offline root signers. Private keys remain
offline; do not copy them into the server, executor, lab, or command arguments.
The software signer accepts one unencrypted Ed25519 PKCS#8 `PRIVATE KEY` PEM
block per `-signer` file. It does not claim HSM custody.

All input files, including public root/bootstrap and the declaration, must be
singly linked regular files owned by the invoking user with mode `0600`, in
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

| Operation          | Exact capability               |
| ------------------ | ------------------------------ |
| Rotate escrow      | `device.escrow-rotate.v1`      |
| Bind TPM2          | `device.tpm2-bind.v1`          |
| Lock sessions      | `device.lock-sessions.v1`      |
| Release lock       | `device.release-lock.v1`       |
| Quarantine         | `device.quarantine.v1`         |
| Release quarantine | `device.release-quarantine.v1` |
| Crypto erase       | `device.crypto-erase.v1`       |
| Sanitize           | `device.sanitize.v1`           |
| Restart            | `device.restart.v1`            |
| Shut down          | `device.shutdown.v1`           |
| Refresh inventory  | `device.refresh-inventory.v1`  |
| Systemd services   | `systemd.service.v1`           |
| Offline enrollment | `enrollment.offline.v1`        |

For example, selecting only `["device.refresh-inventory.v1"]` on both plan and
start delegates permits that protocol without granting restart or shutdown.
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
  -signer /offline/lindm/owner-a.pem \
  -signer /offline/lindm/owner-b.pem \
  -previous-version 7 -minimum-recovery-epoch 3 \
  -out /offline/lindm/delegation-v8.dsse.json
```

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
bounded, descriptor-pinned vendor-link resolver retains its existing checks on
both source and resolved ancestry. Private state/spool and temporary-parent APIs
retain their separate caller-ownership and sticky-directory protections; their
final private directory still requires its exact owner and mode `0700`.
Configuration files, secret files and executable files retain their stricter
file-specific permissions; the group-zero exception is only for directories.

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
step-up. Set `escrow.reveal_approval_required` when a second authorized human
must approve the exact reveal request. The returned 64 hexadecimal characters are
the literal unlock passphrase, not a hex encoding to decode into binary. Reveal
responses are no-store; the console dismisses its memory-only display and never
caches secrets. Record the actual cold-boot unlock separately from escrow status.
A same-boot key test does not qualify cold-boot recovery or TPM PCR behavior.

Suspected key disclosure requires a new recovery rotation and custody incident
handling, including backup/header-copy disposition. Deleting an escrow database
row cannot revoke a key copied from a backup. Do not claim crypto erase when a
retained header plus retained key can still recover the data.

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

Configuration is typed, validated and documented. Secrets may come from protected
files or approved secret managers, not command-line flags. Startup refuses ambiguous
listener trust, default credentials, unsupported schemas and unsafe production TLS.
Readiness covers DB/migration/key/artifact availability; liveness does not depend on
a remote IdP being online. Metrics/admin diagnostics are private and authenticated.

### Native single-host installation

The `lindmd` DEB/RPM contains the embedded-console executable at `/usr/bin/lindmd`,
`lindmd.service`, and a separate, operator-invoked `lindmd-migrate.service`.
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

Build with `lab packages build-server` using the same explicit signing
custody as agent builds. Authenticate DEBs through the signed APT repository with
a separately obtained pinned `Signed-By` key; `dpkg -i` is not signature verification.
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
3. Make runtime configuration/key files `lindmd:lindmd` mode 0600 under
   root-owned non-writable directory ancestry. `/etc/lindm` may be root-owned 0755;
   secrets themselves must have no group/other permission bits. The checked loader
   rejects symlinks, replaceable ancestry and unsafe file permissions. Store an
   explicit PostgreSQL URL in `database-url`, including `sslmode=verify-full` and
   `sslrootcert=/etc/lindm/transport-ca.crt`. Do not set `PG*` environment variables.
4. Put a separately validated config at `/etc/lindm/migrate/server.json`, with
   `database.migration_url_file` pointing at the migrator URL, and its database TLS
   trust/client material in the same directory. Own these mode-0600 files by
   `lindmd-migrate`; keep the directory traversable only by root and that account.
   The runtime service cannot access this directory. Migration resolves only its
   database resources; it does not require access to the server/device private keys.
5. Run `systemctl start lindmd-migrate.service` explicitly and inspect its exit
   status/journal. Revoke runtime INSERT/UPDATE/DELETE and sequence privileges on
   migration bookkeeping (`public.goose_db_version`); retain SELECT for startup
   schema checks. Run `runuser -u lindmd -- lindmd check-config -config
/etc/lindm/server.json`. This checks configuration/resources, not DB connectivity.
6. Run `runuser -u lindmd -- lindmd bootstrap-owner -config /etc/lindm/server.json
-username owner` in a private terminal. It prints a one-time enrollment secret;
   do not capture it in a journal, command argument, URL or support bundle.
   Bootstrap is one-shot, not a password-only login or a recovery bypass.
7. Run `systemctl enable --now lindmd.service`. Verify the actual TLS chain and
   `GET /healthz` and `/readyz` (204), embedded `/` (200), LOCAL `/auth/options`,
   and unauthenticated admin RPC denial (401). Visit `/enroll`, enter the secret,
   choose a password and register a user-verifying WebAuthn authenticator. The
   password plus authenticator are required for subsequent login.

Keep `journalctl -u lindmd -u lindmd-migrate` private. A successful health response
does not certify a login ceremony, device enrollment, dispatch or capacity.

After every explicit migration, remove the broad default DML grants from migration
metadata before starting the server. Execute this as the migrator/database
administrator (substitute the actual runtime role if different):

```sql
REVOKE INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER
ON public.goose_db_version FROM lindm_runtime;
DO $$
DECLARE sequence_name text := pg_get_serial_sequence('public.goose_db_version', 'id');
BEGIN
  IF sequence_name IS NOT NULL THEN
    EXECUTE 'REVOKE ALL ON SEQUENCE ' || sequence_name || ' FROM lindm_runtime';
  END IF;
END $$;
```

Retain table SELECT so `serve` can check the exact applied migration set. On a
local PostgreSQL host, feed this SQL to `runuser -u postgres -- psql -X -v
ON_ERROR_STOP=1 -d lindm`. Schema CREATE denial alone is insufficient: a runtime
credential must not be able to forge migration history or advance its sequence.

### Upgrade, backup, restore and removal

Before changing the binary, stop `lindmd`, fence inbound admin/device traffic and
take a database **and** protected-file backup. Install the authenticated next
package, explicitly run the migration unit, check configuration, start the runtime
unit and verify HTTPS readiness plus authenticated administrator/device behavior.
Package installation never runs DDL. Retain the old binary and backup: rolling back
only the binary is safe only if its exact schema check accepts the current database.
Current greenfield migrations are create-only; no deployed schema-upgrade promise
is implied by a same-schema package upgrade.

Use standard PostgreSQL tools rather than a proprietary backup format. For a local
database, as root with the runtime stopped:

```sh
umask 077
install -d -m 0700 /var/backups/lindm
runuser -u postgres -- pg_dump --format=custom lindm > /var/backups/lindm/database.dump
tar -C /etc -cpf /var/backups/lindm/config.tar lindm
find /etc/lindm -type f -exec sha256sum {} + > /var/backups/lindm/config.sha256
find /etc/lindm -printf '%P %u %g %m\n' > /var/backups/lindm/config.inventory
```

For a remote database, use an independently protected libpq connection/service
file and `pg_dump` from a matching supported PostgreSQL client, with verify-full;
never expose a password-bearing URL as a command argument. Database roles/grants,
PostgreSQL TLS configuration, image/package digests and any separately configured
artifact volumes are additional backup inventory. Encrypt backups before off-host
storage, restrict custody, test decryption separately and retain an immutable copy.

Protected file inventory, including **every configured reference**, is:

| Material                                                                         | Required retention and custody                                              |
| -------------------------------------------------------------------------------- | --------------------------------------------------------------------------- |
| Runtime and migration JSON; deployment UUID/public origins                       | Restore exact identity, paths and listener policy                           |
| Runtime/migrator database URL files, database CA and optional client cert/key    | Separate credentials; migrator never mounted into runtime                   |
| Server TLS certificate/private key and device CA certificate/private key         | Preserve device trust; review expiry/revocation before reopening            |
| Execution root/bootstrap documents; configured plan/start private keys           | Retain exact authority; offline root/release signing custody stays separate |
| Optional OIDC and directory client secrets/trust roots                           | Reconcile with the real provider; LOCAL mode needs none                     |
| PostgreSQL data/dump, roles/grants and TLS files; artifact volumes if configured | Consistent fenced snapshot, independently encrypted backup                  |
| Package/repository signing trust and OCI digests                                 | Verify authentic recovery binaries without trusting the failed host         |

Restore initially **without any device/admin ingress**. Provision the original
database roles and dedicated service users, create a database owned by the migrator,
then feed the custom dump to `pg_restore --exit-on-error --dbname=lindm` as the
database administrator. Restore `/etc/lindm` preserving numeric ownership/modes (or
map each recorded owner to the new host's dedicated account), validate its inventory
and `lindmd check-config`, then start only on the fenced network. Do not automatically
run migrations against an unknown backup. Validate migration identity, owner/device
rows, certificates and current revocations before advancing.

The maintained VM lane destroys only its disposable database and restores the
same-epoch backup to prove binary/config/data recovery. This is **not** stale-backup
dispatch recovery or revocation reconciliation. Before production ingress is
reopened, invalidate restored sessions/challenges, reconcile independently retained
security events and all outstanding work. The global restore-hold/recovery-epoch
workflow described below is not yet qualified; keep a stale restore fenced rather
than assuming the absence of destructive operations in an early build makes replay safe.

Removal/purge stops the service and removes package-owned binaries/units only.
Operator `/etc/lindm` configuration/keys, PostgreSQL data, backups and dedicated
accounts are retained deliberately. Their irreversible deletion is a separate
operator retention decision; never delete them in package lifecycle hooks.

### OCI and Docker Compose

`deploy/server/Dockerfile` packages a statically linked, embedded-console `lindmd`
into a digest-pinned distroless non-root image. Build the console before the Go
binary; do not substitute a dev server or mount frontend source into production.
Publish and verify the organization's signed image digest before installation.
The checked-in base-image pin is not a signature on a locally built Lindm image.

`deploy/server/compose.yml` is the production single-host topology: a
digest-pinned PostgreSQL 18.6 with TLS and a named persistent data volume, separate
explicit `migrate` and `bootstrap` operations, and an unprivileged read-only server
with no capabilities. PostgreSQL has no published host port. Set `LINDM_IMAGE` to
the released digest and `LINDM_CONFIG_DIR` to a protected absolute directory.
Default runtime UID/GID is 65532; own its mode-0600 bind-mounted input files by
that numeric identity. Configure public origins/listener addresses for the
deployment (inside the container bind listeners to `0.0.0.0`). The runtime URL uses
hostname `postgres` and `sslmode=verify-full` with the separately mounted CA.
The runtime does not mount the migrator credential.

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
ON public.goose_db_version FROM lindm_runtime;
DO $$
DECLARE sequence_name text := pg_get_serial_sequence('public.goose_db_version', 'id');
BEGIN
  IF sequence_name IS NOT NULL THEN
    EXECUTE 'REVOKE ALL ON SEQUENCE ' || sequence_name || ' FROM lindm_runtime';
  END IF;
END $$;
SQL
docker compose -f deploy/server/compose.yml run --rm bootstrap
docker compose -f deploy/server/compose.yml up -d lindmd
```

Bootstrap output is intentionally not persisted by Docker's log driver; receive
its one-time secret only in a private operator terminal. Explicitly choose
`LINDM_BIND_IP` and firewall policy before exposing the admin/device ports (default
bind is loopback). Verify the HTTPS chain and readiness from the real access path.
Upgrade by stopping `lindmd`, backing up, selecting the next immutable image,
running the explicit migration and recreating `lindmd`. For Compose backup/restore,
run the same PostgreSQL tools through `docker compose exec -T -u postgres postgres`
and back up the external config directory with preserved ownership. Never run
`down --volumes` during ordinary upgrades/removal: it destroys the database.

`lab server compose -repo . -record NEW_FILE` builds and exercises this exact
topology using a uniquely named disposable project, short-lived LOCAL fixture
keys and dynamically allocated loopback ports. It is a container boot/migration
and isolation proof, not native-host, backup/restore, image-signing or HA evidence.

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
dependencies and verified lab provisioning trust are prerequisites. The generator
is deliberately co-located and is **not** the dedicated-target reference profile
above. It has no arbitrary endpoint or production-credential option.

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
cleanup now allows three minutes, still never terminating another client.

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
passed. The isolated durable ramp and two-hour durable soak have **not run**.
Consequently no higher durable single-host limit or ≥10,000-device claim is
published. Resume only after the parent releases the host's VM-priority hold.

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

## 7. Hosted agent updates and release compatibility

`lindmd` can host a previously published TUF repository on its administrative TLS
origin at `/updates/`. Add the following to the strict protobuf JSON server config
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
confinement; grant only this public repository subtree, never `/etc`, key custody
or all of `/var/lib`. Read-only hosting needs no writable drop-in. With OCI, mount
the public repository as a dedicated writable volume only for online publication,
and online signing files separately read-only; retain the read-only rootfs and
nonroot identity. Back up published metadata/targets and custody separately.

The repository contains only public `metadata/` and `targets/` material. Signing
custody must resolve outside that directory. The optional signing directory holds
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
