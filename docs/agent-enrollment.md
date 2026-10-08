# Packaged agent and native enrollment contract

Status: G2 internal qualification is complete (`cb97712`); G3 execution-trust
rotation and signed durable service execution extend that packaged agent.
The evidence ledger records exercised native runs and remaining gates, not a release
claim. This document refines [architecture](architecture.md) and
[verification](verification.md); it does not reduce the confirmed launch matrix or
replace its desktop/physical acceptance.

## 1. Process and source boundaries

Build `cmd/lindm-agent` separately from `cmd/lindmd`. The agent executable has
`executor`, `run`, `bootstrap`, `resume`, `status`, `trust-update` and typed
`service-prepare`, `service-start`, `service-status`, `service-attest` commands, plus
standalone inspection/verification. Real per-user session behavior belongs to G4.

- `executor`: root-owned Unix listener; owns sensitive identity keys, execution
  trust and journal. No TCP listener and no general command/file/signing RPC.
- `run`: dedicated unprivileged `lindm` account; outbound Connect client, native
  unprivileged observations and a separate durable observation/transport spool.
- `bootstrap`: explicit privileged operator command. It validates trusted local
  bootstrap material, requests a locally generated CSR from the executor, performs
  the one-use HTTPS enrollment and installs the verified result through root-only
  local RPC. The bearer grant is not handed to the long-running network process.
- `status`: reports durable lifecycle state and reasons, not secrets. Separate
  enrollment state, transport reachability and observation freshness.
- `trust-update -file FILE`: relays a bounded protobuf-JSON
  `UpdateExecutionTrustRequest` through the root-authenticated socket using
  `/etc/lindm/agent.json`. Root or the configured network UID may relay signed
  documents, not select trusted keys. This command never starts policy work or
  changes TLS enrollment pins.
- `service-prepare -file FILE`: relays a `PrepareServiceExecutionRequest` containing
  a signed desired intent. Root constructs the native plan and device challenge.
- `service-start -file FILE`: relays a `StartServiceExecutionRequest` containing
  separate signed start authority. Acknowledged queueing is not completion.
- `service-status -file FILE`: sends a `GetServiceExecutionRequest` for retained
  action evidence, not a fresh compliance scan.
- `service-attest -file FILE`: sends an `AttestServiceExecutionRequest` containing
  an action UUID and caller-generated 32-byte nonce. Root signs its retained
  evidence with the current device key; callers cannot supply the signed facts.

All four service commands use `/etc/lindm/agent.json` and the same root/network-UID
socket ACL; none can sign execution authority.

Keep implementation under cohesive `internal/agent` packages for local journal,
executor, transport and native observation. Shared certificate/trust contracts belong
in a focused package consumed by both server and agent, not copied validators.
Serialized configuration and local RPC are protobuf with Protovalidate. External
DSSE/TUF envelope formats remain their standard formats, not rewritten as competing
protocols. SQLite queries use sqlc's SQLite target and a pinned maintained driver.

## 2. Initial trust and protected state

The trusted installation path verifies the native package/repository signature
before executing installed code. An executable cannot establish the authenticity
of the package that supplied itself.

The operator supplies an authenticated deployment execution-root document and a
DSSE-signed bootstrap bundle. Verify the bundle against that supplied root/quorum;
never learn initial root keys from an unauthenticated response. The typed payload
binds deployment UUID, enrollment/device HTTPS origins, transport and device-CA
trust, root version/digest, separate TUF release root, validity and bundle UUID.
Use a maintained DSSE implementation; verify TUF root metadata with the maintained
TUF implementation. Root and online execution signers are not the TLS or release
signers. Local development keys are explicitly development-only.

The executor exclusively owns `/var/lib/lindm/executor` (0700), SQLite database/WAL,
keys and trust (0600). The network account cannot change or remove any of them.
Use a root-owned runtime directory/socket, `SO_PEERCRED`, a fixed service UID and
per-method root/service authorization. Enforce bounded requests, deadlines and
concurrency. Reject symlink/nonregular/wrong-owner/writable trust or state resources;
do not merely inspect a pathname and later open a different object.
SQLite resolves proc-fd paths back to ordinary paths: a pinned final descriptor alone
is insufficient. Walk and validate every ancestor before state access, rejecting
untrusted owners and non-sticky group/world-writable directories. Trusted sticky
ancestry is admissible only when each accepted child remains root/executor-owned.

Initial provisioning is explicit and transactional. Persist the enrollment attempt
UUID, generated private key, CSR, pinned trust and the pending bearer grant in
root-only state before contacting the server. The operator reads the grant from a
protected file/stdin, never an argument/environment variable. Delete the pending
grant after durable certificate installation; do not promise forensic erasure of
past filesystem/WAL copies. Its single-use, bounded server authority remains essential.
After a lost response, resume the same attempt/key instead of generating another
identity. Persist certificate installation atomically before returning success.
Verify chain, intended usage, deployment identity and exact public key against
protected pending state. Device/generation UUIDs are server-assigned and become
pinned from this authenticated response; reject replacement once pinned.

Missing/corrupt state on a previously provisioned installation means recovery hold,
not automatic database recreation. Keep a protected installation/enrollment marker
outside the journal to distinguish a new installation from lost journal state.
Native remove/purge retains replay/identity state. No reset flag bypasses revocation
and approved generation replacement. Filesystem ownership is a boundary against
unprivileged processes, not a claim against an already compromised root/kernel.

Before any external enrollment, durably create the provisioning-intent marker with
a random installation UUID and sync its parent directory, then commit matching
SQLite initialization and pending enrollment with full durability. Certificate
installation commits before acknowledgment; marker finalization is an idempotent
later step. Marker-only, database-only, mismatched UUIDs or corrupt state enter
recovery hold. An explicit root-only provisioning-resume path may finish a known
interrupted initialization; the network UID has no initialize/reset/unsigned
trust-import method. Both absent means unprovisioned, not permission for the daemon
to enroll.

Software keys are reported as software keys. No TPM assurance is inferred from a
machine having `/dev/tpm*`; TPM/non-exportability claims require their separate
provider and physical qualification.

### Execution-trust updates

`execution_trust.proto` defines separate old/new quorum envelopes for each
consecutive execution-root replacement and a current-root-signed online delegation.
The independent envelopes support disjoint sixteen-key quorums. Delegations bind
deployment/root version, deployment-global delegation version, validity, minimum
recovery epoch and exact versioned capabilities for separate plan/start roles.
Empty delegates revoke all online execution signers. Current root, TLS-CA and
release keys cannot become online execution delegates.

The current protected SQLite schema is version 3. Genuine version-1 and version-2
databases migrate transactionally after validating existing authority; original
identity/trust bytes and independent revisions are preserved. The version-1 path
adds the separately revisioned execution-trust singleton. Missing or damaged
current-schema trust is recovery hold, not an empty replacement. The executor
verifies complete root/delegation proposals before one durable commit and
acknowledgment. Wrong quorum, delegation rollback and recovery-floor regression
return `permission_denied` with `Lindm-Reason: execution_trust_rejected`, without
changing accepted authority or putting a healthy installation in recovery hold.

Only an exact retry of the last accepted request returns its original receipt.
It cannot extend expiry or reset counters. Startup, runtime loading and offline
inspection reconstruct accepted trust at its recorded acceptance time: ordinary
expiration is not corruption, but a signed-payload/counter mismatch remains held
across restart. A local clock regression blocks new acceptance, not reconstruction
of a historical receipt.

The maintained `lab vm lifecycle -execution-trust` lane exercises the installed
CLI as the network UID after upgrade. Use a genuine schema-version-1 first package
and the new second package to qualify migration. It rejects a wrong quorum and
independently root-signed delegation/recovery rollback proposals, rotates roots,
revokes delegates and compares public TLS identity/pins. After reboot and
remove/reinstall it first rejects the previously accepted rotation, then replays
the final receipt; this detects lost revocation instead of silently reinstalling
it. Disposable fixture signatures have a one-minute validity overlap, clamped to
the root's validity. Product time checks remain strict.

### Signed durable service execution

`service_execution.proto` separates three DSSE payload domains: a plan-role desired
intent, a device-key preflight challenge, and a start-role grant. Online keys require
the exact `systemd.service.v1` capability. A TLS key, offline root key, plan signature
or caller's Unix identity cannot substitute for the start role.

Intent binds deployment/device/generation, action UUID, desired revision, resource
sequence, recovery floor, root/delegation versions, actor and authorization version.
Its validity is at most fifteen minutes and contained in current delegation/root
validity. Root performs native preflight; callers cannot submit a native plan.
New work requires a current enrolled certificate, a committed current-boot session,
no unresolved session/renewal, and configured authenticated execution delegation.

For drift, root persists the exact intent bytes, native plan, historical trust,
random challenge, device proof and public signing certificate before replying.
The challenge binds both intent and plan digests, boot and process incarnation.
Its maximum thirty-second deadline uses `CLOCK_BOOTTIME`, including suspend, in
addition to wall-clock validity. A process restart invalidates unused challenges
even on the same boot. No-drift work instead verifies actual state and records
success without a start grant or native mutation.

Start acceptance commits `QUEUED`; an executor-owned worker runs independently of
RPC cancellation. After native preconditions and job subscription are ready, the
provider invokes an internal callback immediately before its first effect. Root
revalidates current authority, identity, challenge, clocks and resource fences,
then commits one-use consumption and `RUNNING`. A postcommit deadline check prevents
slow storage from extending the grant. Durable commit and native submission are
not OS-atomic: a scheduling interval remains between the final check and send.
Started multi-effect work can outlive the grant; cancellation is not rollback.

Actions retain verified success, failure, expiry, supersession or outcome unknown.
Exact intent/grant retries return historical evidence without extending authority
or repeating effects; conflicting reuse of an action UUID is rejected. Resource
sequences only advance. Higher sequences can supersede prepared/queued work, never
running work. Restart only observes previously running work: exact native convergence
can establish success; otherwise uncertainty remains persistent. It never replays
the old effect. Historical signatures are checked at their recorded acceptance
times; current revocation blocks new effects without erasing old evidence.

Schema 3 normalizes actions, resource floors and capacity accounting alongside the
unchanged identity/trust records. Admission and transitions compare all relevant
revisions transactionally. Limits are 65,536 actions, 128 KiB per encoded record and
a 256 MiB record budget. Each unfinished action reserves its entire 128 KiB allowance,
including across restart; terminal records consume their actual size. New work is
rejected at capacity, rather than accepting an effect whose outcome cannot fit.
These reservations do not guarantee physical disk availability. I/O failure holds
execution and preserves the durable checkpoint; history is not silently evicted.
Malformed protected records, inconsistent floors/accounting or missing current
schema enter recovery hold, never reconstruction from untrusted input.

This is a protected local execution boundary, not the complete remote policy system.
Production dispatch, integration of fresh actor authorization, profile
targeting/ownership and offline reconciliation remain open. Local status is
authenticated by the root Unix peer; a network relay's unsigned server report
must not be treated as proof of root execution or fresh compliance.

### Authenticated retained service evidence

`ServiceExecutionAttestation` has a separate typed DSSE domain. Root authenticates
the stored execution record and constructs deployment/device/generation, committed
session epoch, action revision, caller nonce, issuance/expiry and the exact retained
status. Signing requires current enrolled identity and certificate, a committed
current-boot session, and no pending renewal/session transaction. The envelope lives
at most thirty seconds and never beyond its signing certificate's expiry.

Attestation performs no native observation, effect, expiry transition or journal
mutation. Execution-delegation revocation does not erase authenticated history.
Retained timestamps and outcomes remain unchanged even after native drift or
wall-clock rollback; issuance is not a new verification time for the resource.
A renewed current device key can attest older evidence without replacing its
original acceptance certificate or signatures. The public response encodes the
authenticated current leaf as canonical PEM, without rewriting stored enrollment.

`Authority.VerifyServiceAttestation` requires an independently pinned device CA,
expected deployment/device/generation/session, action UUID, exact intent digest,
caller nonce and admission time. It verifies the certificate, typed signature,
closed schema, identity/bindings and bounded validity. The consumer must generate
an unpredictable nonce and enforce current certificate eligibility/revocation,
device, desired-head, recovery and authorization policy independently. A CA-valid
historical receipt alone establishes none of those current conditions.

The verifier and local RPC are implemented; production control-plane receipt
ingestion is not. Neither unsigned local status nor a fresh signature over old
status establishes present native compliance.

## 3. Device key use and renewal

The network process gets public certificates and connection configuration, never
private-key bytes. Its Go TLS client implements `crypto.MessageSigner`, not a
digest-only signing bridge. Reject the prehashed `Sign` entry point. The executor
validates the complete TLS 1.3 client CertificateVerify prefix (64 spaces, the
client context string and zero separator), allowed transcript hash length and
algorithm/options before signing for an eligible key. Initial software keys use
pure Ed25519; future P-256 providers must preserve message-aware validation.
Reject arbitrary bytes and other protocol contexts. Renewal signing is a separate
method constructing its own envelope from protected pending state.
This separates protocol authority; it cannot stop a compromised network process
from relaying a live TLS authentication or prove its chosen destination.

TLS authentication alone lets a compromised network process submit its own new CSR
for renewal. Prevent exporting the device identity this way: renewal also requires
a domain-separated statement signed by the currently presented device key. Bind
it to deployment/device/generation, presented certificate fingerprint and exact CSR
digest. The executor creates this statement only for its own durably staged next
key. A TLS CertificateVerify signature cannot stand in for renewal authority.
Use a standard signed envelope, with a recognized payload type and strictly
validated protobuf payload; no homegrown cryptographic primitive.

Persist pending rotation before returning the CSR/proof. Server authorization is
rechecked under the existing device lock, including expiry; only active authority
can issue, while an eligible overlapping certificate can replay its own completed
issuance. The agent validates and atomically installs the result, then changes the
TLS credential used for new connections. Retain only the bounded prior credential
needed for in-flight/replay recovery. A failed/delayed rotation does not silently
replace the active key or permit renewal from expired/revoked authority.

Use the documented 30-day certificate lifetime, renewal after 10 days with jitter,
and bounded overlap. Persist retry intent across process/host restart. Revocation
or terminal expiry is visible and fail-closed, not an automatic fresh enrollment.

Add a public, server-authenticated HTTPS issuance-retrieval RPC for interrupted
rotation beyond the old certificate's overlap. The requester proves possession of
the staged next private key using a distinct DSSE payload bound to deployment,
device/generation and the persisted issuance-request UUID. The server resolves only
that original issuance, rechecks current generation, revocation and certificate
validity, and returns the already-issued public certificate. It cannot mint, extend,
activate a different key or authorize other device RPC. This avoids widening old
authority or requiring operator recovery after an ordinary prolonged power loss.

### Session fencing and clone limits

The executor persists one session-acquisition intent per boot transition, binding
deployment/device/generation, predecessor epoch, unique request UUID and random
incarnation. It signs the claim with protected identity authority. Server acquisition
is compare-and-swap under the device lock; the exact acquisition retry returns the
same receipt. Persist the resulting epoch before releasing transport work. A process
restart in the same boot resumes the existing epoch; reboot acquires its successor.
Every mutation, including snapshots and renewal, rechecks the epoch under the device
lock. Old in-flight messages cannot mutate current state.

A different protected acquisition UUID for an already-consumed predecessor indicates
ambiguity and places the generation in recovery hold; an exact persisted retry does
not. Changed reuse of an existing request UUID is an idempotency conflict, not clone
evidence: the unsigned outer DSSE encoding must not be a way to force recovery hold.
Hold/revocation denies all ordinary mutations and requires approved generation
replacement, not automatic last-writer-wins. The server retains acquisition receipts
and predecessor fences for the active generation. An executor never signs a caller-
selected incarnation/epoch; it derives them from its protected journal and boot.

Retain up to 65,536 successful acquisitions and 4,096 renewal issuances per active
generation. Resolve exact replay and request conflicts before these admission caps.
Capacity exhaustion is explicit; no timer deletes active-generation receipts,
resets the epoch or implicitly re-enrolls the device.

Software credentials cannot distinguish a coordinated exact copy or a sequential
clone using the same persisted state. This is an explicit assurance limit, not
solved by machine-id, serial or boot ID. The separately specified TPM assurance tier
still requires genuine non-exportability/attestation qualification; neither tier is
certified by the initial software-key VM scenarios.

## 4. Native observations and complete package snapshots

The current G1 RPC's 500-package whole-report limit cannot represent a normal desktop
installation. Fix the wire/storage contract before using it in the agent; do not
truncate packages or mark a partial list complete.

Keep host/OS/hardware observations distinct from package collection freshness.
Collect actual boot ID, hostname, OS release, architecture, kernel and available
hardware identity. Missing or inaccessible DMI fields are explicit unavailable
observations, not made-up identifiers. Native package identity preserves epochs,
architecture and multiple installed versions (notably RPM kernel packages).

Use independent generation-scoped host-observation and package-attempt sequences;
heartbeats allocate neither. Remove G1's cross-counter constraint. Allocate sequence
and immutable pending payload in one local spool transaction. On missing/corrupt
unprivileged spool, expose recovery and fetch server high-water marks under the
executor's current session fence before creating new observations; never silently
restart at sequence one. Protected executor state is not recreated by this recovery.

Typed host observations include collection start/finish, boot ID and per-field
availability/reason. A separate package-attempt status carries sequence, collection
times, backend and a bounded reason enum: success, unavailable, permission denied,
timeout, invalid output, capacity exceeded or native command failure. Server receipt
time is separate from device-claimed collection time. Keep latest attempt and last
successful snapshot independently. Older attempts never replace newer attempt
status; heartbeat and exact replay change contact time only. Never interpret
unavailable/failed fields as a new successful empty value.

Use staged package snapshots with three bounded operations:

1. Begin: device/generation-bound snapshot UUID, durable sequence, collection
   metadata and a bounded manifest of batch digests/counts/encoded sizes.
2. Put batch: snapshot UUID, batch index and up to 500 typed package records.
   Verify the declared digest/count/size; identical retry is idempotent, changed
   content is a conflict. Never expose incomplete staging as current inventory.
3. Commit: require the complete verified manifest, recheck device authority and
   monotonic sequence under the device lock, then atomically publish the snapshot.
   A lost commit response replays the same committed result.

States are staging, committed, superseded and expired. Begin binds the exact
metadata/manifest digest; changed reuse is conflict. Reauthorize first, then resolve
the durable receipt before applying monotonic publication rules. Duplicate Put
after commit validates its retained manifest and returns the original acceptance.
Commit of an older uncommitted attempt is explicitly superseded, never falsely
reported as published. Persist compact receipts/digests independently of bulk rows
for 90 days, measured from the first accepted request with no retry extension.
After receipt expiry, refuse the old snapshot UUID without republishing; generation
sequence high-water marks persist. Snapshot UUIDs include an explicit creation time
in the immutable manifest; bound initial admission age/future skew so an expired
receipt cannot be recreated with its old sequence or refreshed creation timestamp.

Bound the whole snapshot as well as each message: 100,000 package records, at most
512 batches and 64 MiB encoded package data. Batch payload is a versioned protobuf
`PackageBatch` encoded once and sent as opaque bytes; SHA-256 and size cover those
exact bytes, not server reserialization. Decode with strict schema/bounds and reject
unknown fields. Each batch is at most 768 KiB and 500 records, leaving room under
the 1-MiB complete control-message limit. Report capacity errors rather than truncate.

One open upload per device has a 24-hour maximum lifetime fixed at Begin; requests
do not extend it. Bound retained raw package data to 256 MiB per device and a typed,
operator-configurable deployment budget, initially 10 GiB. Reserve bytes atomically
at Begin and release on cleanup; also account for finite manifest/receipt metadata.
Rate-limit collection admission to one new attempt per device per five minutes,
with idempotent retries exempt. Cleanup serializes with Put/Commit and cannot delete
current/pinned snapshots. When retention prevents admission, return explicit
resource exhaustion rather than deleting a cursor's data or overstating freshness.

Agent spool holds one immutable in-flight snapshot plus one replaceable, unsubmitted
collection, with a 160-MiB byte budget. Coalesce offline observations rather than
accumulating an unbounded history. Persist immutable batch bytes before upload;
restarts retry those exact bytes. A superseded/expired receipt terminates that
attempt and permits a fresh collection, not mutation of its old manifest.

Host contact and inventory timestamps are different facts. Heartbeat cadence does
not require re-uploading the package inventory every minute. Package collection
failure preserves the last complete snapshot with its old freshness and exposes
the new failure. A full empty snapshot is distinct from unavailable collection.
Provide authenticated device detail/package pagination so VM-native truth can be
compared through the public API and inspected in the console.

Store package rows by immutable snapshot UUID and position; Commit atomically
switches the device's current pointer. Package cursors bind device, generation,
snapshot, filters, next position and a fixed 15-minute expiry inherited by every
subsequent page. Reauthorize each page. Retain superseded bulk rows for at least
15 minutes after supersession; return an explicit expired-snapshot error when
unavailable, never silently switch pages to the current snapshot. Operational
retention here is not a customer historical-data/legal-hold policy.

Providers invoke documented native tools with fixed executable/argv, bounded output,
deadlines and controlled locale/environment where a stable native API is absent.
No shell interpolation or server-supplied executable. Select providers from actual
vendor/version/backend evidence, not `ID_LIKE` or the presence of an arbitrary tool.
Each later launch-matrix row still needs its own lifecycle qualification.

## 5. Native packages and maintained laboratory

Build real DEB and RPM artifacts containing the same versioned agent binary,
separate hardened executor/network systemd units, native account/directory ownership
and minimal native package lifecycle glue. Preserve state on removal/purge and fail
visibly on incompatible state. Do not ship a generic root shell executor.

DEB installation uses an isolated APT repository with a signed InRelease, hashed
Packages index and a separately pinned `Signed-By` key. Do not call plain
`dpkg -i` on an allegedly signed DEB and claim APT authentication. RPM installation
requires a pinned trusted signer and explicit `gpgcheck=1` plus
`localpkg_gpgcheck=1` for local artifacts. Tampered, unsigned and wrong-signer
artifacts must fail before maintainer scripts execute. Record artifact digest and
signer, not merely installer exit status.

The Go lifecycle runner owns image manifests, acquisition/verification, VM lifecycle,
API assertions, fault injection and evidence. Reuse the existing Go dev-lab fixture
and real Keycloak authorization path; no test-only production authentication bypass.
Official cloud images plus NoCloud give the fast loop; actual installer/desktop
acceptance remains a separate openQA route, not a cloud-image certification claim.

Pin image release/snapshot, SHA-256, signed checksum source and trusted signer
fingerprint. Verify upstream signature and selected image digest before opening it
with QEMU. HTTPS alone is not artifact authenticity. Use isolated overlays and
per-run protected SSH keys/state; never mutate the cached base image.

Initial VM execution uses existing QEMU/KVM without changing host firewall, groups
or security policy. Prefer unprivileged user networking and maintained SSH forwarding
for the localhost development endpoints; preserve hostname/CA validation end to end.
Do not set insecure TLS to make VM networking work. Record QEMU/firmware versions
and whether execution used KVM or emulation. Emulation is not native hardware proof.

The maintained runner uses host-side authorization-code/PKCE login against the
real fixture; Keycloak direct grants stay disabled. SSH reverse forwards bind only
guest loopback and reach host localhost TLS listeners, preserving certificate names.
Pin each run's SSH host key supplied through the trusted NoCloud fixture; never use
`StrictHostKeyChecking=no`. Native lifecycle proof uses two versioned built artifacts:
install, upgrade, remove/purge and reinstall preserve the protected generation and
monotonic observations unless an explicit approved replacement was requested.

Exercise built, signature-verified packages in a Debian-family VM and an independent
RPM-family VM before closing the G2 vertical slice. Then expand the same providers,
manifests and scenario runner across the confirmed matrix; do not add one-off distro
scripts. Out-of-band SSH is an oracle/control channel, not a substitute for agent
work. No tests of hook wiring, copied config or command strings.

### Running the native lifecycle lane

Run `make build dev-up dev-trust`, then keep `lindmd serve` running with the
development configuration described in the README. Use a private build directory
under trusted ancestry, not a group-writable checkout. The tools reject unsafe
ownership, symlinks and accidental reuse of signing homes. They never change host
package trust or install the agent on the host.

```sh
work="$HOME/.cache/lindm-native"
mkdir -m 700 "$work"
artifacts/bin/lab packages keygen -output "$work/key"
```

Set `FINGERPRINT` to the full fingerprint printed by `keygen`; independently retain
it as the expected package signer. This key is development-only and is separate
from execution, transport, device and TUF authority. Build two actual versions:

```sh
for version in 0.1.0 0.1.1; do
  artifacts/bin/lab packages build -repo . -version "$version" \
    -revision development -output "$work/$version" \
    -signer-home "$work/key/package-signing-gnupg" \
    -fingerprint "$FINGERPRINT" -development-key \
    -record "$work/$version/build.json"
done
artifacts/bin/lab packages apt -output "$work/repository" \
  -signer-home "$work/key/package-signing-gnupg" \
  -fingerprint "$FINGERPRINT" -development-key \
  -record "$work/repository/repository.json" \
  "$work/0.1.0/lindm-agent_0.1.0_amd64.deb" \
  "$work/0.1.1/lindm-agent_0.1.1_amd64.deb"
artifacts/bin/lab packages rejection-fixtures \
  -build "$work/0.1.0/build.json" \
  -apt-repository "$work/repository/repository.json" \
  -output "$work/rejections" \
  -signer-home "$work/key/package-signing-gnupg" \
  -fingerprint "$FINGERPRINT" -record "$work/rejections/fixtures.json"
```

The rejection fixtures contain real unsigned, tampered and wrong-signer inputs,
not mocked installer responses. The lifecycle runner requires native authentication
failure and checks that no package, account or service state was installed.

```sh
artifacts/bin/lab vm lifecycle \
  -manifest lab/images/ubuntu-noble-amd64.json \
  -first-build "$work/0.1.0/build.json" \
  -second-build "$work/0.1.1/build.json" \
  -apt-repository "$work/repository/repository.json" \
  -rejections "$work/rejections/fixtures.json" \
  -public-key "$work/0.1.0/lindm-package-signing.asc" \
  -fingerprint "$FINGERPRINT" -record "$work/ubuntu-lifecycle.json"
artifacts/bin/lab vm lifecycle \
  -manifest lab/images/fedora-44-x86_64.json \
  -first-build "$work/0.1.0/build.json" \
  -second-build "$work/0.1.1/build.json" \
  -rejections "$work/rejections/fixtures.json" \
  -public-key "$work/0.1.0/lindm-package-signing.asc" \
  -fingerprint "$FINGERPRINT" -record "$work/fedora-lifecycle.json"
```

Use fresh output/record paths for another run; records are not overwritten. Each
successful result follows native installation, lost-issuance recovery, distinct-UID
privilege probes, complete public-API inventory comparison, upgrade, reboot,
removal/purge/reinstallation, corrupt-spool recovery, failed collection preserving
the last snapshot, revocation and missing-journal recovery hold. Cleanup revokes
owned server authority and removes the disposable guest. Optional `-observe-for 3m`
pauses after the first two publications for console inspection (maximum ten minutes
per pause). Before upgrade, the lab selects a freshly compared current snapshot;
retained-cursor assertions use this baseline, not the potentially older initial
publication. The result records it as `upgrade_baseline`. While that baseline
remains current, the lab may refresh its comparison cursor; supersession freezes
the cursor and its expiry. This never extends a server cursor's lifetime.

A native query can fail while an upgrade finishes. The lab allows eighteen minutes
for normal ten-minute recollection, five-minute server admission and heartbeat
jitter; it does not change production timers or turn failed collection into success.
The complete lane is bounded at sixty minutes plus twice the observation pause.

Executables and package lifecycle helpers live in `/usr/libexec/lindm`. Fedora
runtime assertions require SELinux Enforcing, vendor-matching executable labels
and service domains outside `init_t`. This is compatibility with vendor policy,
not a custom SELinux confinement claim. No relabeling or policy override is used.
Transport diagnostics use a descriptor-relative, no-symlink open: systemd's
`RestrictSUIDSGID=yes` blocks `openat2` even for read-only requests. Root may read
the network-owned final spool directory for diagnostics; mutable state and all
ancestor checks retain their original ownership requirements.

### Running the native service-provider lane

Build the lab with `make build`, then run the provider against a fresh disposable
guest. No control-plane service or enrollment grant is needed for this provider
qualification; it does not expose an unauthenticated product management path.

```sh
artifacts/bin/lab vm services \
  -manifest lab/images/ubuntu-noble-amd64.json \
  -record "$HOME/.cache/lindm-services-ubuntu.json"
artifacts/bin/lab vm services \
  -manifest lab/images/fedora-44-x86_64.json \
  -record "$HOME/.cache/lindm-services-fedora.json"
```

Use new record paths for subsequent runs. The lab uploads a digest-checked snapshot
of its executable, creates fixed sacrificial service fixtures only in its owned
guest, and calls `internal/agent/serviceprovider`. Independent `systemctl`
observations verify enable/start, unchanged desired state, stale-plan rejection,
reconvergence, disable/stop, cancellation before start, and rejection of missing,
aliased and nonpersistent oneshot services. Fedora remains SELinux Enforcing.
Success follows fixture cleanup and complete VM teardown.

The production provider uses typed `ServiceDesiredState` and systemd D-Bus:
Observe → Plan → Apply → Verify. It never accepts executable paths, arguments or
unit contents. A plan binds the canonical unit, boot, native state and protected
unit-definition fingerprint; changed preconditions prevent effects. Native job
completion alone is not convergence. A submitted effect with lost/canceled
observation remains uncertain, not implicitly canceled or rolled back.

Persistent enablement changes require a native manager reload. This also
incorporates other pending unit definitions; it is not an isolated per-unit
transaction. The provider rechecks its unit definition/state before runtime
effects. Native `[Install]` semantics can affect related links/units, and an
enabled/disabled result does not establish link ownership. Ownership-safe profile
removal still requires journal integration.

The standalone runs qualify the provider, not remote policy execution, application
health, reboot persistence, all distro cells or complete G3. Product effects now
reach `Apply` only through the signed durable executor's first-effect callback.
Ownership-safe removal remains a separate required contract.

### Running the packaged signed service lane

Add `-service-execution` to the maintained `lab vm lifecycle` commands above. It
implies `-execution-trust` and requires an upgraded package implementing the typed
service RPCs. To qualify migration, retain a genuine old schema-1 or schema-2 first
package; rebuilding the current source with an older version label is not migration
evidence. Keep the actual control plane/Keycloak/PostgreSQL running and product
inventory timers unchanged.

The lab signs narrowly scoped disposable authority, authenticates the root challenge
against its separately pinned device CA, and relays through the installed agent as
the network UID. The installed sandboxed root service performs enable/start,
runtime-only stop/start, no-op verification and enablement-only changes. Independent
native queries check outcomes and absence of effects after forged signature,
plan-domain start, stale precondition, expired grant, same-boot restart and revoked
delegation. Exact replay preserves terminal evidence.

A slow sacrificial native job exposes `RUNNING`; the lab sends SIGKILL to the
executor, not the target service. Read-only restart reconciliation preserves unknown
outcome or verified convergence, while the target's stable native invocation ID
proves the job survived without a new invocation. Replaying the accepted grant
cannot repeat it. For each terminal action, the network-UID CLI obtains a fresh
nonce-bound attestation and the lab independently verifies its certificate,
signature, target, session, intent digest and retained status. A schema-valid
payload alteration with the original signature and a wrong-nonce replay must fail.

The full lifecycle repeats this proof after execution-authority revocation, host
reboot and remove/reinstall, preserving terminal status and action revision.
Before attesting, readiness compares the executor's committed boot ID with the
guest's actual `/proc/sys/kernel/random/boot_id`; `session_epoch_usable` alone is
not current-boot proof. A bounded ten-minute readiness wait accommodates normal
transport recovery without changing product inventory timers. Fixtures and the
VM are then cleaned. Development signing is not production dispatch authorization;
these are VM results, not hardware attestation, destructive qualification or a
complete G3 claim.

## 6. Required G2 failure boundaries

- Real SSO grant issuance, secret redaction/hash-only persistence and lost issuance.
- Native package install, explicit bootstrap, real mTLS activation and reboot/restart.
- Lost certificate response resumes the same key/transaction; wrong key/identity
  cannot replace protected state or consume an already-consumed grant.
- Network UID cannot read private keys, change trust/journal, import arbitrary
  certificates, obtain arbitrary signatures or renew to a caller-chosen key.
- Complete native package inventory exceeds one batch; duplicate/out-of-order batch,
  lost commit, interrupted upload and collection failure preserve correct state.
- Renewal installation survives process interruption; expired/revoked authority
  fails closed, including requests on existing TLS connections.
- Missing/corrupt journal and purge/reinstall cannot create an empty success-ready
  identity/replay store. Clone/reinstall ambiguity is visible and safely fenced.
- API/console show actual state, collection failures and independent freshness.

Each coherent implementation slice receives real runtime proof, focused behavioral
regressions, independent review and separate corrective commits. G2 completion does
not imply G3 policy execution, G4 sessions or any unrun release/hardware gate.

## Research anchors

- [DSSE specification and implementations](https://github.com/secure-systems-lab/dsse).
- [Go DSSE library](https://pkg.go.dev/github.com/secure-systems-lab/go-securesystemslib/dsse).
- [Go TUF implementation](https://github.com/theupdateframework/go-tuf).
- [Ubuntu image authenticity and trusted signer verification](https://documentation.ubuntu.com/security/software-integrity/image-verification/).
- [Ubuntu cloud-image checksum verification and distinct UEC signer](https://ubuntu.com/docs/public-images/public-images-how-to/verify-image-checksum/).
- [Go message-aware signing interface](https://github.com/golang/go/blob/go1.26.8/src/crypto/crypto.go).
- [APT authenticated repository chain](https://manpages.debian.org/trixie/apt/apt-secure.8.en.html).
- [DNF package-signature controls](https://dnf.readthedocs.io/en/latest/conf_ref.html#localpkg-gpgcheck-label).
- [Fedora image/signing-key verification](https://fedoraproject.org/security/).
- [systemd RestrictSUIDSGID and indirect syscall arguments](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html#RestrictSUIDSGID=).

Local prerequisite inspection found QEMU/qemu-img 8.2.2, readable/writable KVM,
`dpkg-deb`, `dpkg-scanpackages`, `rpm`, `rpmsign`, `gpgv` and `cloud-localds`.
These are prerequisites, not proof of native installation. DSSE v0.11.1 and
go-tuf/v2 v2.4.2 are pinned and exercised by the bootstrap verifier and real
development fixtures. Modernc SQLite v1.60.1 backs the protected journal and
unprivileged spool through sqlc. Native packages use the host DEB/RPM tools;
nFPM remains a researched candidate, not an adopted dependency.
