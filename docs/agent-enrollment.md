# Packaged agent and native enrollment contract

Status: G2 internal qualification is complete (`cb97712`); G3 execution-trust
rotation and signed durable service execution extend that packaged agent.
The evidence ledger records exercised native runs and remaining gates, not a release
claim. This document refines [architecture](architecture.md) and
[verification](verification.md); it does not reduce the confirmed launch matrix or
replace its desktop/physical acceptance.

## 1. Process and source boundaries

Build `cmd/lindm-agent` separately from `cmd/lindmd`. The agent executable has
`executor`, `run`, `bootstrap`, `resume`, `status`, `trust-update`, `trust-status` and typed
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
- `trust-status`: reads the protected root/delegation versions, deterministic root
  digest, exact delegation-envelope digest, acceptance time and validity. Expired
  retained authority remains visible; reading it grants no authority or native effect.
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

### Enrollment history and onboarding instructions

`ListEnrollmentGrants` accepts bounded `page_size` (at most 200), `page_token` and an
optional `view` (`ACTIVE`: unused, unexpired and not revoked; `INACTIVE`: every other
grant; unset lists all) and returns `grants`, `next_page_token` and whole-history
`active_count`/`inactive_count` evaluated at the same instant, independent of view and
cursor. Follow the returned cursor rather than inferring that the first page is the
complete history. The console lists active codes by default and loads the inactive
view only when "Show used and expired" is opened. Each grant exposes its ID,
creation/expiry times, creator principal ID and current creator display name,
maximum/used counts, and typed `ACTIVE`, `CONSUMED`, `EXPIRED` or `REVOKED` status.
Consumed grants also project the current device ID, hostname and labels. Labels
are a string list from the device, not a key/value map or fixed grant assignment.
Consumed takes precedence over revoked and expired; otherwise revoked takes
precedence over expired. Historical consumption is not a claim that the resulting
device still has authority. An unconsumed grant has no device projection.

`ListProvisioningTokens` retains its bounded cursor pagination and includes the
creator's current display name alongside the stable `created_by` principal ID.
Names prefer the principal display name, with local username fallback; they are
display context, never authority. Renames do not change credential ownership.
Token metadata retains use counts, expiry, revocation and fixed assignments.
Neither list exposes the bearer credential or its persisted hash. Issuance remains
the only secret delivery opportunity; reading history cannot recover a lost secret.

Enrollment metadata and `GetEnrollmentInstructions` require unrestricted
`manage_enrollment` authority, freshly checked against persisted authorization.
A principal scoped even to the consumed device is denied, not given a partial
credential list. Fleet-read permission alone is insufficient. These reads do not
weaken the existing global enrollment-management boundary.

`GetEnrollmentInstructions` takes an empty request and returns deployment-owned
onboarding metadata: `enrollment_origin`, optional `device_origin`,
`execution_root_url`, `execution_root_sha256` and `bootstrap_bundle_url`, plus
available `apt_repository` and `dnf_repository` records. Native repository URLs
always point to the customer's own `lindmd` HTTPS origin under `/repo/`; agents
are never distributed through an external package host. Repository records carry
the full independently pinned `signing_key_fingerprint`; APT additionally supplies
`suite` and `components`. Registry-backed `platforms` identify the install method
and each platform's readiness/remedy. Missing artifacts block the command with a
configuration remedy, never an instruction to find packages elsewhere.
Private HTTPS bootstrap also supplies `tls_ca_pem` and its DER SHA-256
`tls_ca_sha256`, authenticated through this authorized console response.
Instructions are not executable authority and contain no enrollment secret.
The response also supplies `grant_command`, `provisioning_command` and
`resume_command` templates for the installed agent. The grant template reads
`/run/lindm-enrollment/grant`; the provisioning template reads
`/etc/lindm/provisioning-token`. Both use the protected root and bundle paths shown
below. The resume template waits at most 3600 seconds. These templates contain
file paths, never bearer values, and do not establish that prerequisites exist.

Configured public bootstrap resources are served by unauthenticated GET/HEAD at
`public_url` plus `/bootstrap/execution-root.json` and
`/bootstrap/bootstrap.dsse.json`, not by a general directory server. The copied
console command authenticates the execution root against the digest carried by
the administrator's trusted console session; downloading a root alone does not
establish trust. The bootstrap bundle remains the existing signed DSSE document
and must verify against that authenticated root. Before repository trust is
installed, the command verifies the full signing-key fingerprint and any private
server CA fingerprint. HTTPS hostname/chain verification remains enabled. DNF
requires signed repository metadata as well as signed packages. See the
[install runbook](security-and-operations.md#enrollment-installation-from-your-server)
and [threat model](architecture.md#trust-bootstrap-from-the-customers-server).

After verified package installation and protected placement of the authenticated
deployment material, the one-time grant path is:

```sh
/usr/libexec/lindm/lindm-agent bootstrap \
  -root /etc/lindm/execution-root.json \
  -bundle /etc/lindm/bootstrap.dsse.json \
  -grant /run/lindm-enrollment/grant
```

Keep the grant file root-only; `-grant -` accepts protected standard input.
Never substitute a bearer value into the command line or environment.
Unattended enrollment instead uses `-provisioning-token-file FILE` as below;
that flag does not accept standard input. Missing deployment onboarding settings
must remain visible to the operator rather than producing fabricated commands.

### Unattended enrollment and approval

Create a provisioning token in Enrollment with a bounded lifetime/use count and
fixed metadata, groups and profile revisions. Its secret is displayed once; a lost
issuance response cannot recover it from the server. Revoke and replace an
unrecoverable secret instead of retrying with a different request ID blindly.
Only a credential hash is retained. Tokens expire within 24 hours and permit at
most 10,000 distinct reservations. Keep the first-boot seed and downloaded token
file private; a short server lifetime is not forensic erasure of installer copies.

After installing the verified agent and deployment bootstrap material, a
root-owned first-boot service runs:

```sh
/usr/libexec/lindm/lindm-agent bootstrap \
  -root /etc/lindm/execution-root.json \
  -bundle /etc/lindm/bootstrap.dsse.json \
  -provisioning-token-file /run/lindm/provisioning-token
/usr/libexec/lindm/lindm-agent resume -wait-seconds 3600
```

The token file must be a protected root-only file, not an argument, environment
value or image ingredient. The root executor persists one CSR/key/installation and
transaction before submission. Resume proves that same key; an interrupted call
does not allocate a second device or consume another token use. An initial
successful bootstrap can mean `PENDING_APPROVAL`, not enrollment completion:
bounded resume succeeds only after identity installation. On timeout inspect the
pending state and use the same protected resume path; never discard the journal
or generate a replacement key just to retry.

Approval-required reservations appear in the existing approvals inbox and cannot
authenticate as devices or execute assignments. An independently authorized human
reviews the exact reservation; self-approval is denied. Rejection, expired
authority and revoked provisioning credentials cannot be bypassed by old claims.

### Offline-site file exchange

The server must have current PLAN and START delegates explicitly authorized for
`enrollment.offline.v1`; service-execution or TLS keys do not implicitly grant that
capability. The device receives its independently trusted execution root and
root-signed deployment bootstrap through the installation channel. In Enrollment,
follow "Enroll devices at offline sites" and create an offline authorization for a
provisioning token and the exact bootstrap
root version/digest. The exported authorization contains no reusable token secret;
it is still a sensitive, bounded enrollment capability. Validity is bounded by
the token's remaining lifetime as well as signing authority, not merely the
requested seven-day protocol maximum.

Copy the authorization file to the device using protected media. All file inputs
and outputs below are root-owned, mode 0600, bounded strict protobuf JSON:

```sh
/usr/libexec/lindm/lindm-agent offline-export \
  -root /etc/lindm/execution-root.json \
  -bundle /etc/lindm/bootstrap.dsse.json \
  -file /root/offline-authorization.json \
  -out /root/offline-request.json
```

The request includes a locally generated CSR and device-key-signed proof binding
the deployment, protected installation, transaction, authorization digest, CSR
digest and validity. Carry that request back to the console and import it. The
normal reservation, max-use and approval rules apply. After approval, export the
response for that same signed request and carry it to the device:

```sh
/usr/libexec/lindm/lindm-agent offline-import -file /root/offline-response.json
```

The response's authorized server signature, exact request/key binding, certificate
chain and validity are checked before durable installation. The response cannot
choose a new trust root or supply a private key. These device commands make no
network request and do not require a reachable public service. They do not make
the later device synchronization network optional: a local authorized site server
is still needed for ongoing fleet management. If request export is interrupted,
use `offline-export -resume -out /root/new-offline-request.json` to recover the
same protected attempt; never initialize a different key to retry. Re-import
after successful durable installation is rejected rather than resetting state.

### Explicit reinstall and clone recovery

Device detail's recovery action identifies the exact existing device and current
generation; serial, hardware, MAC and TPM EK observations are evidence for the
operator, not authenticators. Two-person approval produces a short-lived one-use
recovery grant. On a clean installation, use the normal protected grant bootstrap
path with a newly generated key. Consumption preserves the selected device ID,
creates a new generation and retires every previous generation's certificates.
An already used device key is rejected. The old journal is not reset by package
remove/reinstall, and corrupt protected state is not repaired by an ordinary
enrollment credential: retain incident evidence and follow the explicit approved
reinstallation workflow.

The same signed installation may acquire a new boot session from the current
predecessor. A different signed installation or competing successor of a consumed
predecessor instead puts both device and generation into recovery hold, including
existing live sessions. Resolve that hold by approved generation replacement, not
by merging devices with matching inventory or releasing an ambiguous old key.

### Native unattended qualification

The maintained command boots two fresh native guests for one max-uses-two token,
checks real inventory and immutable preassignments, and requires an explicit
exhaustion denial for a third valid new CSR. Approval mode also proves no device
authority before an independent approval and then resumes the same reservation.
Run each command with a new evidence output path:

```sh
artifacts/bin/lab vm enroll-unattended -repo . \
  -manifest lab/images/ubuntu-noble-amd64.json \
  -lindmd /absolute/path/lindmd -lab-binary /absolute/path/lab \
  -record /private/new/ubuntu-unattended.json
artifacts/bin/lab vm enroll-unattended -repo . \
  -manifest lab/images/fedora-44-x86_64.json \
  -lindmd /absolute/path/lindmd -lab-binary /absolute/path/lab \
  -record /private/new/fedora-unattended.json
```

Repeat with `-approval-required` and a distinct evidence path. Prerequisites are
KVM, QEMU, `qemu-img`, `cloud-localds`, the maintained native packaging/signing
tools, pinned Go, current generated code/binaries, protected development trust
and running PostgreSQL. Signed image acquisition needs a verified cache or access
to the configured vendor sources. The lane uses an isolated database and dynamic
listener ports, not Keycloak or shared `:18444`. Native guest observations are
required; merely generating a seed or compiling the command is not qualification.
The overall deadline is 60 minutes, with bounded boot, observation and approval
waits; all run-owned resources are removed on failure or success.

### Execution-trust updates

`execution_trust.proto` defines separate old/new quorum envelopes for each
consecutive execution-root replacement and a current-root-signed online delegation.
The independent envelopes support disjoint sixteen-key quorums. Delegations bind
deployment/root version, deployment-global delegation version, validity, minimum
recovery epoch and exact versioned capabilities for separate plan/start roles.
Empty delegates revoke all online execution signers. Current root, TLS-CA and
release keys cannot become online execution delegates.

The protected SQLite journal supports only its current version-1 schema, including
the separately revisioned execution-trust singleton. Unexpected versions, missing
tables or damaged trust enter recovery hold, not migration or an empty replacement.
The executor verifies complete root/delegation proposals before one durable commit and
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
CLI as the network UID after a package binary upgrade; both packages must use the
current journal schema. It rejects a wrong quorum and
independently root-signed delegation/recovery rollback proposals, rotates roots,
revokes delegates and compares public TLS identity/pins. After reboot and
remove/reinstall it first rejects the previously accepted rotation, then replays
the final receipt; this detects lost revocation instead of silently reinstalling
it. Disposable fixture signatures have a one-minute validity overlap, clamped to
the root's validity. Product time checks remain strict.

### Control-plane authority and automatic relay

Optional server `execution_bootstrap` contains protected public `root_file` and
`bootstrap_file` references; `device_public_url` is then required. These are the
owner-pinned execution-root JSON and its genuinely quorum-signed bootstrap, not
private signing keys. Resolution binds deployment, admin/device origins and device
CA to the server configuration, and verifies its TLS leaf against the pinned
transport roots for both hostnames. TLS leaf, CA and release keys cannot become
execution roots or delegates. Removing this configuration after database
provisioning fails startup; it does not clear authority.

`AdminService.GetExecutionAuthority` exposes retained public state.
`UpdateExecutionAuthority` requires an owner/admin with fresh directory
authorization, a signed `UpdateExecutionTrustRequest`, and an audit reason.
Principal authorization, root/delegation changes, immutable receipts and audit
commit together. The server retains the original signed bootstrap, authenticated
root history and deployment-wide version/recovery floors. Exact historical request
replay returns its original receipt even after newer updates or expiry; it cannot
rewind authority or add a second audit. Live state must match its captured retained
admission/root records; contradictory partial restores fail closed.

Device `GetExecutionTrust` checks eligible certificate, device/generation and
session under the existing authority lock. Credential overlap retains its existing
bounded semantics. Reported versions/digests are untrusted delivery hints, not
applied-state receipts. Responses contain verified signed documents; a missing or
expired prerequisite, unknown root, divergent digest or chain longer than eight
transitions requires explicit recovery rather than a guessed reset or partial chain.
History is bounded at 4,097 roots, 65,536 updates and 64 MiB of retained document
bytes; capacity rejection preserves existing authority and historical retries.

The installed network process owns a separate cancellable synchronization loop and
connection cache. Inventory collection cannot starve it. Both loops share a
cancellable gate around complete identity/session establishment; inventory holds
that gate through `GetSyncState`, but collection, upload and trust synchronization
do not. Root alone verifies and atomically admits the signed update. Server desired
counters must match its receipt. An unprovisioned response never erases local trust.
This path does not dispatch work, load online signing keys, or establish compliance.

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

Actions retain verified success, failure, expiry, supersession or outcome unknown
subject to the read-only retention window below. Exact retries of retained intents/grants
return historical evidence without extending authority
or repeating effects; conflicting reuse of an action UUID is rejected. Resource
sequences only advance. Higher sequences can supersede prepared/queued work, never
running work. Restart only observes previously running work: exact native convergence
can establish success; otherwise uncertainty remains persistent. It never replays
the old effect. Historical signatures are checked at their recorded acceptance
times; current revocation blocks new effects without erasing old evidence.

The single journal schema (version 1) normalizes actions, resource floors and
capacity accounting alongside identity/trust records. There are no schema-upgrade
paths; an unexpected version enters recovery hold without rewriting protected
state. Admission and transitions compare all relevant revisions transactionally.
Limits are 65,536 actions, 128 KiB per encoded record and
a 256 MiB record budget. Each unfinished action reserves its entire 128 KiB allowance,
including across restart; terminal records consume their actual size. New work is
rejected at capacity, rather than accepting an effect whose outcome cannot fit.
The newest 256 non-floor read-only successes and every current resource-floor record
are retained. Older successful no-drift records without grants are pruned transactionally
with admission, sequence-floor advancement and capacity accounting. Granted records
and non-success outcomes are never removed by this policy. A pruned action's historical
attestation is unavailable, but replay remains rejected by its retained sequence floor.
These reservations do not guarantee physical disk availability. I/O failure holds
execution and preserves the durable checkpoint; it never evicts protected outcomes.
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

### Running the pinned Arch lane

Use the same private development signer, but build explicitly with `-formats arch`.
Arch packages contain `.PKGINFO`, `.MTREE` and `.BUILDINFO`, the shared systemd
units/sysusers/tmpfiles, and a detached `.sig`. Each pacman sync database contains
one version per package name, so publish separate initial and upgrade repositories:

```sh
for version in 0.1.0 0.1.1; do
  artifacts/bin/lab packages build -repo . -version "$version" -formats arch \
    -output "$work/$version" -signer-home "$work/key/package-signing-gnupg" \
    -fingerprint "$FINGERPRINT" -development-key -record "$work/$version/build.json"
  artifacts/bin/lab packages arch -output "$work/repo-$version" \
    -signer-home "$work/key/package-signing-gnupg" \
    -fingerprint "$FINGERPRINT" -development-key \
    -record "$work/repo-$version/repository.json" \
    "$work/$version/lindm-agent-$version-1-x86_64.pkg.tar.zst"
done
artifacts/bin/lab packages rejection-fixtures -arch \
  -build "$work/0.1.0/build.json" -output "$work/rejections" \
  -signer-home "$work/key/package-signing-gnupg" \
  -fingerprint "$FINGERPRINT" -record "$work/rejections/fixtures.json"
artifacts/bin/lab vm lifecycle -manifest lab/images/arch-20261001-x86_64.json \
  -first-build "$work/0.1.0/build.json" -second-build "$work/0.1.1/build.json" \
  -arch-first-repository "$work/repo-0.1.0/repository.json" \
  -arch-second-repository "$work/repo-0.1.1/repository.json" \
  -rejections "$work/rejections/fixtures.json" \
  -public-key "$work/0.1.0/lindm-package-signing.asc" \
  -fingerprint "$FINGERPRINT" -control-plane-trust -lindmd artifacts/bin/lindmd \
  -allow-network -record "$work/arch-lifecycle.json"
artifacts/bin/lab vm inspect -manifest lab/images/arch-20261001-x86_64.json \
  -agent artifacts/bin/lindm-agent -allow-network -record "$work/arch-inspect.json"
artifacts/bin/lab vm dispatch -manifest lab/images/arch-20261001-x86_64.json \
  -repo . -lindmd artifacts/bin/lindmd -allow-network -record "$work/arch-dispatch.json"
```

The stock Arch image orders initial pacman keyring population and SSH after
time synchronization. These connected commands explicitly permit user-mode
egress for the vendor's first-boot services; the default lab network remains
restricted. This is recorded as `user-egress`, not air-gap qualification, and
does not change host networking or disable guest signature/time checks.
Pass `-diagnostics DIR` only for private troubleshooting: a failed inspection can
retain the complete raw host/package observation in a mode-0600 file there.
These diagnostics are not the redacted `-record` qualification evidence.

The guest trusts only the separately pinned development package key in an isolated
pacman keyring and requires both package and database signatures. Removal retains
protected identity/state and the system account; Arch has no separate DEB-style
purge operation. These commands qualify only the recorded image/repository
snapshot, architecture and exercised capabilities, not newer rolling snapshots,
desktop sessions or whole-system update/rollback. See
[rolling qualification semantics](verification.md#1-launch-platform-qualification).

### Running the control-plane authority lane

Use a genuinely older installed package and a current second build, plus separately
built current `lab` and `lindmd` binaries. Add these options to either native
lifecycle command above, using new output paths:

```sh
-control-plane-trust -lindmd /absolute/path/to/lindmd
```

Stamp the server with an actual release when building the laboratory executable,
for example `go build -ldflags '-X lindm/internal/agent/buildinfo.Version=0.1.0'
-o /absolute/path/to/lindmd ./cmd/lindmd`. Unstamped development identities are
not silently registered as supported releases. Both lifecycle modes use the normal
authenticated release-management API to register the server's reported identity
and the two actual signed package versions under test; no version is inferred from
an image name. This also applies to the shared server used for signed service lanes.

This mode is exclusive with `-execution-trust` and `-service-execution`. Those manual
variants normally enroll against the shared development console; add
`-local-authority -lindmd /absolute/path/to/lindmd` to run them against the same kind
of private server and local password/WebAuthn owners instead (remote hosts always do
this). The private server receives the fixture's public execution root, so the
offline-signed trust updates and service intents are unchanged. In every private mode
the lab creates a unique disposable PostgreSQL database and starts the real server on
private host ports. Only lab code uses the protected development PostgreSQL admin
credential to create/drop that database; the server receives its non-superuser
migrator credential. Production database option validation is unchanged. Shared
application data, roles, Keycloak configuration and execution authority are not
modified. Owner login retains certificate/hostname validation, CSRF and S256-PKCE;
private transports and guest tunnels preserve the logical public origins.

The lane admits delegation through the real owner API and waits for the installed
network process to synchronize it, without `trust-update`. It exercises quorum and
rollback denials, root rotation, empty-delegate revocation and historical retry
after a real server restart, then retained root facts across reboot/reinstall.
A dormant owned service has a persistent start marker, positive-controlled before
the observation window, to detect unintended start/stop cycles even if systemd
discards its in-memory timestamps. This is a no-effect check, not service execution
qualification. Cleanup stops and joins the private server before dropping its
owned database without force.

### Running the connected service-dispatch lane

With the development PostgreSQL/Keycloak dependencies running, initialize the
development enrollment trust with `go run ./cmd/dev trust` if it is absent (for
example after a dev reset). Build current `artifacts/bin/lab` and
`artifacts/bin/lindmd` binaries; the lab executable must be portable to the guest,
so use `CGO_ENABLED=0 go build -trimpath -o artifacts/bin/lab ./cmd/lab`. Then run:

```sh
artifacts/bin/lab vm dispatch \
  -manifest lab/images/ubuntu-noble-amd64.json \
  -lindmd artifacts/bin/lindmd -record "$HOME/.cache/dispatch-ubuntu.json"
artifacts/bin/lab vm dispatch \
  -manifest lab/images/fedora-44-x86_64.json \
  -lindmd artifacts/bin/lindmd -record "$HOME/.cache/dispatch-fedora.json"
```

Allow both real five-minute reconcile intervals: each periodic wait has an
eight-minute deadline, and the overall command has a 50-minute budget plus any
`-hold` duration. An external runner should allow at least 55 minutes per guest
plus that hold duration so owned cleanup and evidence writing can finish. Run
the guests sequentially when sharing host VM capacity.

Device revocation and cleanup use the normal two-human approval workflow. A
separate test-owned Keycloak administrator is created only when the first tracked
device needs revocation, then deleted at cleanup. Every independent decision uses
the shared laboratory approval helper to authenticate afresh: code/PKCE for the
directory fixture, password plus WebAuthn for local native fixtures. This also
handles sessions expired during long scenarios or invalidated by account
revoke/restore negatives. HTTP 401 on logout means the old session has no logout
authority; it never substitutes for the required new login. Disabled accounts
still cannot authenticate. No timeout extension, keepalive, authentication bypass
or automatic mutation retry is introduced. The record includes the
requester/approver IDs and exact approval.

Use new record paths. This command builds the real agent into a development-signed
RPM or signed APT archive using the lifecycle package path, installs it in an owned
disposable guest, and starts a real isolated server/database with fresh online
plan/start keys. The owner admits their offline-root-signed delegation through
`UpdateExecutionAuthority`; no lab signer issues plans or start grants and no
manual service-prepare/start commands are used. The guest imports trust and relays
dispatch automatically. Fedora and RHEL must remain SELinux Enforcing. RHEL
manifests use the same RPM dispatch path; enabling that path is not evidence of
a passing RHEL run.

Before enrollment the lab installs an inert `labdispatch.service` fixture and
checks its inactive/disabled baseline using independent `systemctl`. Profile
revision 1 enables/starts it. Assignments request `reconcile_interval_seconds=300`
through the normal assignment API, and the returned interval must match.
Without changing the initial assignment, the lane waits for a higher-sequence
periodic successful check with `COMPLIANT` evidence, no start grant and no extra
native start. It then runs guest `systemctl disable --now labdispatch.service`
out of band, independently confirms inactive/disabled state, and waits for the
next periodic action to observe that drift, obtain a start grant and finish with
`DRIFT_REMEDIATED` evidence. Independent `systemctl` must again report
active/enabled, with exactly one additional native start. Both checks require
new action IDs, increasing sequences and fresh server verification/device
observation timestamps; no assignment churn, shortened production timer or
manual execution RPC triggers the rechecks.

Revision 2 then disables/stops the unit with a higher resource sequence.
A further action remains open during a real server restart and must complete
under the same action ID. Reassigning unchanged desired state must succeed
without a start grant. Two further assignments must succeed with guest
network time disabled and its clock stepped first +90 seconds and then −90
seconds relative to the host. Each case restores the guest clock and its original
NTP setting. Certificate and admitted trust validity are never weakened.
Revocation must deny another assignment, be observed by the automatic transport
and leave native state unchanged. Each completion must contain verified device
history, and remain in `recent_actions`.
A persistent native start witness detects extra starts; assignment intervals,
periodic compliance snapshots, verification/observation timestamps, IDs, sequences,
package/image/lab/server digests and native observations are recorded.
Failed runs can also produce a record with `passed: false`; successful evidence
is returned only after owned server/database/VM cleanup.

Add `-hold 45m` (maximum one hour) to inspect the live authenticated console after
the execution scenarios and before revocation. This mode reserves
`127.0.0.1:18444` at startup; the ordinary dev server must not be running there.
The printed origin is `https://localhost:18444`, with the existing development
transport CA (`.cache/dev/transport-ca.crt`) and normal Keycloak callback. Trust
that CA in the browser; no certificate-error bypass is provided. Sign in through
Keycloak as `owner` using the protected `.cache/dev/owner-password` file.
The lab prints `DISPATCH HOLD READY` only after successful pre-revocation checks.
The device and automatic relay remain active for browser assignments. Timeout or
SIGINT ends the hold, obtains a fresh automated owner session, waits for outstanding
work to settle, re-reads native state, then runs revocation and owned cleanup.
The final record notes whether the assignment head changed during browser
inspection. Records are written after cleanup, not when the hold begins.

Unstarted supersession is **covered by integration test, not natively exercised**.
Minting is acquisition-driven and the executor holds the mTLS signer, so stopping
it prevents acquisition rather than deterministically pausing before preparation.
No test-only product fault seam or fabricated native result is used. This lane
does not replace the local trust-rotation lifecycle scenarios, whose mutual
exclusion remains intentional.

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
aliased, nonpersistent oneshot and legacy-include services. An eleventh phase
requires systemd to load a valid procfs-backed drop-in whose actual bytes exceed
its reported size, then verifies conflict without runtime/enablement changes and
restoration of the original definition after fixture cleanup. The host checks the
exact required scenarios and their native identity/state bindings, not only a
record count. Fedora enforcement is checked before and after the scenario.
Success follows fixture cleanup and complete VM teardown.

The production provider uses typed `ServiceDesiredState` and systemd D-Bus:
Observe → Plan → Apply → Verify. It never accepts executable paths, arguments or
unit contents. A plan binds the canonical unit, boot, native state and protected
unit-definition fingerprint; changed preconditions prevent effects. Native job
completion alone is not convergence. A submitted effect with lost/canceled
observation remains uncertain, not implicitly canceled or rolled back.

Job completion subscriptions use the pinned manager's sender, object path,
interface and signal name, not bus-side argument filters. AlmaLinux 9's
dbus-broker 28 accepts an `arg2` unit-name filter but incorrectly checks the
first argument's type: `JobRemoved` (`uoss`) starts with an integer, so valid
completion signals are dropped. This previously left completed services
uncertain until the 90-second provider deadline. The provider checks the exact
sender, job ID/path, canonical unit and result locally before re-observing
convergence. This retains the existing authority, timeout and uncertainty rules
without relaxing SELinux or retrying native effects.

Legacy `.include` prefixes in fragments or drop-ins are unsupported: older native
parsers can load files outside the definition set reported by systemd. Convert
such definitions to native drop-ins before managing them. The bounded reader
screens physical-line prefixes across read boundaries, including BOM and NUL
handling; it conservatively refuses those prefixes inside continued lines too.
Ordinary comment and assignment-value mentions remain accepted. Accepted bytes
retain their existing fingerprint encoding; historical signed records are not
rewritten.

The definition reader also requires actual EOF immediately after the reported
file length. Regular-file type and stable metadata alone do not prove that all
bytes were hashed: procfs can expose nonempty files with size zero. Unreported
bytes or an inability to establish EOF cause conflict, not an accepted partial
definition. Stable ordinary files, including empty files, retain their existing
hash encoding. Filesystem reads still use cooperative cancellation; a blocked
kernel read is not made interruptible by a context check.

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
implies `-execution-trust` and requires packages implementing the typed service
RPCs and current journal schema. Package binary upgrade lanes remain supported;
historical journal schema-upgrade lanes are not. Keep the actual control
plane/Keycloak/PostgreSQL running and product inventory timers unchanged.

The lab signs narrowly scoped disposable authority, authenticates the root challenge
against its separately pinned device CA, and relays through the installed agent as
the network UID. The installed sandboxed root service performs enable/start,
runtime-only stop/start, no-op verification and enablement-only changes. Independent
native queries check outcomes and absence of effects after forged signature,
plan-domain start, stale precondition, expired grant, same-boot restart and revoked
delegation. Exact replay preserves terminal evidence.

Failure assertions retain the complete public `ServiceExecutionStatus`, including
before/verification observations and accepted/started/completed timestamps, rather
than replacing it with a generic success mismatch. The packaged signed-service
lane also collects a bounded action-UUID-filtered agent/executor journal tail.
Only fixed nonsecret message-reason classifications, unit, numeric priority and
timestamp fields are retained; all free-form message content and unrelated units
are withheld. Empty matching history remains explicit absence, never a success.

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

## 7. Verified unattended agent-only updates

P20/L08/L17 update execution is an explicit root-owned opt-in. Add an `updates`
message to `/etc/lindm/executor.json`; preserve its other existing fields:

```json
{
  "updates": {
    "repository_url": "https://devices.example/updates",
    "ring": "stable",
    "poll_interval_seconds": 3600,
    "manager": "NATIVE_UPDATE_MANAGER_APT"
  }
}
```

The repository endpoint must use the bootstrap transport CA. It is transport
location, not release authority: the executor loads the separate release TUF root
from its already authenticated protected bootstrap journal. There is no network
trust-on-first-use or unsigned override. `manager` is one of APT, DNF, ZYPPER,
or PACMAN, selected by the administrator for the native mutable OS. OSTree and
NixOS are refused and require their distinct image/generation providers.
Only the `lindm-agent` native package is eligible, never `lindmd`, `lindmctl`, an OS
upgrade, or a transport-selected executable.

The normal unprivileged `run` process polls without an operator command or a
currently supported executable-plan session. Polling is independent of inventory
and heartbeat scheduling. The executor's config determines its cadence
(1–86,400 seconds; one second is for isolated lab rejection/expiry observation,
not the recommended production interval). Absence of executor update config
disables new admission. The network process uses protected connection CA material,
rejects redirects and sends bounded HTTP range reads. `ExchangeAgentUpdate`
accepts at most 256 KiB for one outstanding executor-generated request UUID,
relative path, offset, and limit. The root process never performs HTTP transport.
Both sides refuse updates in protected live-root report-only mode.

The maintained TUF client checks role signatures, rotations, expiry, rollback
high-water marks, catalog identity and compatibility before selecting a target.
The installed stamped release and actual package architecture constrain selection;
the signed catalog supplies an exact native package version as well as upstream
`x.y.z`. Root streams at most 1 GiB into a protected staging file and rechecks its
signed length/hash, product, native version and architecture before effects.
Metadata/catalog transfers are separately bounded. An interrupted download is
not an admitted native transaction.

The immutable transaction records the earliest expiry of the catalog and complete
verified TUF role chain. The helper checks it again immediately before its first
native write, after dependency previews: a merely staged package cannot initiate
an install after expiry. Past expiry, an already consumed transaction may repair
only observed own-package effects (target database state, incomplete/absent state,
or native payload divergence from the recorded exact predecessor). An intact
predecessor is not proof of an interrupted install. An expired unstarted transaction
is durably `rejected`; a later fresh signed selection may replace it without
resetting installed-version high-water marks. Signed pause/rollout changes stop
future selection; they do not claim to cancel an already started native transaction.

Arch catalogs also bind the detached `.pkg.tar.zst.sig` as its own signed TUF target.
The executor streams and verifies that bounded signature beside the package;
Pacman's existing native signature/keyring policy is not disabled or replaced.

### Native transaction and reboot recovery

Protected state is under `/var/lib/lindm/executor/updates`:

- `state.pb` is an atomic, fsynced protobuf checkpoint containing the installed
  version high-water mark and immutable current transaction. Missing/corrupt
  checkpoints in initialized state fail closed.
- `tuf/` retains the verifier's protected metadata/version checkpoints.
- `<transaction-uuid>/transaction.pb`, `lindm-agent_<native-version>_<arch>.deb`/
  `agent.rpm`/`agent.pkg.tar.zst`, and `helper` bind the exact admitted native
  transaction. Debian staging uses APT's canonical archive filename (with native
  version `:`/`_` percent-escaped) and the same private directory as its cache;
  `--no-download` therefore resolves the verified archive without copying/linking
  it or consulting unrelated caches. Native package and network security gates
  remain unchanged.
  `helper` is a bounded copy of the known-current running executable, not a
  path inside the package being unpacked. Its exact source SELinux executable
  context is preserved on that single owned file; no permissive mode or broad
  directory relabel is used.
- `<transaction-uuid>/helper.pb` records the detached helper's `installing`,
  `installed`, `rejected`, or `recovery_required` phase durably.

Transaction staging retains the durable journal's current UUID, including its
terminal recovery evidence, plus at most the next in-flight download during
cutover. Before another download, superseded terminal transactions and abandoned
pre-admission staging are reclaimed only with protected custody, an exclusive
transaction lock, no active helper and no remaining persistent recovery unit/link.
The new transaction's journal admission must be durable before the prior current
UUID becomes reclaimable. Retirement first renames to `.retired-<uuid>` and fsyncs
the parent; interrupted deletion can then resume without trusting partially
removed receipts. Unresolved or ambiguous helper state and unsafe filesystem
entries block new staging rather than deleting recovery material or accumulating
unbounded packages. Neither reclamation nor unit cleanup removes another active
transaction's recovery state.

The executor records `staged` then `applying` before launching
`lindm-agent-update-<transaction-uuid>.service` through systemd. This independently
owned cgroup resides in `lindm-updates.slice` and has no `Requires`/`PartOf`
relationship to executor/network services; native package scripts can stop or
replace those services without killing it. The lab may apply a runtime-only I/O
limit to that slice to observe the actual native transaction before power loss.
Before native effects, the helper fsyncs the owned
`/etc/systemd/system/lindm-agent-update-recovery.service` and its multi-user boot
link. That service executes the preserved helper after a power loss, even if the
installed binary is partially unpacked. `Type=exec` releases startup ordering
after the recovery executable has started, avoiding a dependency deadlock when
native post-install scripts synchronously restart the executor. The unit and
owned link are removed after verified native completion or a proven unstarted,
expired transaction's durable rejection.

Both helper services use `PrivateNetwork=yes` and `RestrictAddressFamilies=AF_UNIX`.
The helper additionally refuses to run in PID 1's network namespace. Native argv
is fixed, not supplied by metadata or the network. APT uses an empty private cache,
no source files/downloads/removals and a preview that refuses unrelated packages.
DNF/Zypper disable repositories and weak/recommended dependencies; Pacman must
resolve exactly the local agent target. Missing dependencies fail rather than
silently installing unrelated content. Native signature policy remains in force.
Zypper's local-install flags follow its
[native command contract](https://manpages.opensuse.org/Tumbleweed/zypper/zypper.8.en.html).

Recovery first observes the exact native installed package/version/architecture.
Only the signed target or its recorded exact predecessor may be repaired.
APT distinguishes fully installed from unpacked/half-configured states, configures
only `lindm-agent`, and re-unpacks only its staged package if an interrupted unpack
requires it. RPM recovery may reinstall the exact admitted package after observing
its database state; it never treats a version row alone as completed scriptlets.
Success additionally requires native payload verification, the exact installed
executable version and a durable helper completion record. DPKG verification may
report exit 1 for deliberate owner conffile edits (including update configuration);
only strictly parsed conffile-only differences with no diagnostic stderr are
accepted, and the installed database/executable checks still apply. Other payload
differences, malformed output or operational failures cannot establish success.
Unknown/failed state remains `recovery_required`; there is no blind downgrade or
whole-system repair.
Update admission and imperative action gates mutually exclude native effects,
including unresolved consumed recovery-boot grants across executor restart.
Disabling polling does not clear an unresolved update's destructive-action fence.

### Runtime evidence for the native laboratory

Root may run `/usr/libexec/lindm/lindm-agent update-status`. This reads
`GetAgentUpdate` and emits protobuf JSON with `status.phase`, `version`,
`transaction_id`, `reason`, `observed_at`, `attempt_started_at`,
`attempt_finished_at`, `last_outcome`, and `last_metadata_at`.
Attempt/metadata timestamps are persisted; a repeated old success is not fresh
rejection evidence. Rejected refreshes retain the prior installed version and
record a new `rejected` outcome. Acceptance/staging is never reported as installed.

For the Ubuntu/Fedora VM lane, configure the explicit lab cadence, publish
compatible signed N and N+1 packages, and wait for fresh native installed evidence.
To test power-loss recovery, observe durable `installing` plus the actual apt/dnf
process in the owned helper cgroup, then power-cycle the disposable guest. Merely
interrupting a download does not establish native recovery. Preserve the package
database status, helper/systemd journals, installed executable version, identity
and protected checkpoints as evidence; Fedora must remain SELinux Enforcing.
Expiry tests use actually elapsed signed timestamp expiry, not a fake guest clock.
Tampered, mismatched, expired and downgraded targets must not change installed
package state. These are runtime contracts and regression coverage, not claims
that any unrun VM or physical platform gate passed.

## Research anchors

- [DSSE specification and implementations](https://github.com/secure-systems-lab/dsse).
- [Go DSSE library](https://pkg.go.dev/github.com/secure-systems-lab/go-securesystemslib/dsse).
- [Go TUF implementation](https://github.com/theupdateframework/go-tuf).
- [Ubuntu image authenticity and trusted signer verification](https://documentation.ubuntu.com/security/software-integrity/image-verification/).
- [Ubuntu cloud-image checksum verification and distinct UEC signer](https://ubuntu.com/docs/public-images/public-images-how-to/verify-image-checksum/).
- [Go message-aware signing interface](https://github.com/golang/go/blob/go1.26.9/src/crypto/crypto.go).
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

## Console enrollment operator flow

The Enrollment page retains interactive one-use grants and adds separately bounded
provisioning tokens. Issue a token with an expiry, maximum use count, approval
requirement, labels/owner/typed attributes, static group IDs and an immutable service
profile revision. The server validates current scope and assignment authority;
entering a UUID does not grant authority. The paginated list exposes assignments,
use count, issuer, expiry and revocation, never secrets. Revoking a token stops new
redemptions and pending issuance, not already enrolled device credentials.

Token issuance calls do not use a mutation/query cache. Secrets and generated
installer inputs exist only in the issuing component until dismissal, navigation
or authentication-lifetime teardown. Explicit downloads are the operator's
sensitive copies; the browser uses a transient local Blob handle and immediately
revokes it, never a credential-bearing network URL. A lost issuance response is
not recoverable: retry the exact request to identify its token, revoke that token,
and issue a replacement with a new request ID.

The one-time result is task-shaped: choose the **Installer format**, then the
**Operating system**, and copy one snippet. The platform registry
(`internal/platform`, `Release.Provisioning`) declares which vendor formats each
release's installation media support, and the server projects them as
`EnrollmentPlatform.provisioning_formats`; the console never infers a format from
the package family. Offered formats: cloud-init (cloud images of every packaged
release), Ubuntu autoinstall (subiquity on Ubuntu 22.04/24.04/26.04 only — not
Debian or Ubuntu derivatives), Kickstart (Anaconda on Fedora and the EL family),
AutoYaST (openSUSE Tumbleweed, SLES/SLED 15; Leap 16.0's Agama installer is not
modelled) and NixOS (a visible design-only gate; see below).

Every snippet embeds the server's complete install script: it verifies any private
HTTPS CA against its pinned SHA-256, the package signer's full fingerprint and the
execution-root SHA-256, adds only this server's signed repository, installs
lindm-agent and the authenticated bootstrap material, and installs
`lindm-provision.service`. No agent, repository, CA or bootstrap may be preinstalled;
the snippet is merged into the operator's complete trusted installer configuration,
not substituted for it. The unit runs no script from `/etc`: `ExecStartPre` waits at
most 30 seconds for the executor, then two `ExecStart` lines run the exact
`provisioning_command` (`bootstrap -root … -bundle … -provisioning-token-file
/etc/lindm/provisioning-token`) and `resume -wait-seconds 3600`, under
`TimeoutStartSec=3700`. `ExecStartPost` removes the token only after successful
installation; pending approval is not reported as installed. After a timeout or
transient error, restarting the unit retries the same protected transaction/key;
it never resets the journal.

- **cloud-init** writes the token as root:root 0600 (`write_files`) and the unit,
  then `runcmd` runs the install script on first boot, enables and starts the
  executor and network units, enables the provisioning unit and starts it with
  `--no-block`. The approval wait can last an hour; a blocking start would hold
  cloud-init's final stage and, through `systemd-user-sessions.service`, logins.
- **Ubuntu autoinstall** delivers the same cloud-config as `autoinstall.user-data`,
  which subiquity hands to the installed system's cloud-init for its first boot.
  No secret appears in a `late-commands`/`curtin` argument. The installed system
  needs network on first boot, not in the installer.
- **Kickstart** (`%post --erroronfail`) and **AutoYaST** (a `chrooted` chroot-script)
  run the install script inside the installed target before its first boot, using
  the installer's network, DNS and the target's CA store. The installer network must
  be active (Kickstart `network --activate` or the installer default). The target's
  systemd is not running in that chroot, so the snippet only enables units (and the
  package scriptlet's `systemctl restart` is a chroot no-op); enrollment occurs on
  the first boot. The token is written through a quoted, base64-encoded heredoc
  (encoding is not encryption). Where SELinux is enabled the snippet restores the
  labels of `/etc/lindm` and the unit file. DNF and zypper install their
  prerequisites only when `rpm -q` lacks them, because an unregistered RHEL DVD or
  offline target may have no distribution repository. zypper refreshes and searches
  only lindmd's repository (`--reposd-dir` holding a copy of `lindm.repo`), so
  install media or unreachable mirrors listed in the target cannot fail or redirect
  the install. Kickstart fails the installation on any error; an AutoYaST
  chroot-script failure is only reported by YaST, so check
  `/var/adm/autoinstall/logs/` (script `lindm-enroll.sh`) when the device does not
  appear.
- **NixOS** is gated in the registry. lindmd serves agents only as signed native
  APT/RPM/pacman repositories and no NixOS artifact; a module that requires an
  externally hosted derivation would violate the self-hosted model, so the console
  shows the gate reason instead of a snippet. The design is in
  [atomic-nixos](platforms/atomic-nixos.md#self-hosted-nixos-installation-design).

All generated seeds require controlled delivery and retention. Installers retain
copies outside the token file, and removing that file is not forensic erasure:
cloud-init keeps `/var/lib/cloud/instance/user-data.txt` (and the seed source);
subiquity keeps `/var/log/installer/autoinstall-user-data` and writes the user-data
into `/etc/cloud/cloud.cfg.d/`; Anaconda keeps `/root/anaconda-ks.cfg` and
`/root/original-ks.cfg`; AutoYaST keeps its profile and scripts under
`/var/adm/autoinstall/`. Delete these after enrollment where the site keeps them,
never bake credentials, journals, installation markers or keys into a reusable
image, and revoke unused credentials within their bounded lifetime.

Enrollment transactions expose pending, ready, rejected, expired and held lifecycle
facts as returned by the server. The existing Approval inbox presents the exact
pending-enrollment payload. A different authorized human approves or rejects;
the original requester executes the approved payload. Current scope, expiry and
no-self-approval remain server-enforced. The agent's bounded root resume installs
only the identity-bound response after approval.

Offline enrollment uses three strict protobuf-JSON files: authorization, device
request and signed response. Issue authorization using a provisioning token and the
authenticated bootstrap root version/digest. On the offline device, run
`offline-export -root ROOT -bundle BUNDLE -file AUTHORIZATION -out REQUEST`.
Import that request in the console, complete any approval in the inbox, and export
the response using the same request file. Return it to the same installation and
run `offline-import -file RESPONSE`. Interrupted request export uses
`offline-export -resume -out REQUEST`. Files require root ownership and mode 0600;
browser downloads do not enforce those permissions. No private key travels with
the files, and signed response export is not proof of installation or first contact.

Device detail's Encryption / Actions tab offers explicit reinstall/identity
recovery, with a stronger hold warning when clones or divergent identity evidence
are present. Retype the device ID and give independently verified linkage evidence
to request a two-person approval bound to its current generation and revocation
state. A changed generation or later revocation requires refresh and a new approval;
earlier authorization cannot silently override that revocation. The requester
executes the approved recovery payload in the inbox and receives a one-time grant
for the selected device. Successful consumption retires all old-generation
credentials. Hostname/serial/MAC/TPM hints never authorize merging, and the UI never
offers blind release of the ambiguous old identity.

This console slice adds generated-output regression coverage in
`test/tooling/enrollment-snippets.test.mjs`. Its author did not run web checks,
browser acceptance or native installer lanes; final integrated verification remains
parent-owned. The snippets do not claim new native-package/platform qualification.
