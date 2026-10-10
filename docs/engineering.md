# Engineering and developer experience

Status: control-plane implementation in progress. Commands listed in the root README
run against actual application sources and a real PostgreSQL/Keycloak lab. Broader
agent, platform and release gates below remain requirements, not passing targets.

## 1. Maintainability standard

Follow the [Google Go style guide](https://google.github.io/styleguide/go/guide),
[decisions](https://google.github.io/styleguide/go/decisions), and
[best practices](https://google.github.io/styleguide/go/best-practices): clarity,
simplicity, explicit contracts, ownership and useful errors. This is an engineering
standard, not a claim of Google certification. Linters cannot certify maintainability.

- One Go module initially, small cohesive `internal` domain packages, concrete types
  by default, interfaces at real consumer/test boundaries and explicit constructors.
- Separate transport/auth, domain decisions, SQL persistence, agent reconciliation
  and OS providers. Do not put business authorization exclusively in RPC middleware.
- Context deadlines/cancellation, structured errors, no panic for routine failures,
  no hidden global state, no goroutine without bounded lifetime/backpressure.
- Review allocations and copying on agent/inventory/artifact paths. Stream artifacts,
  paginate queries, cap batches and reuse expensive clients. Benchmark before adding
  pools or abstractions; never load whole packages into memory for convenience.
- No generic repository framework, universal workflow DSL, homegrown PKI/crypto,
  cross-distro shell template engine, or speculative plugin SDK.
- Generated protobuf/sqlc code is committed, marked generated and reproducible.
  Handwritten changes to generated output are forbidden. SQL remains reviewable.
- Every provider states privileges, version/capability checks, state transitions,
  idempotency/recovery, ownership, rollback limits and evidence required for success.
- Every permanent bug fix gets a deterministic regression test when practical.
  Tests protect consumer-visible behavior, boundaries, authority and durability—not
  source text, mock echoes, incidental defaults or copies of implementation details.
  Do not add tests for Git hooks, formatter invocation, command forwarding or other
  third-party tooling glue. Running the normal command is sufficient verification.
  Each proposed test must identify a plausible product failure it would catch.
- Public APIs and irreversible migrations require design review. Sensitive execution,
  auth, update, encryption and wipe changes require security-owner review.

### Schema and runtime validation

Versioned protobuf messages define serialized configuration and RPC contracts.
Configuration uses strict protobuf JSON decoding: reject unknown fields rather than
silently ignoring misspelled security settings. Do not maintain a parallel Go struct
schema or handwritten copies of field bounds.

Use `buf.validate` built-ins first, message CEL for cross-field relationships, and
[predefined rules](https://protovalidate.com/schemas/predefined-rules/) for repeated
domain constraints. `api/lindm/validation/v1/string_rules.proto` owns HTTPS
origin/endpoint restrictions, required file references and audit reasons. These
extensions remain CEL-backed and deterministic; they are not hooks for arbitrary
Go code or I/O. Combine URL restrictions with the standard URI validator. Prefer
structured messages and existing validators to inventing grammars: listener
configuration separates a validated IP address from a bounded port.

Custom Buf lint/check plugins inspect schemas, not runtime values. Add one only for
a concrete, reviewed schema policy that existing Buf checks cannot enforce. Do not
build a plugin framework merely because the extension mechanism exists. Private
extension numbers must be registered before publishing schemas for external
composition.

Filesystem permissions, certificate signatures/trust, authorization, database
constraints and transitions are checked where the corresponding resources and state
are available. They cannot be established by static schema validation. Compile
validation rules during service initialization; do not first discover malformed CEL
on a production request. RPC and configuration paths use the same schema semantics.

Database credential files contain explicit PostgreSQL URLs (host, user and database)
with `sslmode=verify-full`. Nonempty `PG*` environment settings, service/pass files,
duplicate options and unknown URL options are rejected rather than silently changing
the serialized deployment configuration. Supported options are `sslmode`, `sslrootcert`,
`sslcert`, `sslkey`, `application_name`, `target_session_attrs`, `channel_binding`,
`require_auth` and `sslnegotiation`. Host lists use PostgreSQL failover syntax,
including individually specified ports and bracketed IPv6 addresses.
`load_balance_hosts` is not supported by the pinned driver and is rejected.

The checked loader reads database trust roots and client keys through the same owned,
bounded regular-file descriptors as other resources; pgx does not reopen those paths
or read home-directory credential defaults. Relative references resolve from the
configuration directory. Empty/system `sslrootcert` uses system trust. TLS server,
database-client and device-CA certificates must permit their intended extended key
usage; a valid signature/key pair alone does not establish that.

### Frontend structure and framework

The console uses React with TanStack Router for typed file-based routes and
TanStack Query for server state. Vite produces static assets served by the Go
backend; no second Node server or SSR framework is required for the authenticated
console. Use official shadcn/ui blocks and components with Tailwind CSS semantic
theme tokens, not a parallel bespoke component library or sample dashboard data.

Copied shadcn sources retain provenance and MIT notices in `web/LICENSE.shadcn`.
The console does not depend on the generator CLI at runtime or build time. Its
required utility stylesheet is vendored with attribution; the CLI was removed from
the development dependency graph after an unresolved transitive advisory. Generated
UI remains owned, reviewable source rather than a reason to suppress dependency audit.

The console applies [shadcn preset `b1Q5GC`](https://ui.shadcn.com/create?preset=b1Q5GC&template=vite):
Nova (Base UI registry `base-nova`), neutral base, blue theme, zero radius,
IBM Plex Sans with inherited headings, Lucide icons, default/solid menus with
subtle accent, and neutral chart colors. These settings were confirmed through
the create page in Chromium and `npx shadcn@latest preset decode b1Q5GC --json`
(CLI 4.21.4). The [official CLI](https://ui.shadcn.com/docs/cli) supports
`apply --preset b1Q5GC`; it was run in an isolated Vite scratch copy before porting
theme variables and regenerated primitive changes. Keep the existing `cn` alias
and vendored utility stylesheet; do not add the CLI to `package.json`.
IBM Plex Sans is an exact-pinned Fontsource package bundled by Vite, not a runtime
CDN fetch; its redistribution notice is `web/LICENSE.fonts`. No Next.js, pnpm,
remote fonts, analytics, or runtime registry requests are introduced.

The sidebar-07-derived shell groups authorized pages under Fleet, Security and
Administration, with explicit device/profile breadcrumbs and a closable mobile drawer.
Groups covers both account and device groups. The shell has collapsible navigation,
a role/break-glass account menu, keyboard skip link, and a locally persisted
light/dark toggle. Control/Command-K opens the official command palette with
navigation and search within the first 200 authorized devices; it does not claim
an unbounded fleet search. Dialog labels remain inside their accessible portal.
Feature pages use consistent headings, responsive controls, skeletons, and
actionable empty/error states. Toasts report accepted mutations, not proof of
native execution, and never contain enrollment/recovery secrets. Inline normalized
errors and ambiguous same-request-ID recovery remain authoritative; no mutation
retry behavior changes.
Forms compose the official shadcn Select rather than native dropdowns; controlled
enum conversions, disabled state, and named uncontrolled form values are preserved.
Long operational caveats live in accessible info tooltips or help disclosures,
while destructive confirmation warnings remain visible.

Console copy uses concise sentence case and names the operator's next action. Use
commas, colons or periods rather than em or en dashes; ESLint checks string literals,
template text and JSX text in handwritten `web/src` code. Distinguish unavailable,
unknown, stale and empty results. A failed read must not look like an empty list or
a successful refresh. Use `RpcError` for classified failures and expandable technical
details, preserving ambiguity and request identity rather than retrying mutations.
Compose page headings and empty results with `PageHeader` and `EmptyState`.
Use `StatusBadge` for statuses, not ordinary category or role labels: success means
the stated condition is confirmed, warning needs attention or has an uncertain
outcome, destructive denotes failure or revoked authority, neutral denotes unknown
or inactive state, and info denotes progress or an informational state. An active
enrollment is not a claim of device health. Status text remains visible independently
of color; optional dots are decorative. The five semantic tones have light/dark
tokens, separate from the preset's blue action and neutral chart palette. Keep
the preset's zero radius, bundled font and theme parity.

RPC presentation uses the Connect code and `Lindm-Reason` together. Known missing
capabilities or inventory are neutral; stale data, permission and re-authentication
requirements are warnings with a next action. Internal, unknown and unrecognized
failures remain errors, with the server's diagnostic details available on demand.
Do not suppress backend failures or turn a failed read into an empty result.

Advisories show each configured source's refresh state, last successful refresh and
reported reason. A failed attempt does not erase the last successful timestamp.
No configured sources is a setup state, not a refresh failure. Stale or missing
coverage explicitly means exposure counts may be incomplete.

Profiles distinguish saved revisions from assignments; Rollouts owns deployment.
Enrollment separates one-time grants, unattended tokens and offline signed files.
Device action forms use dialogs for short operations and dedicated pages for
storage, encryption and recovery workflows. Keep one concise warning at confirmation;
put policy explanations in Details. Preserve typed confirmation, independent approval,
exact target identity and uncertain-request recovery. Accepted is not completed.
Approval cards lead with the requested effect and target, human permission labels
and requester names. Keep raw identifiers and payload hashes in Details without
changing the exact approved payload. Names are display context, never authority.
Storage actions select server-returned inventory targets and display their exact
stable identity read-only. Never ask operators to transcribe LUKS UUIDs, WWNs,
serials, sizes or native NVMe identity. Missing or stale observations require a
fresh inventory action; they are not blank forms or permission to guess. Wipe
confirmation uses the displayed hostname, falling back to the device ID only when
no hostname was reported. Signed action targets remain exact observed identities.
Recovery handoff forms and approval review show the server's readiness decision,
observation time, EFI partition, signed artifact size, required/free space, Secure
Boot and UKI capability. Missing, stale or insufficient observations block new
approval/submission; exact ambiguous-request recovery remains available. Never
treat locally configured artifact size as signed release metadata.

Device Overview leads with the latest observed machine, hardware, network and
encryption fields, compliance, ownership and last check-in. Keep collection states
visible; do not infer a primary network interface or agent version from unrelated
fields. Protocol sequence counters belong in collapsed Diagnostics, not the summary.
Agent version is the current generation's accepted signed-session release and
receipt time, not inferred from installed packages. Network summaries use the
reported per-family default-route markers, and active session names preserve each
collection/field state. Inventory retains the full interface and session tables.

`/dashboard` is the signed-in landing page. Its narrow `GetFleetSummary` admin RPC
uses SQL aggregates across the caller's authorized device scopes, never page
samples or fabricated fleet totals. Lifecycle, contact freshness, service
compliance dispositions, and OS counts describe that complete authorized set.
Service dispositions count current-generation resources, not allegedly compliant
devices; devices without assigned resources are counted separately.
OS groups are bounded to the top 20 with an exact remainder count. Recent contact
means within 24 hours of the database snapshot; absent contact remains unknown.
A separate first-five stale-device preview uses the existing last-contact filter
and links to that filtered list. It is a live read in normal enrollment order,
not an oldest-first list or a source of aggregate counts.
Findings count affected results by severity, excluding accepted/unknown results;
evaluated and unknown active-device populations remain separate. Pending unexpired
approvals honor independent action and inbox-management device scopes. That count
uses identity's fresh-authorization transaction, not the fleet snapshot, and
counts pending records rather than a promise that their requests are actionable.
Existing consume-time fences remain authoritative. Recent
device and service actions are newest-first across generations with a bounded
response. Sections unavailable to a caller remain explicitly unavailable rather
than reporting a misleading zero. Recorded actions are not proof of successful
native execution. Principal-scoped query cancellation and invalidation remain
in force.
The dashboard presents exact distributions as an OS/version donut, service-resource
stacked bar, and severity bars through official shadcn chart primitives and pinned
Recharts, with the preset's neutral chart colors. Exact text legends remain
available independently of the charts; animations are disabled and no trend is
invented where historical aggregate data is absent. Chart custom properties are
scoped using style attributes, not injected style elements, preserving the server's
strict Content-Security-Policy without allowing inline style blocks.

Device tables offer compact single-line rows, relative timestamps with absolute
tooltips, status dots, current-page sorting, column visibility, and density.
The always-visible hostname-prefix/OS/label toolbar retains advanced typed filters.
Hostname prefix matching is literal and case-sensitive. Server SQL applies scope
and the bounded page before projecting the worst current-head service disposition;
no per-row RPC fanout occurs. Last verification is the oldest resource proof only
when every current resource has proof; no resources means unassigned, not compliant.
The prefix participates in cursor filter binding. Sorting never changes server
order or cursor meaning; Previous/Next, expiry, and paged exports remain intact.
Revocation is a row action dialog retaining its existing approval/reason flow and
ambiguous request identity after dismissal. The device header has one permission-aware
Actions menu. Short actions open dialogs; storage, encryption and recovery actions
open dedicated pages with exact target review. Accepted actions link to their status
page; no control claims that acceptance proves native completion. Tabs separate
Overview, Inventory, Services, Encryption, Actions, Findings and History.
Inventory mounts on first activation (or an explicit package-search deep link),
so opening Overview does not silently start an inventory cursor. Encryption and
recovery secrets are cleared on navigation, blur and their existing expiry timers.

For isolated visual acceptance, build embedded assets and run a disposable console:

```sh
npm run build:web
go build -ldflags '-X lindm/internal/agent/buildinfo.Version=0.1.0' \
  -o artifacts/bin/lindmd-ui ./cmd/lindmd
go run ./cmd/lab console -repo . -lindmd artifacts/bin/lindmd-ui \
  -devices 300 -packages 200 -assignment-percent 20 -enrollment-workers 8
```

This uses protected development trust and running PostgreSQL, but not Keycloak or
the shared `:18444` listener. The fixture owns a database and dynamic loopback HTTPS
origin, populates real enrollment/inventory/service RPC paths, prints a one-time
enrollment secret for the separate `console-owner` account, then holds until
interrupted. Treat the terminal output as sensitive. Trust the development CA in
a dedicated browser profile; enroll at the printed `/enroll` URL with a password
and user-verifying WebAuthn authenticator, then sign in. Chromium acceptance may
use a CDP virtual internal authenticator with user verification enabled. Population
is synthetic lab data, not native machine evidence; reporting stops after seeding.
Interrupting the command cleans its owned process/database/material. Never point
the generator at a production tenant or publish enrollment/browser credentials.
The fixture also enables real integration/report RPCs with its own protected,
random encryption key; no destinations or schedules are preconfigured.

Organize `web/src` around working product features:

| Directory                                                      | Responsibility                                                     |
| -------------------------------------------------------------- | ------------------------------------------------------------------ |
| `app/`                                                         | Router, query client and application composition                   |
| `routes/`                                                      | Thin route definitions, loaders and authenticated layout guards    |
| `features/auth/`                                               | Session and sign-in/sign-out lifecycle                             |
| `features/devices/`, `features/enrollment/`, `features/audit/` | Cohesive domain queries, views, actions and local types/components |
| `components/ui/`                                               | shadcn primitives                                                  |
| `components/layout/`                                           | Shared block-derived console shell                                 |
| `lib/`                                                         | Shared RPC transport and narrowly named utilities                  |
| `styles/`                                                      | Tailwind entrypoint and semantic theme tokens                      |

Routes compose features. Shared components/utilities must not import feature or
route internals; features must not reach into another feature's private files.
Keep generated contracts in `web/gen`, not duplicated handwritten API models.
Create a module because it owns cohesive behavior, not to fill every possible
folder. Avoid catch-all utility files, giant application components and compatibility
re-exports left behind by moves.

Clear principal-scoped query state on logout and identity changes. Enrollment
secrets must not enter query caches, persistent storage or URLs. Do not automatically
retry secret-issuing mutations. Preserve cancellation and backend idempotency
semantics rather than relying on framework defaults.

The console discovers enabled sign-in modes through generated protobuf JSON
`GET /auth/options`. Local sign-in requires password acceptance followed by
WebAuthn user verification; it never treats the password challenge as a session.
Use a current HTTPS browser with native WebAuthn JSON conversion support. `/enroll`
accepts a manually entered one-time secret and new password, registers an
authenticator, then directs the user back to sign in. Never put enrollment secrets
in links. Principals with unrestricted `accounts.manage` manage local accounts at
`/accounts`: create, enable/disable, select built-in or custom roles and device
scopes, change break-glass designation, and reset credentials.
Issued enrollment secrets remain component-memory-only and disappear on navigation.
Account mutations send the session CSRF header and are never automatically retried.
Every authenticated route displays a persistent emergency banner for break-glass
sessions, including the incident reason; navigation is not an authorization boundary.

### Planned code layout

| Area                                                                                         | Responsibility                                                                                                                     |
| -------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| `cmd/lindmd`, `cmd/lindm-agent`, `cmd/lindmctl`                                              | Composition and entrypoints only                                                                                                   |
| `api/`, `gen/`                                                                               | Versioned protobuf sources and generated Go/TypeScript                                                                             |
| `internal/identity/`, `internal/device/`, `internal/executionauthority/`, `internal/policy/` | Control-plane domains, typed resolution and owned sqlc persistence                                                                 |
| `internal/config/`, `internal/server/`, `db/`                                                | Checked resources, service composition and reviewed migrations                                                                     |
| `internal/agent/`                                                                            | Unprivileged transport/spool, separately root-owned executor journal/trust, reconciliation and native update supervision           |
| `internal/provider/`                                                                         | Native package/network/service/security adapters with narrow contracts                                                             |
| `web/`                                                                                       | Typed console and browser self-service surfaces                                                                                    |
| `packaging/`, `deploy/`                                                                      | DEB/RPM/Arch and Nix/OSTree delivery, systemd/SELinux/AppArmor, native/OCI/replicated server deployment and local assistance relay |
| `cmd/lab/`, `internal/vmlab/`, `lab/`                                                        | Maintained Go laboratory, signed-image manifests and disposable native-observation VM scenarios                                    |

Create a package when it owns working behavior. Do not create all directories,
interfaces and empty tests up front merely to match this table.

Current agent prerequisites live in `internal/agent/inventory/` (bounded native
observations), `internal/trust/` (DSSE/bootstrap/TLS authority) and `internal/pki/`
(shared certificate-key/usage policy). Canonical observation messages live in
`api/lindm/inventory/v1`; the agent and device RPC use the same package record.
For focused work, run `go test -race ./internal/agent/inventory ./internal/trust
./internal/vmlab` without rebuilding the console or starting databases. Signed-image
tests require GnuPG tools and use isolated real keys plus local TLS servers, not
vendor downloads. Actual pinned image acquisition and native-observation VM scenarios
are separate maintained lab commands, not hidden in unit tests or pre-commit hooks.
Image verification supports detached GNU SHA256SUMS and BSD SHA256 CHECKSUM
(including Rocky), Fedora clearsigned SHA256, and explicit
`CHECKSUM_MODE_DETACHED_SHA512` for signed Debian-style SHA512SUMS. SHA512 mode
requires a detached signature, independently pinned full signer fingerprint and
provenance, and hashes image bytes against the authenticated SHA512 record as well
as the manifest's required SHA256 pin in one streaming pass. Cache identities remain
`sha256-<pin>`; offline reuse rechecks both digests and the signature. Missing or
ambiguous records, invalid signatures, and either digest mismatch fail closed.
This is verifier capability, not current Debian cloud-image authentication:
[Debian's cloud publication](https://cloud.debian.org/images/cloud/) describes
signatures only for legacy OpenStack images, not current per-distribution images.
Unsigned current Debian checksum metadata cannot use this signed mode; no signature,
trusted fingerprint, or vendor qualification is inferred from HTTPS downloads.
Debian 12/13 native lanes instead use `lab/images/debian-12-amd64.json` and
`lab/images/debian-13-amd64.json`, with separately pinned `debian-12-arm64.json`
and `debian-13-arm64.json` for native ARM hosts. These are official netinst ISOs
authenticated by Debian's signed SHA512SUMS. Inspect, lifecycle and dispatch require explicit UEFI
firmware flags for these manifests. The first run installs an unencrypted ext4
guest through Debian preseed with signed Debian repository packages, preserving
vendor EFI/kernel payloads; it never substitutes a direct-kernel boot. Installation
has guest-only network access and requires `xorriso` in addition to normal VM tools.
A successful installer exit is insufficient: a disposable first boot must complete
NoCloud, authenticate fresh pinned SSH, and prove Debian version, ext4 root and the
root-only installer-source marker before the local golden disk is published.
Identity/provisioning probes use noninteractive `sudo sh -eu`; failures
identify a fixed probe label without printing marker contents or relaxing its mode.
The private `<image-cache>/debian-installed` cache binds source ISO digest, recipe
version, architecture/storage and firmware bytes/version. Reuse reauthenticates the
source ISO and checks local disk integrity; the derived disk is not vendor-signed,
and repository packages reflect the signed suite at installation time rather than
a reproducible snapshot. Each normal run uses a fresh overlay and SSH credentials.
These maintained paths are not passing Debian lifecycle or physical-validation
claims until their native commands complete and evidence is recorded.
The additional `*-aarch64.json` Rocky 9.8/10.2, AlmaLinux 8.10/9.8/10.2 and
openSUSE Leap 16.0 manifests independently pin official native cloud-image bytes,
signed checksum metadata and vendor trust anchors. They are not architecture
aliases for the x86_64 images. Run acquisition and offline verification before
native ARM KVM qualification with the execution host's pinned AAVMF firmware.
Neither manifest presence nor a passing x86_64 lane proves the ARM cell.

Native inspection independently observes per-interface default-route membership
through iproute2's netlink JSON (IPv4 main table, IPv6 all tables), rather than
reusing the agent's proc-table parser. Active-session truth uses `loginctl`
properties independently of the agent's `busctl` JSON decoder. Missing optional
properties retain unavailable status; neither oracle chooses a preferred interface
or infers session activity from session counts.

The default native VM lane requires accessible KVM, QEMU, `qemu-img` and
`cloud-localds`. Explicit foreign-architecture runs use QEMU TCG instead; neither
path changes host security or substitutes container observations for a real guest.
The integration lane also exercises real `cloud-localds` cancellation: staging stays
inside the owned private run directory and helper descendants stop before cleanup.
It requires `cloud-image-utils`, but not KVM or a booted guest.

#### Lab host configuration

`lab vm` commands use the strict protobuf JSON `LabConfig` contract in
`api/lindm/lab/v1/hosts.proto`. Resolution is `$LINDM_LAB_CONFIG`, then
`~/.config/lindm/lab.json`, then a built-in local-only host. An explicitly selected
missing file, unknown field, duplicate host name, invalid resource ceiling or
unpinned container image fails closed. The built-in host uses the running
machine's architecture and existing guest sizes; native KVM remains mandatory
rather than silently falling back when `/dev/kvm` is inaccessible.
Default admission reserves one quarter of CPU and RAM, budgets each slot at
4 vCPU/4096 MiB, and takes the smaller CPU/memory capacity (at least one slot).
The measured 24-core/62 GiB workstation therefore defaults to four guests, not
one slot per two-vCPU QEMU. Ordinary clouds still use 2 vCPU/2048 MiB and encrypted
guests 2 vCPU/4096 MiB. The operator config installed for this lab sets local
capacity to two after observed swap pressure with five guests plus test suites;
each Spark retains its baseline's four slots.

Copy and adjust `lab/hosts.example.json` for local amd64 plus the two arm64 SSH
hosts. Each entry declares its transport/SSH alias, native architectures, KVM,
maximum simultaneous guests, per-guest vCPU/memory ceilings, owned work directory
and native or digest-pinned container runtime. `~/` resolves on the execution
host. Limits are admission ceilings, not implicit guest resizing. Change a host's
name, work directory or capacity only while its slot namespace is idle, and use
the same configuration across collaborating processes.

```sh
export LINDM_LAB_CONFIG="$PWD/lab/hosts.example.json"
artifacts/bin/lab hosts
artifacts/bin/lab hosts baseline -host dgx20 -record artifacts/dgx20-baseline.json
artifacts/bin/lab hosts baseline -host dgx21 -record artifacts/dgx21-baseline.json
```

The maintained baseline supports local and SSH Ubuntu 24.04, installs exact direct
package versions from `lab/baseline/ubuntu-24.04.packages`, records all before/after
package and group changes, and verifies package-owned firmware, native tool versions
and a fresh run-user `/dev/kvm` open. It emits a ready host entry as protobuf JSON.
It is an explicit authorized host mutation, unlike ordinary VM runs; it never
performs a broad upgrade or cleanup. Native tools are preferred on the Sparks:
this avoids nested Docker/libguestfs device plumbing and preserves normal firmware
package ownership checks. Package pins and baseline evidence make that choice
auditable; the baseline does not claim all transitive apt dependencies are a
hermetic snapshot.
APT operations select only the existing validated
`/etc/apt/sources.list.d/ubuntu.sources` official Noble sources and their Ubuntu
archive keyring; unrelated third-party sources/keys are neither updated nor fixed.
Signature and validity checks remain enforced. `NEEDRESTART_MODE=l` reports
restart needs without restarting unrelated shared-host services.
The example Spark work directory is `~/lindm-lab`, created mode 0700 by the
baseline. Every ancestor must be owned by root/the run user and not replaceable
by another unprivileged user (a sticky temporary parent is permitted). The Sparks'
existing `~/work` is group-writable and shared with other projects, so it is not a
safe parent for package-signing state. The baseline never chmods that shared
directory; configure the private alternative instead. Evidence records the work
directory and whether it was created.

`-arch arm64` (also `aarch64`; `amd64`/`x86_64` are equivalent) must match the
pinned image manifest. Selection prefers matching KVM hosts over TCG, then a free
configured host; `-host dgx20` overrides selection. `-accelerator kvm` explicitly
refuses foreign-architecture TCG. `lab hosts` shows reachability, configured native
architectures, observed KVM access, active leases, observed QEMU processes and free
managed capacity. Old QEMU processes started without this command are visible but
cannot be retroactively leased.

A host-local flock slot is held for the entire lane through VM/fixture teardown.
Remote workers take the same locks over SSH on the target, not on the controller.
Kernel locks release after process death, QEMU helpers have parent-death killing,
and SSH stdin closure cancels the worker before its cleanup/lease release. Full
hosts wait under the command deadline; agents do not coordinate by `pgrep`.

Admission also samples native `MemAvailable` and `pswpout`: available memory must
cover the configured per-guest RAM ceiling plus 8 GiB of headroom, with no
swap-out counter increase over the 100 ms admission sample. The ceiling is
conservative for lanes using less RAM. Each held slot records its admission
timestamp, PID, available/guest/headroom bytes, swap counters and sample duration.
Admissions are serialized and count still-held slots outside a reduced configured
limit, so lowering capacity does not silently ignore existing guests.

For example, from a pinned source checkout with built embedded web assets:

```sh
artifacts/bin/lab vm inspect -arch arm64 -accelerator kvm \
  -manifest lab/images/ubuntu-noble-arm64.json \
  -firmware-code /usr/share/AAVMF/AAVMF_CODE.secboot.fd \
  -firmware-vars /usr/share/AAVMF/AAVMF_VARS.fd \
  -firmware-package qemu-efi-aarch64 -firmware-version 2024.02-2ubuntu0.10 \
  -record artifacts/ubuntu-arm64-kvm.json
```

Replace `-arch arm64` with `-host dgx20` to target that host explicitly. Firmware
paths/version refer to the execution host and must match its baseline record.
Remote runs cross-build static Linux lab/server/agent binaries, rsync source and
required package inputs into one private run directory, reauthenticate staged
images before publishing them to the persistent digest cache, and reverify cached
entries on every use. Staged package names remain unchanged inside individually
numbered directories: native repository pool lookups bind the original basename,
not just signed payload bytes. Identical names from different inputs cannot collide.
The remote staging compiler selects its source from `-repo`; use an immutable
source checkout there with the isolated remote authority, not the mutable shared
fixture checkout. Local source-building lanes separately support `-build-repo`.
Never supply a mutable source tree for an evidence run.

Remote dispatch uses real local password/WebAuthn authority instead of an external
IdP. The server and dedicated pinned PostgreSQL container run beside the VM, with
dynamic loopback listeners and a fresh owned database; no local `:18444` binding or
shared development secrets are forwarded. This avoids WAN latency in the guest's
control-plane path and keeps fixture ownership/cleanup together. Remote lifecycle
requires `-control-plane-trust=true`; manual shared-console lifecycle variants stay
local. Successful and partial lane records are copied to the requested new local
`-record` file before exact run-directory cleanup. The record includes host/runtime,
elapsed time, source revision and binary-diff SHA-256. Persistent image/golden caches
and slot identities are retained. A lost transport or failed evidence copy reports
the exact retained run path instead of deleting evidence or guessing at live state.

Source-building VM commands `vm dispatch`, `vm device-actions` and `vm updates`
accept `-build-repo DIR` independently of `-repo DIR`. The latter remains the
initialized development-fixture/trust root; the former selects only package,
agent and (where built by the lane) server compilation inputs. Omitting
`-build-repo` preserves the existing `-repo` source default. For a stable native
run, build the prebuilt lab/server from a pinned read-only checkpoint and pass
that checkpoint to `-build-repo`, while retaining the shared fixture in `-repo`.
Never copy, symlink or rebind fixture secrets into a source worktree. Record the
checkpoint commit and any applied private-worktree diff SHA-256 with the resulting
executable/package digests.

`vm lifecycle` already consumes explicit `-first-build`, `-second-build`, `-lab`
and `-lindmd` artifacts; it performs no repository-source compilation, so has no
no-op source flag. Build its N→N+1 packages from the same pinned current tree.
Standalone `vm encrypted` installs/reuses the authenticated vendor ISO/golden and
observes native cold boots; it likewise compiles no repository source. Encrypted
device-action package compilation is covered by `vm device-actions -build-repo`.

Laboratory independent approvals share `OwnerSession.ApproveApproval`: each
decision obtains fresh local password/WebAuthn or directory code/PKCE authority.
Do not cache approval authority across idle expiry or account revoke/restore,
extend server session lifetimes, or retry an approval mutation automatically.
The deterministic regression uses a real prebuilt `lindmd`, real PostgreSQL in an
owned disposable database, and Keycloak for the directory case. The production
config rejects `search_path`, so this process fixture uses database isolation,
not `testdb`'s in-process schema override. `go run ./cmd/dev test-integration`
builds a release-stamped `lindmd` and sets `LINDM_NATIVE_SERVER_BINARY` and
`LINDM_NATIVE_REPOSITORY` for every native-server regression (approvals, reveal
authorization and release fixtures), so they run in the normal integration gate
and fail rather than skip when those inputs are missing.
It moves only owned session timestamps across the idle boundary, verifies the
old-session 401, rejects login while the approver is disabled, restores the
account through the real API, and verifies fresh two-human approvals.

The encrypted installer lane is `lab vm encrypted -manifest
lab/images/ubuntu-noble-encrypted-amd64.json` (or
`lab/images/fedora-44-encrypted-x86_64.json`). Supply `-firmware-code`,
`-firmware-vars`, `-firmware-package` and the exact installed
`-firmware-version`; `-secure-boot` requires an enrolled PK/KEK/db template and
actual guest SecureBoot=1/SetupMode=0. Ubuntu hosts can use the `ovmf` package's
`OVMF_CODE_4M.secboot.fd` and `OVMF_VARS_4M.ms.fd`; the off variant uses
`OVMF_CODE_4M.secboot.fd` and unenrolled `OVMF_VARS_4M.fd`, without
`-secure-boot`, to observe SecureBoot=0/SetupMode=1. The non-Secure-Boot
`OVMF_CODE_4M.fd` can omit the SecureBoot variable entirely; unavailable is not
proof of disabled enforcement. Package ownership/version and both firmware
digests are checked, not inferred from filenames. Updating host firmware produces
a different golden-cache key rather than silently changing an existing machine.

Original-device recovery lanes can explicitly supply the Go lab API's
`EncryptedFirmwareOptions.OwnedDBCertificate`: one public PEM certificate for
the run-owned signer, never a private key or certificate bundle. This requires
Secure Boot and the same package-pinned, already enrolled PK/KEK/db template.
`virt-fw-vars --add-db` modifies only a private run NVRAM derivative; the harness
verifies the exact certificate DER in firmware db (not MOK), retains the original
db bytes and rejects changes to PK, KEK, dbx or unrelated firmware variables.
Evidence records the certificate DER SHA-256 and source/final initial VARS
SHA-256 separately. The signer also binds the golden-cache key when this explicit
option is used; ordinary vendor fixtures and their cache keys are unchanged.
Enrollment evidence is not a Secure Boot pass: the running guest must still
report SecureBoot=1/SetupMode=0 and the qualified systemd-boot LoaderInfo before
the separately signed original-device recovery handoff can proceed. Guest disk
and bootloader provisioning remains inside the disposable guest; this firmware
hook neither accesses host EFI variables nor handles the signing private key.

This lane additionally needs `swtpm`, `xorriso`, `mcopy`, `virt-fw-vars`, and
`guestfish` with its direct QEMU appliance/cryptsetup support. Official ISO
manifests reuse the existing digest, exact-size and vendor OpenPGP verification.
Only installer configuration is remastered; vendor-signed shim, GRUB and kernel
remain intact. Ubuntu autoinstall and Fedora kickstart install LVM on LUKS2,
serial initramfs unlock and pinned lab SSH keys. `-desktop gnome` or `-desktop kde`
installs the real desktop through native installer/package tooling and configures
lab-only autologin; its display is a private Unix VNC socket, never a TCP listener.
Fedora desktop packages use the release repository with RPM signature checking.
Desktop/session assertions remain separate from the encryption smoke assertions.

The device-action lock lane additionally prepares a password-enabled
`lindm-desktop-test` account in each disposable overlay and restarts GDM with
test-only autologin. It retains the original logind session identities, then
requires a real `Class=user`, Wayland/X11 `gdm-autologin` session, a user-owned
`gnome-shell`, and agreement between logind `LockedHint` and GNOME ScreenSaver.
The optional logind desktop label may be `ubuntu` or empty; it is not GNOME
identity. The immutable golden is unchanged. Passwords and shadow rows never enter
qualification records.
Release removes only owned account restrictions; it must not remotely unlock the
desktop, which still requires local authentication.

`-tpm-boot` is a separate golden-cache dimension: it installs a systemd/dracut
early-boot path, TPM libraries/tools and `tpm2-device=auto` while preserving the
existing LUKS UUID/map name. It does **not** enroll a token. Ubuntu's default
initramfs-tools path remains a separate negative tuple; token enrollment alone
is not proof of unattended boot. The TPM action lane must enroll through the real
provider and then call `ColdBoot` with an empty secret, which fails immediately
if a passphrase prompt appears. `systemd` supplies Ubuntu 24.04's cryptsetup
tools; Fedora 44 supplies them in `systemd-udev`, not a nonexistent
`systemd-cryptsetup` package.

On hosts whose installed kernel is not caller-readable, supply both
`SUPERMIN_KERNEL` and `SUPERMIN_MODULES` explicitly for the libguestfs appliance.
Use a private, readable copy of a packaged kernel and its matching installed
module directory; never relax `/boot` permissions. The harness validates both
paths, records the selected kernel SHA-256/module-directory version, and forwards
these variables only to guestfish. It does not invoke sudo implicitly or claim
that the selected module-directory name is an observed booted-kernel version.

`-golden-cache` holds private, immutable installed disks, matching NVRAM/TPM state
and lab-only unlock/SSH credentials. Never enroll a golden or treat these
credentials as production secrets. Each run gets a qcow2 overlay and copied
NVRAM/TPM; the cache verifies every stored machine-state digest before reuse.
Snapshots require a stopped machine, include all state and flatten disk backing
chains. The guest-independent header oracle opens only regular qcow2 files
read-only inside libguestfs; it never attaches host NBD or calls cryptsetup on a
host block device. Successful empty-header observation is distinct from an
appliance failure and alone is not a sanitization claim.

`lab vm inspect-storage` is the read-only storage-identity capture lane for an
already qualified Ubuntu 24.04 or Fedora 44 encrypted golden. It refuses a missing
golden instead of starting an installer, installs the supplied version-stamped
agent as a real native package in a disposable clone, and runs root inventory.
Supply `-repo` and `-build-repo` pointing to the immutable capture source tree,
`-agent` for the binary built from that tree, `-package-version`, the encrypted
installer `-manifest`, `-cache`, `-golden-cache`, and the exact firmware flags above.
Use `-storage-bus virtio-scsi` for the qualified serial/WWN tuple; Fedora's current
desktop golden additionally requires `-desktop gnome -tpm-boot`.

`-fixture-output NEW_DIR` creates a new private fixture directory beneath an
existing mode-0700 parent; `-record NEW_JSON` retains the public run evidence.
The lane captures native `lsblk -J -O`, the block subset of udev's exported
database, and public projections of LUKS text/JSON metadata. Projections strip
token payloads and cryptographic parameters before retention; no keys, volume
keys, binary headers or golden credentials become testdata. Evidence binds source
commit/diff and untracked-source digests, image/golden/package/agent digests and
native tool versions. Stopped read-only host inspection independently checks LUKS
UUID and partition size; serial/WWN are compared to the host-owned emulated
controller configuration, not claimed to be stored in qcow2 bytes. Fixture files
are published only after complete owned-guest cleanup and unchanged-header checks.

Reusable `EncryptedVM` primitives provide chosen-key or unattended `ColdBoot`,
observed unlock outcome/boot ID, guest-native `Run`, graceful `PowerOff`, hard
`Kill`, complete `Snapshot`, root-only `Headers`, whole-machine `HeadersAll`, and
QMP `NetworkLink`. `HeadersAll` includes whole-disk LUKS containers and partitions,
identifies each observation as `root` or `extra-N`, and rejects duplicate LUKS UUIDs
across disks. Both header APIs require a stopped, detached target. `BootRecovery`
starts a separately verified disposable cloud root for an off-target journal,
then attaches the stopped target by a checked descriptor with explicit virtual
serial/WWN. Its lifecycle excludes concurrent normal target boots or snapshots.
This is laboratory recovery-operator plumbing, not production handoff authority
or a durable external journal after the recovery VM is removed.
`PowerOff` first requires acknowledgement of a short systemd shutdown timer,
matching the lifecycle reboot pattern, then requires successful owned-QEMU exit
before stopping swtpm. It does not reinterpret an SSH error as successful shutdown;
the timer prevents poweroff from racing the SSH command's exit-status reply.
Recovery package preparation can explicitly select `VMHardwareOptions.AllowNetwork`
for signed native package acquisition. The default remains restricted user-mode
networking; evidence distinguishes egress permission, and no variant installs a
host bridge or changes host firewall rules.

Configured cloud guests retain the verified base descriptor for
`stoppedDiskSamples`: a read-only explicit QEMU backing graph samples 4 KiB at the
first, middle and final regions without guest software or host block devices.
Evidence records logical size, offsets and SHA-256 hashes; three matching samples
do not establish whole-drive sanitization. `closeAfterExpectedExit` accepts only
an already reaped successful process and then removes private state. Callers must
prove the intended recovery outcome separately and sample before cleanup; normal
service-lane `close` still rejects unexpected process exits.

Device-action failures also retain the protected executor's public action status
and a bounded 200-entry executor/relay journal tail before owned guest cleanup.
Collection uses a fresh pinned SSH connection and the read-only `action-status`
RPC, never a raw protected journal copy, key file or LUKS header. Failed probes
are recorded explicitly in private mode-0600 JSON referenced by the failure.
Asynchronous signed-recovery staging failures log their nonsecret native or
authority error so a resulting `OUTCOME_UNKNOWN` does not erase the diagnosis.
Each status request owns a unique exclusive request filename, so a failed
transport cannot block the diagnostic query by leaving its request behind.
The action/encryption lane records host load average, available memory, swap
capacity/free space and cumulative swap-in/out page counters at preflight and
failure. Action diagnostics also sample them before guest cleanup. Compare the
counters across timestamps to distinguish active swapping from historical swap
occupancy; a contention-window timeout is not native product qualification.
Live-root actions also retain bounded root status and journal samples over a
separate pinned connection while waiting for the server attestation. The sampler
is canceled/joined before returning; its latency cannot block the server oracle.
Escrow material is removed from status, and the fixed poweroff-helper journal is
included. The helper needs `CAP_WAKE_ALARM`: systemd's `ProtectClock=yes` removes
that capability, so its unit instead denies `@clock` syscalls explicitly and
keeps clock-setting authority out of its capability set. The 120-second alarm,
independent PID 1 failsafe and no-device/no-swap restrictions remain unchanged.

Recovery artifacts use deterministic compressed initramfs bytes and only the
actual operation's native helper/ELF closure and signed storage/network/EFI/FAT
module closure, including FAT's dynamically selected NLS modules. Kernel
`CONFIG_RD_GZIP=y` is checked before building this gzip path. TPM modules are
selected for TPM custody, not merely because the machine has a TPM. The signed
UKI's measured byte size remains in every recovery record. Do not enlarge the
vendor ESP to hide an oversized image: the lab retains its original capacity.
The newc archive explicitly includes `"."` with UID0/GID0 and mode0755; all
configuration ancestors must be protected even when the kernel's initial rootfs
mode is replaceable. Do not bypass the no-follow root-ownership validator to boot
a malformed image.
ELF `PT_INTERP` dependencies must be executable ingredients as well as present
in the approved closure. Other shared libraries need not be executable. The
builder refuses a non-executable loader before signing; otherwise Linux reports
`permission denied` for a correctly permissioned native helper.
The recovery qualification lane resolves whole-disk device nodes again after the
owned ordinary reboot, requiring the frozen WWN/serial/size and unique match.
An NVMe node number is boot-local; it is never approval identity. Native scope
observation then verifies the controller/namespace identity independently.
For retained QEMU recovery diagnostics, the signed image selects the existing
architecture's UART. `lindm-recovery-build -serial-console` accepts only
`ttyS0,115200n8` or `ttyAMA0,115200`; omitting it preserves the default console.
It cannot inject arbitrary kernel arguments. Recovery init binds standard streams
to `/dev/console` after mounting devtmpfs; otherwise an archive without static
device nodes can lose the precise init failure before forced poweroff. This adds
no interactive shell or alternate boot path.

Signed recovery bootstraps time through the pinned recovery origin before
generating an action-scoped proof. `GetRecoveryTime` signs a fresh nonce/boot-bound
request digest and PostgreSQL clock value under the current recovery START
delegation; it is public time information, not enrollment or wipe authority.
The root/delegation transition chain and protected provisioning-time floor remain
mandatory. A provisional TLS connection may send only this time request; action
requests require certificate validity across the subsequently authenticated UTC
interval, including keepalive connections. Neither local RTC skew nor
unauthenticated NTP can supply a replacement.

Recovery retains only a process-local, suspend-aware monotonic clock interval.
The full time-bootstrap round trip is uncertainty, never an allowance added to a
credential/grant lifetime. Use its lower bound for issued-at and not-before, its
upper bound for expiry and signed checkpoint receipt time. A missing/invalid
statement, changed nonce/request/boot/key, delayed/expired bootstrap or monotonic
rollback refuses execution. Statement expiry limits initial admission; long
read-only result reconciliation uses monotonic elapsed time, while every new
effect still requires unexpired delegation, credential and fresh start grant.
Native qualification must retain the exact signed source/binary/image digests
and separate original-device SATA and NVMe records on each named distribution.

Before recovery approval, publish the signed UKI through
`lab release repository publish-artifact -repository DIR -keys OFFLINE_KEYS
-target recovery/<lowercase-sha256>.efi=/path/signed.efi`. This requires the
offline targets quorum, not merely online rollout signers. Configure the
server's `releaseRepository.verificationStateDirectory` as a protected private
directory outside the published repository for its TUF rollback checkpoint.
The deployment's verified execution bootstrap supplies the release-root anchor;
an absent catalog or readiness observation refuses approval rather than trusting
a client-supplied image size. The maintained action fixture creates its own
isolated signed repository and waits for fresh root-observed readiness before
asking for either human's approval.

Shared `VMHardwareOptions` selects x86_64/aarch64, KVM/TCG, UEFI or x86 legacy
BIOS, TPM2 or TPM absence, virtio-blk/scsi, NVMe or SATA/AHCI, up to four extra
1 GiB disks and a virtio GPU/private VNC display. Encrypted installer manifests
derive the guest architecture from the signed-media manifest, rejecting an
explicit hardware mismatch. The `*-encrypted-arm64.json` Ubuntu and
`*-encrypted-aarch64.json` Fedora routes use package-pinned AAVMF,
`qemu-system-aarch64 -machine virt`, the PL011 serial console, a virtio-SCSI
installer CD and the TPM2 MMIO device. Select `-accelerator tcg` on x86 hosts;
these runs remain limited to two guest CPUs and record real elapsed time.
Availability of this route is not a native qualification claim: passing tuples
and evidence are listed separately in verification. Extra disks are blank,
not implicitly encrypted.
The opt-in inventory fixture formats only the first extra disk's explicit lab
serial, refuses existing signatures/children, and requires existing cryptsetup,
filesystem and optionally LVM tools. It supports LUKS1, LUKS2 and LVM-on-LUKS2;
it never installs guest dependencies silently or modifies the guest root.

UEFI cloud guests permit firmware initialization resets while waiting for the
pinned SSH host key. Readiness also executes one successful quiet command within
the existing five-minute boot deadline: SSH authentication alone precedes native
PAM/session initialization and does not prove that a command channel is usable.
Only transport startup failures and explicit temporary channel rejection may poll
that side-effect-free readiness command; authentication, host-key, protocol and
command failures remain terminal. Scheduled lifecycle reboots issue one reboot
request, then poll only the boot ID over fresh pinned SSH transports until the
old boot has actually changed, within the existing six-minute deadline. An old
boot ID never counts as readiness; authentication or malformed IDs fail closed.
Do not require the old host TCP connection to close: native QEMU/slirp evidence
shows it can remain open without FIN after the guest has completed a new boot.
For callers that disallow reboots, readiness requires QMP acknowledgement of
shutdown-on-reboot before that command.
BIOS guests retain startup shutdown-on-reboot, and explicit reboot-enabled or
encrypted guests retain their existing policy. A firmware reset terminating QEMU
can also make swtpm exit normally; that is a startup failure, not TPM qualification.

`go run ./cmd/lab images redhat discover -version 9.8 -token-file FILE` reads the
official Red Hat x86_64 KVM catalog without creating a subscription or accepting
terms. The [vendor release table](https://access.redhat.com/articles/red-hat-enterprise-linux-release-dates)
lists `9.8` and `10.2` as the current minors, both generally available May 19, 2026.
Version selection is explicit, not a mutable "latest" pin. `images redhat fetch
-version MINOR -token-file FILE -manifest NEW_FILE [-cache DIR]` obtains the authorized download, verifies its
published SHA-256 and exact CDN Content-Length, and imports it into the same
digest-addressed cache used by VM lanes. The default cache is `.cache/lab/images`;
the manifest parent must already exist. The token file must be a current-user-owned
mode-0600 regular file, not a symlink. An eligible RHEL subscription (including an
activated Developer subscription) and **Download Software and Updates** permission
are required; an offline token alone does not grant download entitlement.

Authentication follows [Red Hat's refresh-grant documentation](https://access.redhat.com/articles/3626371)
and its [download API contract](https://api.access.redhat.com/management/v1/swagger.json).
Credentials remain in memory and are never printed or persisted. HTTPS requests
are bounded, API authentication never follows redirects, and the separate
allowlisted CDN request carries no bearer token. Only sanitized protobuf manifests
and receipts are persisted privately; temporary signed download URLs are excluded.
The RHEL-specific `VENDOR_AUTHENTICATED` mode records an authenticated HTTPS vendor
checksum, **not an OpenPGP signature**. Offline `images verify -manifest FILE
[-cache DIR]` checks receipt/manifest agreement, exact size and every image byte;
it cannot reauthenticate the historical HTTPS publication or detect a local owner
replacing both pins and evidence. Ubuntu/Fedora continue requiring their pinned
vendor signatures. Acquisition evidence is not guest lifecycle qualification.

`lab vm lifecycle` (including `-control-plane-trust`) and `lab vm dispatch`
accept `-redhat-token-file FILE` for RHEL. Also supply `-allow-network` explicitly:
registration and entitled metadata refresh require guest user-mode egress; the
default QEMU `restrict=on` intentionally cannot reach vendor endpoints. This changes
only the disposable guest's user-mode network and is recorded as `user-egress`.
The same protected offline-token file policy applies. The hosted RHSM API
additionally requires `rhc administrator`;
the lane reads the authorized organization and creates one random
`lindm-lab-<32 lowercase hex>` activation key, never a new organization.
Organization/key material uses the existing `RedHatRegistrationCredentials`
protobuf JSON contract over ephemeral pinned-SSH stdin only. Each registration
also generates an independent public `lindm-lab-<32 lowercase hex>` run name;
it is never derived from the activation key. The validated contract rejects using
the key itself as the public name. The guest invokes its installed
`subscription-manager register --name` entrypoint with in-memory parser arguments,
not operating-system arguments or environment, without changing the guest hostname.
Native output and RHSM logging are suppressed, including opt-in host failure
diagnostics. Successful registration emits only validated protobuf JSON containing
the public run name and canonical consumer UUID from `/etc/pki/consumer/cert.pem`'s
subject CN; other certificate subject fields are never emitted.

Registration refuses a preexisting consumer or ownership marker. The lane checks
native identity, requires enabled repositories, and performs a bounded
`dnf --refresh makecache` with unavailable repositories treated as errors.
This observes authorized metadata access without installing unnecessary packages.
Evidence contains the public run name, actual consumer UUID, private receipt path,
and registration, identity, metadata-refresh, unregister and key-deletion booleans.
Before registration, the host creates a private (0600, exclusive-create)
`<run-name>.redhat-registration.jsonl` alongside the disposable VM directory in
the selected work directory (the system temporary directory by default). The first
record contains only the public run name, enabling exact hosted-name recovery if
the registration reply is lost. As soon as registration returns, the host appends
the validated name/UUID and fsyncs it before identity, repository, or lifecycle
operations. The file and initial directory entry are durably synced; the receipt
survives VM-directory removal and remains after normal cleanup. Retain the work
directory for crash recovery; temporary-directory retention is host policy.
Neither receipt record contains organization, activation-key, token or certificate
material. An owned guest is unregistered before its key is
deleted, using separate cancellation-independent deadlines while QEMU is still
alive; a failed unregister does not skip key deletion and both errors propagate.
No token is needed for the existing offline local-RPM path, whose systemd
dependency is already installed; any RHEL repository package acquisition requires
registration. Fedora and RHEL retain the identical pinned-key RPM rejection,
install, upgrade and removal path with configured repositories excluded.
Lifecycle records SELinux Enforcing before and after; native running-service
assertions also require it. Dispatch retains its explicit Enforcing observation.

The client refreshes expiring access credentials from the protected token file
without retrying mutations. After an interrupted process, stop all lab lanes, then
run `lab images redhat inventory -token-file FILE` for read-only consumer UUID,
name, creation and last-checkin metadata. This allowlisted JSON excludes account,
activation-key and certificate data. A default hostname or timestamp match alone
does not establish ownership.

Explicitly run `lab images redhat cleanup -token-file FILE
-confirm-delete-lab-registrations` to delete systems whose public names match
exactly `lindm-lab-<32 lowercase hex>` and activation keys in that exact namespace.
System UUIDs must be canonical lowercase UUIDs; system names are re-read before
deletion. An independently established legacy orphan can additionally be selected
with `-legacy-consumer-uuid UUID`; this selects only that UUID, never all systems
with the same hostname. Unrelated systems and keys remain untouched.

The official authenticated [RHSM v1 Swagger schema](https://api.access.redhat.com/management/v1/swagger.json)
defines `GET /management/v1/systems` (limit 100, offset pagination),
`GET /management/v1/systems/{SystemUUID}` and `DELETE` of that exact resource
(204 success). Details supply `createdDate`; these UUIDs identify RHSM consumers,
not Insights inventory hosts. Key cleanup uses the separate
[RHSM v2 activation-key API](https://console.redhat.com/api/rhsm/v2/openapi.json).
Inventory is bounded to 1,000 systems and keys. Cleanup JSON records selected,
deleted and subsequently absent consumer UUIDs plus key counts, never key names
or organization identifiers. Each selected consumer requires a subsequent GET
404 and key cleanup requires a fresh empty owned-key list; an acknowledged DELETE
alone is not absence evidence. Partial failures retain evidence, attempt other
selected cleanup without mutation retries, and return an error. Cleanup neither
accepts subscription terms nor changes a disconnected guest's local credentials.
A failed lane or lease creation alone is not qualification evidence; native checks
and cleanup must complete.

`go run ./cmd/lab auth check` exercises the running server's normal SSO/CSRF path
against the fixed development fixture. The reusable development-session helper keeps
passwords/cookies in memory, restricts TLS destinations and credential form actions,
and revokes its console session. It is not an alternate production authentication API.

`devlab.OpenApprovalSession` gives native lanes a separate real approver. In
Keycloak mode it creates a randomly named test-owned administrator through the
lab-admin client, follows normal code/PKCE login, and deletes that user at cleanup;
it changes no shared group or realm policy. Local fixtures use their independently
enrolled WebAuthn approver. `ApprovalSession.Approve` creates the typed request as
the requester and approves it through the second human's Admin API. The shared
VM control plane retains device-revocation request and approval IDs for exact
retries, and revokes the owned device before closing either session. Dispatch
records the two-human revocation approval as nonsecret evidence.

`devlab.OpenLocalAuthorityFixture` uses the same disposable database/process lifecycle
with local-primary authentication and ephemeral loopback listeners; it never binds
the shared admin port or resets the development fixture. It invokes the real
`lindmd bootstrap-owner -config FILE -username owner` CLI, captures the one-time
enrollment output only in bounded memory, and enrolls the owner through the real
HTTPS password/WebAuthn endpoints. The owner creates a distinct second owner through
the account API, then that approver enrolls with an independent credential. Both
expose the normal `OwnerSession` AdminService client. `StepUp` revokes the old session
and performs fresh password plus verified WebAuthn login; account revocation uses
the normal account-update API, not database principal/session/credential inserts.
`RestoreAccount` can re-enable only the owned approver through that same API;
previous sessions and approvals stay revoked, requiring a fresh approver login.

The maintained `internal/devlab/webauthnlab` helper uses standard-library P-256
signatures and real WebAuthn responses shared with identity tests. It simulates
presence/user-verification flags, not hardware custody or human intent. Golangci
`depguard` enforces its lab/test-only import boundary. `ConfigureDeviceActions`
generates private temporary RSA escrow transport, independent wrapping and online
execution keys, admits no wildcard or service capabilities, and requires two-person
recovery reveal. Its returned seven-action delegation still needs real Admin API
admission. Secrets remain in memory or mode-0600 files beneath the owned private
temporary directory; closing removes that directory and the disposable database.
This headless fixture qualifies server authentication/authorization, not browser
WebAuthn UI behavior or physical authenticator assurance.

`devlab.OpenDeviceActionAuthorityFixture` additionally signs both allocated admin
and device listener ports into its private bootstrap before server startup.
`ReadAgentFixture` returns those verified public provisioning bytes; recovery guests
must use their exact signed origins, with normal TLS hostname verification, rather
than a shared-port tunnel or an unsigned endpoint override. Ordinary native and
interactive console fixtures retain their existing origin contracts.

`go run ./cmd/lab cli check -root . [-record NEW_FILE]` qualifies `lindmctl`
against the already-running development server and real Keycloak fixture. It uses
the maintained browserless Keycloak helper, explicitly submits the CLI approval
form with CSRF, and completes the client's loopback/S256-PKCE exchange. It checks
`whoami`, a bounded AdminService device read, logout and revoked-bearer denial.
Only nonsecret results are emitted; optional evidence is exclusively created with
mode `0600`. Temporary CLI configuration is private and removed, and both owned
sessions are revoked. Without `-lindmd FILE`, the lane fails when the required
fixture/server is absent. Supplying a prebuilt `-lindmd FILE` instead creates an
owned migrated database and console server on `127.0.0.1:18444`, failing if that
port is occupied; cleanup removes only those owned resources. Both modes require
the running development PostgreSQL/Keycloak dependencies and never replace, reset
or stop the shared laboratory. Local-mode CLI qualification remains the existing
software-WebAuthn identity integration plus a manual browser login/approval flow;
this Keycloak lane is not evidence that the local browser flow has been exercised.

Local identity tests use a real PostgreSQL schema and a software P-256 WebAuthn
authenticator, not a verifier mock. The `TestLocal*` and `TestBreakGlass*` integration
tests exercise password lockout, one-use enrollment and challenges, replay/expiry,
immediate disable, worker fences and emergency audit. Run these with the same
`LINDM_TEST_DATABASE_URL` used by the integration lane. Browser qualification must
add a Chromium CDP virtual authenticator with user verification enabled and complete
`/enroll`, sign-in, account reset and the persistent emergency banner.

The generated protobuf-JSON HTTP contract is `GET /auth/options`, plus
`POST /auth/local/login/begin`, `/auth/local/login/finish`,
`/auth/local/enroll/begin` and `/auth/local/enroll/finish`. Unrestricted
`accounts.manage` operations are `GET /auth/accounts` and `POST /auth/accounts/create`,
`/auth/accounts/update`, `/auth/accounts/reset`. Unsafe requests require the exact
configured origin; account mutations additionally require the session CSRF token.
Responses are no-store. Enrollment finishes without creating a session.

Identity schema `00001_identity.sql` owns `local_accounts` (the same immutable UUID
as its principal), `local_credentials`, hash-only `local_enrollments` and
`local_ceremonies`. Ceremony library state has its challenge removed and a separate
SHA-256 digest; one-use challenge consumption commits even when verification fails.
Enrollment ceremonies retain only the enrollment-secret digest. Beginning or
cancelling registration does not consume that secret or set the account password:
a new begin replaces the unfinished ceremony. Successful WebAuthn registration
atomically consumes the still-unexpired secret and stores the password and
credential. A failed registration can retry with the same secret until expiry.
Enrollment secrets expire after one hour; ceremonies after five minutes. Five
failed attempts lock an account for fifteen minutes. Password PHC strings encode
Argon2id v19, 64 MiB, three iterations and one lane with a random 16-byte salt.
Emergency session lifetime is additionally bounded by configuration and worker
approvals require an active emergency session. Restarting identity ends existing
emergency sessions and invalidates their pending authority before new policy applies.

`go run ./cmd/lab auth check-fresh -repo .` exercises the worker-authorization API
with real Keycloak lifecycle changes and PostgreSQL transaction fences. It creates
unique test-owned user/group objects and a private migrated PostgreSQL schema;
only the immutable actor binding is seeded, never authoritative group observations.
The identity service uses read-only directory credentials; the fixture adapter alone
uses the protected lab-admin client to mutate and delete its temporary objects.
The check covers unchanged/display-only refresh, immediate group removal and
disable denials, regrant/re-enable versions, stale approvals, committed writes and
rollback. It reports nonsecret owned identifiers and bounded cleanup results.
An unavailable or invalid supplied fixture fails; it never falls back to cached
authority or changes shared users, groups, realm settings or application tables.

The primary-source oneof also includes Okta and Google Workspace. Their OAuth
service credentials are separate from browser login; protected PEM resources are
loaded through the existing owned-file boundary. `DirectorySource` uses opaque
immutable strings, not a universal UUID assumption. Only UUID-native adapters
parse UUIDs. Provider TLS tests use documented response shapes and real JWT
signatures; they are not live-tenant qualification. The README gives exact
least-privilege setup and lifecycle/outage procedures for each provider.

Supplemental `/scim/v2` uses connector-specific rotating hash-only credentials,
configured immutable correlations and bounded RFC 7643/7644 representations.
`POST /auth/scim/credentials/rotate` requires unrestricted account management,
normal session CSRF and exact origin. `GET /auth/settings` is a read-only
protobuf-JSON account-management endpoint exposing configured sources and only
the requesting principal's freshness. SCIM integration tests require real
Postgres isolated schemas and cover conditional mutation, tombstones and races.

The broker fixture has dedicated `lindm-upstream` and `lindm-broker` realms.
The upstream lab-admin has only user management/view access. The **broker realm
only** additionally grants its lab-admin `manage-clients`, so each broker check
can create/delete a uniquely named OIDC client with an exact ephemeral-loopback
redirect. No wildcard redirect, master administrator or access to the shared
`lindm` realm is introduced. Production directory clients remain read-only.
Permanent fixture imports require a parent-coordinated dev reset; a lab check
must never reset the shared fixture. Test-owned user/group/client prefixes define
the leftover-cleanup boundary. SAML signed persistent NameID feeds signed broker
session claims; user-editable imported attributes cannot establish lineage.

Entra uses the same `DirectorySource`, durable observation/version transitions and
worker transaction fences as Keycloak. Its public-cloud OIDC client requests
`openid profile` and binds issuer + signed tenant-local object ID, not pairwise
subject or email. The app-only Graph source uses a separate credential and reads
`accountEnabled` plus bounded transitive group-ID pages. Graph's advanced-query
index is eventually consistent: qualification must measure upstream visibility
delay separately; no retry or outage extends the 30/60-second refresh/denial rules.
`TestEntra*` uses local `httptest` TLS servers with signed OIDC tokens and documented
Graph shapes. These are deterministic unit/race checks, **not live Entra
qualification**. A live tenant, two registered apps with admin-consented Graph
application access, and test-owned users/groups remain prerequisites for launch.
The [Entra setup and manual qualification procedure](../README.md#microsoft-entra-id)
lists exact calls, least privileges, disable/removal/deletion/outage scenarios and
required timing evidence. The greenfield identity migration admits an `entra`
deactivation source; no compatibility migration or cached-authority fallback exists.

`go run ./cmd/dev test-integration -root .` runs that same live check before the
real-PostgreSQL integration tests. It requires already-running development
dependencies and does not start or migrate the public application schema.
Unlike `make test-integration`, it does not invoke `dev-up`; use the direct command
when an independent native lane must retain its running control-plane environment.
`internal/testdb.New` owns reusable isolated-schema creation/cleanup; integration
tests retain the `testdb.Open(t)` wrapper. This is schema isolation, not a separate
PostgreSQL database. The fresh-authorization proof does not qualify job dispatch,
device execution or finer commercial authorization scopes.

The control-plane trust VM lane uses a separate disposable PostgreSQL **database**,
not `testdb`'s schema. It invokes the real `lindmd` executable, whose protected
configuration intentionally rejects arbitrary `search_path` parameters. Lab-only
cluster administration creates the uniquely named database; the subprocess receives
only a non-superuser migrator URL. Owned server shutdown precedes database cleanup.
Neither this fixture nor the fresh-authorization fixture changes shared IdP policy.
Isolated authority fixtures generate their own current-schema typed configuration
from verified public provisioning trust and manifest-checked development
certificates/URLs; they never decode the shared `server.json` as a template.
`ReadPublicAgentFixture` verifies public root/bootstrap bindings without reading
offline signing keys. The normal shared-server fixture reader still requires the
shared configuration to match. This permits isolated labs during a greenfield
schema cutover without resetting another lane's running development environment.

`go run ./cmd/lab load -repo . -lindmd artifacts/bin/lindmd -record NEW_FILE`
uses that same disposable database/real-process boundary without binding the
shared admin port. `internal/loadlab` simulates real enrollment, device mTLS,
session proofs, jittered sync/work polling, 2,000-package snapshots and signed
service challenges/results; it cannot target an arbitrary production server.
Build the isolated server with an explicit development release identity, for
example `go build -ldflags '-X lindm/internal/agent/buildinfo.Version=0.1.0' -o artifacts/bin/lindmd ./cmd/lindmd`.
The fixture registers that actual release through the admin API; simulated
sessions obtain its version/protocol through authenticated compatibility reads,
rather than bypassing the production compatibility gate.
The default 500→2,000→5,000→10,000 ramp uses 11-minute plateaus and stops on an
SLO breach. `-seed`, `-stages`, `-stage-duration`, `-packages`,
`-assignment-percent`, `-enrollment-workers`, `-pool-size` and `-profile-dir` describe bounded repeatable
experiments. Records are exclusive, private, nonsecret files, including failures.
`-database-storage shared` retains the development-cluster boundary.
`-database-storage tmpfs` and `nvme` instead start an exact-owned pinned PostgreSQL
18.6 container with the maintained TLS, roles and `pg_stat_statements` configuration.
The former is labelled **storage: tmpfs (no durable fsync cost)** and cannot
qualify durable capacity. The latter uses an owned sparse file backed by verified
NVMe, a loop device and XFS; it never formats a host block device. It requires
local Docker, `mkfs.xfs`, `findmnt`, `lsblk`, `losetup`, `mount`, `umount` and
noninteractive sudo for the exact-owned loop/mount lifecycle.
Use disjoint `-generator-cpus 0-3 -server-cpus 4-11 -postgres-cpus 12-19`
after checking the host topology. Generator re-exec and server `taskset` apply
before Go starts; Docker applies the PostgreSQL CPU set. Records retain effective
thread affinity, bounded `iostat -dx 1 2` observations and QEMU process counts.
CPU sets are not exclusive reservations against other host jobs.
Dedicated container regression: set `LINDM_CONSOLE_REPOSITORY`,
`LINDM_CONSOLE_LINDMD` and `LINDM_LOAD_POSTGRES_INTEGRATION=tmpfs` (then `nvme`)
and run `go test -race -tags=integration,consolelab ./internal/devlab -run '^TestDedicatedLoadPostgresTLSRolesExtensionAndCleanup$' -count=1 -timeout=10m`.
See [capacity interpretation](security-and-operations.md#connected-capacity-laboratory)
for cadence, measured quantities, saturation-proxy limitations and exclusions.
Run focused checks with `go test -race ./internal/loadlab ./internal/devlab`
and the pinned golangci-lint against those packages plus `./cmd/lab`.

`go run ./cmd/lab profiles check-catalog -lindmd <prebuilt-server> -repo .`
uses the same private real-process/database boundary for profile publication.
Optional `-record <new-file>` persists successful evidence without overwriting an
earlier run. It first restarts the real server with two fresh, protected, undelegated
online keys to exercise configuration-resource loading. It follows the real owner
authorization-code/PKCE login, publishes
two typed immutable revisions, rejects stale-head and changed-request mutations,
restarts the server, then verifies exact historical retry, retained dependencies
and the current catalog listing. Session revocation precedes server/database
teardown. Publishing a catalog revision does not assign or deploy it to devices;
this command does not qualify target preview, dispatch or native reconciliation.

`artifacts/bin/lab vm dispatch -manifest lab/images/ubuntu-noble-amd64.json
-lindmd artifacts/bin/lindmd [-record NEW_FILE]` qualifies connected service
dispatch through real signed native packages, the private server/database fixture,
authenticated profile publication/assignment and the installed automatic relay.
Use `lab/images/fedora-44-x86_64.json` for the SELinux Enforcing RPM guest. It checks
active/enabled then inactive/disabled revisions, strictly increasing sequences,
device-signed ingested history, server restart retaining an open action ID,
no-drift completion without a start grant, successful assignments at guest clock
offsets of +90 and −90 seconds (with time sync disabled and restored afterward),
and revocation without native effect. Assignments use the normal API's minimum
300-second reconcile interval. After initial convergence, the unchanged assignment
must complete a fresh periodic read-only check without a start grant (`COMPLIANT`).
The lab then disables/stops the unit out of band and requires the next periodic
action to detect that drift, obtain a start grant and restore active/enabled state
(`DRIFT_REMEDIATED`). Both checks record fresh sequences, verification timestamps
and independent native/start-witness observations; no production timer bypass exists.
Each periodic wait allows eight minutes; the command budget is 50 minutes plus
any hold, with external timeouts requiring additional cleanup allowance.
An inert pre-enrollment fixture and independent systemctl/start-witness observations
remain separate from server evidence. `-record` includes assignment intervals,
compliance snapshots, build digests, timing and explicit failure state and never
overwrites an earlier run. Owned guests, private server processes, signing material
and databases are cleaned up.
Optional `-hold 45m` reserves the normal development console port and pauses before
revocation, keeping the guest, database and real server available for authenticated
browser assignments. The ordinary dev server must not occupy port 18444. The
printed origin uses the same dev CA and Keycloak owner login; timeout or SIGINT
resumes native re-observation, revocation and cleanup. Holds are bounded to one hour.
Unstarted supersession is covered by the real-Postgres integration test, **not
natively exercised**: acquisition requires the executor-held mTLS signer, so
stopping that executor cannot deterministically hold an unstarted acquired action.
No product fault seam is added. See [the command details](agent-enrollment.md#running-the-connected-service-dispatch-lane).

The catalog uses `ResourceProfile` and `ProfileResource` with closed
`ResourceDesiredState` arms. Canonical identity is the pair of resource kind and
canonical key, not a service unit or an administrator-supplied opaque key.
Publication persists immutable typed protobuf resource records together with
relational identities and dependency references/conditions. Reads validate both
representations and the deterministic revision digest. Expected-head CAS,
actor-bound request receipts, original-revision retries and append-only history
remain independent of device activation.

Resolution retains priority and contributor provenance across heterogeneous
resources. Equal-priority optional dimensions merge only when compatible;
explicit false/zero and managed empty sets remain specified values.
Known set-valued fields, including membership and verification-check sets, are
canonicalized on owned copies before immutable hashing and equal-priority merging.
Their permutation does not change a revision digest or manufacture a conflict.
Ordered native lists such as SSH matches, firewall rules, DNS servers/search
domains and routes retain their supplied order.
Ownership, applicability and verification policies must agree rather than silently expanding
authority. Cross-resource native claims can conflict even across different kinds
or priorities; no desired state is returned for a conflict. Dependency conditions
are retained, cycles conflict, and their dependents are blocked. Repeated target
matches may select different priorities or revisions of one profile; identical
revision/priority matches are deduplicated. A typed schema arm or ready catalog
preview is not evidence that a native provider is implemented or qualified.

The authenticated **Profiles** console uses the generic catalog RPCs. Each resource
is edited as strict generated `ProfileResource` protobuf JSON, with an expandable
generated field reference covering every declared desired-state arm. Unknown fields
are rejected and generated protobuf constraints, including shared custom rules,
validate publication rather than a second handwritten schema. Desired references,
ownership, verification, applicability and dependency conditions remain typed.
The resolver additionally rejects noncanonical identities and dependency cycles and
preserves blocked/conflicting results. Catalog publication does not certify native
backend support.
The editor captures one request ID and payload before sending, retains an ambiguous
attempt across route navigation, and only changes its expected head/request identity
on an explicit rebase or replacement. Revision refresh failures do not discard an
unsent draft. These drafts and attempts are tab-memory state, not durable browser
storage: full reload and sign-out clear them. Exact server-side retry receipts and
retained revisions remain durable.

The existing **Groups** page retains static authorization membership under
unrestricted `accounts.manage`; its dynamic targeting section uses unrestricted
`inventory.manage` and never creates RBAC membership from inventory predicates.
**Rollouts** exposes real target-assignment and rollout administration, bounded
100-record keyset pages, and typed ring/health policy documents. Global edits require
unrestricted `resources.assign`; device preview and activation honor device scopes.
Preview displays the immutable device-generation snapshot, input/resolution/preview
digests, captured assignment revisions, resource conflicts, contributor revisions
and explicitly unsupported dispatch capabilities. Dispatch support is not a native
qualification claim. Activation pins the displayed device ID, preview ID and digest
and never rebases automatically; the server rechecks freshness and authority.
When policy requires an independent human, the console submits that exact activation
to the existing approval inbox; execution attaches its approval ID without changing
the captured target. Mutations have no automatic retry, and ambiguous requests
retain their exact identity in scoped tab memory.
Device **Resources / Compliance** shows generic desired references, typed
dependencies and retained ownership-safe release rows. Signed service-action history
remains service-specific evidence during Phase 1, not fabricated evidence for other
resource kinds.

Optional `execution_signing.plan_key_file` and `start_key_file` are distinct protected
file references to single unencrypted PKCS#8 Ed25519 private keys. Loading excludes
pinned transport/root/release keys and TLS/device-CA identity keys. It does not
delegate authority or enable an issuer; current authority and admission must still
authorize every later issuance. Absent configuration provides no signing fallback.

### Isolated native install and custody check

`go run ./cmd/lab native check-install-projection [-work-dir DIR] [-record FILE]`
requires Linux, native `systemctl` and GNU `stat`. It creates and removes its own
private fixture; it never enables, disables or starts host units. `-work-dir`
selects an existing parent on a trusted filesystem. The fixture must have
root/caller-owned ancestry without group/other write access; trusted sticky shared
temporary directories are accepted. Replaceable ancestry and symlink components
are rejected before fixture creation. Do not change checkout permissions to make
this check pass; use a protected parent such as `$HOME/.cache` or the default.
The optional record is created privately and exclusively, after successful cleanup.

The scenario starts with a declared alias, an undeclared alias and an already-enabled
`Also` instance. It observes exact native enablement links, including an install
drop-in, then records native disable's treatment of the baseline alias and empty
parent directory. A subsequent enable must recover the declared alias and `Also`
link without adopting the undeclared alias. This distinguishes the declared
footprint from both the direct-enable delta and the complete pre-existing link set
for this fixture. A private non-unit-named hardlink retains the symlink inode across
native disable and observation by a fresh process.
Actual `renameat2(RENAME_NOREPLACE)` interleavings exercise owned capture,
replacement restoration and preservation of both entries when a newer public entry
blocks restoration, including a captured unrelated regular file.

The root-boundary cases use two deliberately different definitions, both owned by
the fixture. An absolute directory symlink lets native `--root` read the definition
outside that root. Rewriting only that directory link to a private relative path
selects the copied definition while preserving the native install-link paths.
A separate absolute final-file symlink remains unchanged: native root-aware lookup
selects the copied definition and retains linked-unit install semantics. The record
contains the exact link sets for all three cases. This is a controlled demonstration,
not a general directory-rewriting algorithm or permission to trust arbitrary links.

For the linked-unit case, the fixture accepts exactly two complete native link
shapes: the alias points directly to the linked definition, or it points through
the canonical configuration link to that same definition. The staged-only
wanted-by target remains mandatory, and the record preserves the actual shape.
Systemd 239/255 produced the direct form; Fedora's 259.5 produced the configuration
indirection. This does not normalize general alias identity or runtime behavior.

These are native filesystem observations, not a production ownership API. They do
not qualify production resource-ancestry checks, power-loss recovery, SELinux,
safe runtime-invocation restoration or supported-distro certification. The fixture
uses fixed arguments/environment and `SYSTEMCTL_SKIP_SYSV=1`; `--root` is not
treated as a general sandbox for arbitrary input, and `--dry-run` is not relied on.

The same maintained scenario also passed with systemd `239-78.el8` as UID 0 on
tmpfs in a network-disabled, read-only, capability-free Rocky 8 container, using
image digest
`sha256:9794037624aaa6212aeada1d28861ef5e0a935adaf93e4ef79837119f2a2d04c`.
This checks the isolated native install/custody mechanics, not the Rocky guest
lifecycle or production SELinux policy.

### Captured-input native root check

`lab native check-install-snapshot -work-dir DIR [-record FILE]` exercises the
bounded source snapshot with actual native commands inside the copied filesystem
as the process root. Build the lab with `CGO_ENABLED=0` and install it under
root-owned, non-writable ancestry before invoking this check. It requires UID0,
chroot/mknod bootstrap capabilities and an existing root-owned mode-0700 work
directory on an executable, device-capable filesystem. A normal checkout,
`sudo go run`, a shared temporary parent or a noexec/nodev work mount is not a
substitute for these prerequisites.

The command creates only its private fixture. It captures a protected unit tree,
an unchanged literal absolute directory symlink, OS context and the native ELF
runtime; the private configuration starts deliberately empty. A fresh fingerprint
must match the capture. Changing the original definition must then change the
fingerprint, while actual `systemctl --root=/ enable` in the copied root must still
use the original captured WantedBy. The record retains the exact wanted-link
target and confirms that this uniquely named link is absent outside the copy.
The private fixture is removed before successful evidence is returned.

The snapshot enforces root ownership, non-writable ancestry, bounded traversal,
actual EOF and rejection of observed metadata/content changes. Unit/context limits
are 1MiB per file and 32MiB per unique inode set; runtime limits are 64MiB and
256MiB. The graph admits at most 32,768 nodes, 32,768 outstanding entries and
32MiB of metadata accounting, including paths, targets, labels, pending directory
names, queued targets and symlink-resolution states. Fixed per-entry charges cover
container overhead; this is not an exact Go resident-memory ceiling.
Directory-link targets are processed iteratively after the current descriptor
stack closes. Canonical depth is limited to 64 for files and links as well as
directories. A repeated symlink is a cycle only with the same remaining suffix.
Trailing slash and final-dot requirements survive symlink expansion; a regular
file followed by either records ENOTDIR rather than an invented successful lookup.
Being observed as runtime never waives unit/context limits or the legacy include
guard. Revisited nodes require matching metadata and SELinux labels. Directory
and symlink topology, negatives, observed hardlinks and labels contribute to the
deterministic source fingerprint. Destination identity does not. Protected
destination ancestry remains a caller precondition; a partially written
destination must be discarded after failure.

Native stdout state is separate from bounded diagnostic stderr. The command
preserves, rather than suppresses, modern systemd's missing-proc/sys warning.
NNP and capability dropping apply on an OS-locked native-exec thread; the evidence
does not claim every Go runtime thread has lost privileges. Parent-death signals
bound the fixed child chain without signalling a reusable numeric process group.
The bootstrap chroot/mknod grants are lab requirements, not new executor grants.

This qualifies copied-byte/topology mechanics for the exercised fixture. It does
not provide host execution authority, an atomic source snapshot, a packaged
production worker, general native-tool compatibility without proc/sys, crash
recovery, ownership-safe release or distro certification. In particular, a
production worker's execution placement on a noexec state volume still needs
separate design and qualification.

### Server deployment laboratory

Build embedded console assets with `npm run build:web`, then run:

```sh
go run ./cmd/lab vm server -manifest lab/images/ubuntu-noble-amd64.json -repo . -record /private/new-server-vm.json
go run ./cmd/lab server compose -repo . -record /private/new-server-compose.json
```

Both `lab packages build` (agent) and `lab packages build-server` accept `-arch
amd64` or `-arch arm64`; omitted means the build host. `-repo` source compilation
sets Linux, the explicit Go target and `CGO_ENABLED=0`, with private intermediate
and output paths rather than shared binaries. Go callers set
`packaging.BuildRequest.TargetArchitecture`, including through `SourceRequest`.
DEB metadata uses `amd64`/`arm64`; RPM uses `x86_64`/`aarch64`. A mismatching ELF
machine, Go module identity or embedded target settings fails closed. Native-host
builds execute `version`; foreign-host builds read the actual version string through
its ELF symbol/load segment and record `version_validation=embedded-build-metadata`,
not native execution. Foreign prebuilt executables must retain ELF symbols. Go's
`-trimpath` intentionally omits linker arguments from build settings, so their text
is not treated as proof of the stamped value. No QEMU-user dependency or guest
behavior is inferred.
Two clean source compilations and real DEB/signed RPM archives per target and
product are exercised by `TestCrossArchitectureSourcePackages`; its small Go module
fixtures test packaging boundaries, not the production agent/server protocols.

The VM lane needs the existing KVM/QEMU/cloud-init and native signed-package tools,
plus guest distribution repository access for PostgreSQL. It uses no shared dev
database, IdP or host port 18444. It snapshots bounded Go/SQL/native/embedded-console
inputs once, records their digest, then builds two `lindmd` DEBs plus a clean
repeated build from those same bytes. It authenticates the repository with a fresh
isolated signing key and installs
PostgreSQL with verify-full TLS and separate runtime/migration roles, invokes the
explicit migration unit and claims a LOCAL owner exactly once. It proves HTTPS
health/readiness, embedded console, LOCAL auth options, protected RPC 401, service
hardening, restart and signed package upgrade. Backup uses real `pg_dump`, a
config/key ownership/hash inventory, database destruction and `pg_restore`; owner
and a clearly identified pending backup-fixture device row must remain identical.
Purge must retain keys/config/database. The fixture device is not enrollment proof;
the lane does not claim a WebAuthn ceremony or stale-restore dispatch reconciliation.

The independent Compose lane requires local Docker/Compose v2 and access to pinned
image registries (or cached images). It creates a unique project and random
loopback ports, builds the static embedded-console image, runs migration explicitly,
checks LOCAL bootstrap/public/protected surfaces, live DB TLS/role separation and
actual container confinement, then removes only its owned project/volumes/image.
Both lanes emit nonsecret records exclusively to a new `-record` path; private
fixtures and one-time enrollment output are never evidence. These commands are
native/container qualification, not substitutes for physical or full release gates.
Production steps and secret inventories are in the
[operations runbooks](security-and-operations.md#native-single-host-installation).

### Advisory feed operations

Configure `advisories.feeds` in the server protobuf JSON. Each `FeedSource` names
`id`, `distro`, `release`, HTTPS `url`, `format` and `maxAgeSeconds` (one minute–seven
days). RPM metadata/CSAF and Arch require explicit architecture. Vendor OSV uses
`FEED_FORMAT_OSV_ZIP` or `FEED_FORMAT_OSV_JSON`; Fedora uses
`FEED_FORMAT_RPM_REPOMD`. Other authoritative formats are:

- `FEED_FORMAT_REDHAT_CSAF`: one signed Red Hat advisory/VEX JSON document.
- `FEED_FORMAT_REDHAT_CSAF_ARCHIVES`: root
  `https://security.access.redhat.com/data/csaf/v2/`, acquiring both signed weekly
  distributions through their `archive_latest.txt` pointers. Use the seven-day
  freshness ceiling for weekly publication; missing a new weekly archive expires
  the old evidence rather than silently extending it.
- `FEED_FORMAT_SUSE_CSAF`: a signed vendor JSON notice, exact SLES major/service-pack
  or Leap major/minor. Tumbleweed uses `rolling`, but GA-media aggregate notices
  are rejected as fix boundaries.
- `FEED_FORMAT_ARCH_JSON`: `arch`, `rolling`, `x86_64`, official
  `https://security.archlinux.org/all.json`; the official `advisories.json` companion
  supplies dates only for exact AVG/package matches. AUR/derivatives are not covered.
- `FEED_FORMAT_DEBIAN_TRACKER_JSON`: Debian numeric release and
  `https://security-tracker.debian.org/tracker/data/json`. A release absent from the
  export is rejected, not interpreted as clean.

RHEL requires `platformStream` of `standard`, `eus` or `e4s`. Mainstream may select
major `9`; EUS/E4S require an exact minor, corroborated by native inventory. Format
and distro are protobuf-validated, and overlapping RHEL major/minor source scopes
are rejected. These new sources deliberately remain partial when the vendor
format/mapping cannot establish a complete applicable binary universe.

`lindmd advisories-refresh -config FILE` explicitly fetches and atomically publishes
configured feeds. `advisories.refreshEnabled` defaults to false: air-gapped
deployments perform no scheduled feed egress. When enabled, refresh defaults to
six hours (configurable one hour–seven days). Package/host evidence defaults to
24-hour validity, configurable five minutes–seven days. Inventory matching and
expiry handling do not need network access.

`lindmd advisories-import -config FILE -feed ID -file FILE` admits cached vendor
bytes only when that feed has an out-of-band `expectedSha256` pin (protobuf JSON
base64). The raw compressed/ZIP bytes are hashed before decompression. For repository
metadata, configure `FEED_FORMAT_RPM_UPDATEINFO` and pin the referenced updateinfo
bytes; bare repomd without its companion is not importable. A byte pin does not
prove acquisition time: file imports contribute findings but cannot establish
current complete coverage, even for a complete archive. This prevents an old file
from becoming an apparently fresh clean result merely by reimporting it. Signed
offline-bundle custody and replay protection remain a separate protocol.

Online Red Hat/SUSE proofs use pinned vendor OpenPGP keys retained under
`internal/advisory/feed/keys`; its provenance records the trust-bootstrap limits.
The console exposes artifact digests, signer fingerprints and signed snapshot time
separately from last successful fetch. Composite feed status SHA-256 hashes the
deterministically encoded protobuf `FeedManifest`; `expectedSha256` pins that
manifest for Red Hat archives, and raw primary bytes for other formats. Offline
individual CSAF imports still require externally authenticated operator pins and
do not claim signature provenance; paired Red Hat archive import requires the
separate replay-fenced bundle protocol.

Ordinary input is capped at 128 MiB compressed, 512 MiB expanded and 500,000
normalized records. Signed individual CSAF is capped at 32 MiB with 64 KiB proofs.
Red Hat acquisition stages at most one 512 MiB compressed archive in a private
temporary file, removes it on every exit, bounds each archive to 16 GiB expanded
and 250,000 entries, and bounds the combined normalized data to 128 MiB/500,000
records. Eight logical requests (forty including redirects) and parsing share one
five-minute deadline. Database insertion uses bounded COPY batches. A scheduled
matcher scans at most 100 devices per minute; reads evaluate the current snapshot
immediately. Expiry is rechecked at read time independently of scan progress.
Findings pages are row- and byte-bounded. Failed refreshes preserve historical
evidence and expose an error without resetting freshness.

### Signed release repository core (P20/L17)

`internal/releaseupdate` uses maintained go-tuf v2 metadata and updater verification.
`lab release repository` composes its focused `RunCLI` entry point and accepts
`development-keys`, `init`, `publish`, `promote`, `rollout`, `rotate`, and `mirror`.
Every operation uses explicit paths. `development-keys -keys DIR` is conspicuously
development-only; production private custody is provisioned independently.

Repositories contain `metadata/` and hash-prefixed `targets/` with consistent
snapshots. Five distinct root/targets/rollout/snapshot/timestamp signing identities
are required. Library callers can supply quorum signers; file custody is explicit
owner-private PKCS#8. Keep `root.pem` and `targets.pem` offline. Online custody
contains only `rollout.pem`, `snapshot.pem` and `timestamp.pem`; the loader rejects
exposed offline files, including symlinks. The terminating rollout delegation can
sign only `channels/*.json`; packages and native signatures remain top-level targets.
Their complete protobuf artifact identity and compatibility contract is bound in
offline-signed target metadata. Root rotation requires predecessor and successor
root quorums plus offline targets authority. Never put private custody inside the
published tree.

`publish -repository DIR -keys DIR -channel FILE -target LOGICAL=SOURCE` consumes
strict protobuf JSON `lindm.update.v1.AgentUpdateChannel`; repeat `-target` for
packages and release attestations. Agent choices are restricted to logical paths
under `packages/lindm-agent/` and carry numeric release identity, exact native
package version, architecture, package format, and explicit agent/protocol windows.
Other products can be ordinary signed targets but cannot become self-update choices.
`promote -repository DIR -keys ONLINE_DIR -channel FILE` can select only exact
offline-authorized artifact contracts. It cannot introduce package bytes or alter
their native version, architecture or compatibility windows. Pause/percentage
updates leave top-level targets bytes and version unchanged. Offline targets expiry
cannot be extended by online custody: schedule offline renewal before seven days.
Arch choices must also bind `signatureTargetPath` to the package logical path plus
`.sig`. Publish that detached native signature as a distinct TUF target, capped
at 64 KiB. `Selection` exposes its verified transport hints and `StageSignature`
checks the same private snapshot-bound descriptor before staging. The executor
places it adjacent to the package and retains pacman's native signature policy;
TUF transport verification does not replace native keyring trust.
Channels bind their ring, generation, seven-day maximum validity, pause state and
stable device/ring percentage eligibility. Rollout updates use
`-ring`, `-paused`, `-percentage`, `-expected-generation`, and `-request-id`; the
signed intent identity makes exact retries distinguishable from concurrent changes.

The client receives authenticated bootstrap `release_root_json`, a private state
directory, and an injected bounded transport callback. It never constructs a
network client. The native root process owns metadata verification and selection;
the unprivileged process supplies requested relative paths and bytes. Verified
high-water metadata is atomically fsynced before the next untrusted metadata read,
including timestamp advancement when a later refresh step fails. Checkpoints bind
the bootstrap digest, clock floor, and accepted channel generations/digests.
A separate fsynced initialization marker makes disappearance of either protected
checkpoint component a fail-closed error, not permission to reset rollback state.
Metadata is capped at 4 MiB per role, catalogs at 1 MiB, targets at 2 GiB, and the
repository at 4096 targets. Packages are streamed through SHA-256/length checking
to private staging and atomically published only after successful fsync.

The read-only HTTP handler accepts GET/HEAD only and rejects indexes, traversal,
symlinks, private paths and temporary names. Air-gap
`mirror -repository DEST -source SOURCE -root AUTHENTICATED_ROOT` transports the
same signed public files, verifies the complete root chain and every streamed
target, and commits the timestamp last. It does not disable freshness checks.
Root/targets/snapshot/timestamp validity limits are 365 days/7 days/7 days/1 day;
operators must refresh publication before expiration even in isolated sites.

Focused regression source covers actual signatures, root rotation/quorums,
rollback across restart and interrupted refresh, freeze, mix-and-match, catalog
binding/equivocation, target tampering, streaming cancellation, publication recovery,
and mirrored/HTTP boundaries. Run `go test -race ./internal/releaseupdate` after
all integration slices land; these library tests do not claim native package
transaction or full platform qualification.

### Clean release exports and custody (P20/L17)

`lab release build` creates two isolated source, HOME, Go module/compiler and npm
cache trees, installs the pinned frontend dependencies and builds all three
products for `amd64` and `arm64`. Native exports are DEB/RPM for `lindmd`,
`lindm-agent` and `lindmctl`; OCI exports are the server and CLI. An agent container
is not a substitute for host systemd/package ownership. Complete unsigned native
archives and deterministic OCI archives must match between both builders before
atomic export. RPM signatures are compared separately from the pre-sign archive.

Every artifact has a CycloneDX dependency SBOM and DSSE in-toto artifact/provenance
statements signed by a distinct pinned release-attestation key. These statements
describe two isolated builds on this host/toolchain, not independent organizations,
hermetic networking, transparency-log inclusion or SLSA certification. Release
verification uses an externally obtained public key and key ID, never a trust key
from the export being checked.

```sh
go run ./cmd/lab release build -repo . -output /private/release-export \
  -version 1.2.3 -revision RELEASE_LABEL -source-date-epoch UNIX_SECONDS \
  -signer-home /private/package-signing -fingerprint PACKAGE_FINGERPRINT \
  -attestation-key /private/attestation.pem -attestation-key-id PINNED_SPKI_ID \
  -oci-ca-bundle /private/approved-roots.pem -oci-ca-sha256 PINNED_CA_SHA256 \
  -signing-trust-inventory /private/signing-public-inventory.json \
  -signing-trust-inventory-sha256 PINNED_INVENTORY_SHA256
go run ./cmd/lab release verify -directory /private/release-export \
  -public-key /private/trusted-attestation-public.pem -key-id PINNED_SPKI_ID
```

Production attestation custody is operator-provisioned PKCS#8 mode `0600` with the
purpose sidecar required by the tool. The strict protobuf `SigningTrustInventory`
contains authenticated execution and TLS public keys and signed TUF public trust
metadata, including delegated-role identities. All domains are required. Keys are
compared by actual public material, not incompatible OpenPGP/TUF identifier strings;
the same exclusions reach the native package signer. Inventory and CA pins must
come from an independently authenticated release-custodian process.

OCI images are deterministic nonroot scratch images with a `0555` static executable
and the explicitly pinned CA bundle at `0444`; that material is covered by the image
digest, SBOM and provenance. Supply appropriate roots for public OIDC and configured
outbound TLS services. No ambient host root bundle is captured. Server startup still
requires operator configuration/secrets, explicit migration, read-only rootfs and
data volumes as described in the production runbook. The existing distroless
Compose image is a separate pinned deployment definition, not byte-identical to
these release OCI exports.

`release attestation-keygen`, `packages keygen`, and `-development-key` are explicit
laboratory facilities, not production custody provisioning. Required build tools,
fresh module/npm downloads and the pinned toolchain must be available; publication
does not silently exclude a failing architecture or format.

### Native unattended update verification (P20/L08/L17)

The maintained `lab vm updates` lane builds signed agent packages at `0.1.0` and
`0.2.0` from one immutable source snapshot, plus a matching local-auth control plane.
These are distinct release stamps from the same checkout, not historical release
implementations. It uses an isolated database and dynamic host listeners; the guest's
fixed TLS origins are forwarded through its owned SSH connection. It never binds
the shared host `:18444`, modifies development trust, or requires an external IdP.

```sh
go run ./cmd/lab vm updates -repo . \
  -manifest lab/images/ubuntu-noble-amd64.json \
  -record artifacts/updates-ubuntu.json
go run ./cmd/lab vm updates -repo . \
  -manifest lab/images/fedora-44-x86_64.json \
  -record artifacts/updates-fedora.json
```

Use the repository's pinned manifest filename for Fedora when selecting a snapshot.
The image cache, built embedded console, running development PostgreSQL and normal
native package/signing tools are prerequisites. `-lab FILE` selects a prebuilt guest
probe; otherwise the current lab executable is uploaded. `-diagnostics DIR` opts
into private failure diagnostics. `-record` refuses overwrite and contains public
build/runtime identities and observations, never keys, sessions or grant secrets.

SIGINT/SIGTERM cancel the lane through the CLI signal context. Owned guest,
authority/database, package service, overlays and signing/source staging unwind
through their existing bounded cleanup; cancellation skips the independent SSH
failure-diagnostic probe. The final record explicitly reports `outcome: cancelled`
with `cancellation_reason`, not a product failure or pass. Allow cleanup to finish:
SIGKILL/tool-forced termination cannot execute defers or guarantee a final record.
`TestVMUpdatesSignalsCleanOwnedStaging` exercises actual SIGINT and SIGTERM during
native signing staging and requires removal of owned bytes/processes plus a
cancelled record, without launching a guest.

Read-only update-status and unpack probes discard a closed SSH transport and
reconnect with the original host-key pin inside their existing deadlines. Native
mutations are never replayed after an ambiguous transport failure. A completed
status command may observe an unavailable executor during package replacement;
invalid status JSON, authentication and host-key failures are terminal. Deadline
errors retain the last successful update state. Reset recovery uses the common
fresh-pinned-connection, changed-boot-ID oracle, not old-socket FIN. Private failure
diagnostics independently reconnect and capture uptime/load, process/unit state,
update-helper and kernel journals; they do not reuse the failed connection.

The unpack witness loop also reads protected update status once per second: a
terminal recovery failure, rejection or already-completed installation is not an
interruption witness and fails immediately with the actual status. Failure
diagnostics include package-manager versions and a fresh protected update status.
An observation deadline is never interpreted as a native package transaction hang.

Self-update failures carry `NativeUpdateDiagnostic`: a fixed native executable
name, failed operation phase, exit code (`-1` when no exit status exists), at most
eight final error lines of 512 bytes each, and an explicit truncation flag. Native
output is sanitized before durable helper/journal storage; URLs, credentials,
environment assignments and control/terminal escapes are withheld. Neither raw
command arguments nor process environment are appended. The copied recovery helper
and root update status retain the historical diagnostic through restart/checking.
Only successful replacement clears the retained failure.

Normal mTLS/session-fenced heartbeats read this state from the root executor.
The server stores the current enrollment generation's latest status with a receipt
time, rejects older observations, and journals meaningful diagnostic/terminal
changes with an audit-event link. Identical heartbeat and checking timestamps do
not duplicate events. Reports are untrusted diagnostic telemetry, never native
success authority. Device Overview's collapsed Diagnostics section displays the
historical status, manager/phase/exit code and escaped bounded error text; missing
reports explicitly remain unknown, and page refresh uses the existing scoped
device query.

The lane observes signed pause and zero-percent holds, timestamp rollback, mixed
targets, actual expiration of a previously valid unchanged timestamp, and package
byte tampering before native admission. It then applies a kernel-verified I/O limit
to the owned update slice, waits for an actual native unpack temporary file and
installer PID in the update helper's cgroup, and issues an owned QEMU `system_reset`.
After a different boot ID, the persistent protected helper must finish the exact
native update; package database, architecture, binary stamp/digest, daemon readiness
and unchanged enrollment identity are checked. A fresh signed downgrade offer must
remain rejected. Fedora requires SELinux Enforcing throughout.

This is KVM/QEMU guest-reset and virtual-block-device evidence, not physical power
removal or drive-cache qualification. A library test or manual package installation
does not substitute for this lane. Native arm64, Arch/zypper transactions and other
hardware/OS tuples require their own recorded runs.

## 2. Toolchain and quality gates

Pin a supported Go release and `toolchain`, PostgreSQL major/patch image digests, Node
LTS, package lock, Buf/protoc/Connect generators, sqlc, golangci-lint, govulncheck,
packaging/signing tools and VM firmware/images. Download/cache through a single
bootstrap path with verified integrity; CI and local development resolve the same
versions. Development offline bundles include module/npm/tool/image caches when an
offline engineering environment is required. Runtime air-gap support does not depend
on a developer having external package registries.

Required Go checks: gofmt, goimports, `go vet`, golangci-lint with staticcheck,
error-handling and resource-leak checks, govulncheck and race tests. Begin with a small
reviewed linter set, not every available opinionated rule. Exclusions are narrow,
justified and reviewed. Ban blanket `nolint`, ignored errors, unbounded subprocess
output and security checks disabled in production configurations.

Required contract checks: Buf lint/breaking, deterministic generation, `sqlc vet`,
migration/query tests on real PostgreSQL, cross-version agent contracts, dependency
license/SBOM review and secret scanning. TypeScript uses strict type checking, ESLint,
Prettier and real browser acceptance. Package/install shell glue uses ShellCheck;
workflow definitions use actionlint. Pin CI actions by commit and restrict permissions.

Documentation tooling currently uses exact Prettier, markdownlint-cli and lint-staged
versions. Transitive `js-yaml`, `smol-toml` and `katex` overrides select patched releases
for GHSA-r3ph-w7gj-g6xm, GHSA-r4xh-jqrq-34v2 and GHSA-238p-pmpm-9mq7. Review/remove
overrides when upstream dependency ranges include those fixes. markdownlint-cli2 was
rejected here because its braces-dependent glob stack had GHSA-vfj7-8cjw-p6xm with no
patched braces release available during setup. Run the maintained dependency-audit
command when updating the lock; do not silence advisories or apply unreviewed forced
downgrades. These are development dependencies, not an application security claim.

Go is pinned to 1.26.9 in `go.mod` and Make, and `golang.org/x/net` to v0.60.0.
These replace the versions rejected by the audit for newly published HTTP/TLS
advisories, including [GO-2026-6617](https://pkg.go.dev/vuln/GO-2026-6617) and
[GO-2026-6607](https://pkg.go.dev/vuln/GO-2026-6607). The required dependency updates
also select `x/crypto` v0.57.0, retaining the fixes for SSH advisories
[GO-2026-6354](https://pkg.go.dev/vuln/GO-2026-6354) and
[GO-2026-6355](https://pkg.go.dev/vuln/GO-2026-6355). The patched build passed the
full quality/integration run and real SSO login against the restarted server.
The audit reports no affected symbols or imported packages. It still identifies
module-level
[GO-2026-5932](https://pkg.go.dev/vuln/GO-2026-5932) for the unused, unmaintained
OpenPGP package; do not import it. Vendor-image signatures use isolated GnuPG `gpgv`,
not that package. Audit output is evidence of known reachability, not proof of
absence of vulnerabilities.

Pre-commit operates on the staged snapshot and runs fast formatting/lint checks.
It must not silently reformat unrelated files or require booting VMs. Pre-push and CI
run the broader affected checks; protected-branch CI is authoritative because hooks
can be bypassed. Install hooks explicitly through bootstrap. The initial docs hook
uses lint-staged to preserve partially staged changes; extend it with Go/proto/SQL/UI
checks as those sources land, not no-op checks for files that do not exist.

## 3. One repeatable command surface

Use a small Makefile as orchestration once product code exists. Use Go for lifecycle
stateful orchestration, declarative manifests for matrices, and existing tools for
format/lint/build/packaging. Shell recipes should compose tools, not contain a second
implementation of business logic. CI calls the same targets as developers.

For in-place greenfield migration edits, recover a stale shared development schema
with `go run ./cmd/dev recreate-database -confirm-delete`, not a cluster reset.
Coordinate the shared server and any tests using schemas inside `lindm` first:
the command terminates connections and deletes that entire database only. It verifies
the running checkout-owned Compose PostgreSQL container, protected secret mount and
loopback endpoint, uses the fixture superuser over verified TLS, retains cluster
roles and all other databases, and reapplies initial database permissions. Explicit
`lindm_migrator` migration, metadata-write restriction and authentication-mode owner
bootstrap use the same path as `up` (local mode prints the one-shot command).
Keycloak, volumes, certificates and secrets are untouched. Consent is mandatory
even when no server is connected; arbitrary database selection is not supported.

| Required target                         | Contract                                                                                                                                                                |
| --------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `make bootstrap`                        | Verify/install pinned tools, fetch verified caches, install hooks, explain missing KVM/container prerequisites without mutating host security                           |
| `make dev`                              | Start isolated PostgreSQL/test IdP/artifact service, apply development migrations and run reloadable server/frontend; no production secrets                             |
| `make test`                             | Fast deterministic unit/contract tests; preserve the ability to run `go test ./internal/... -run ...` directly                                                          |
| `make integration`                      | Real ephemeral PostgreSQL and OIDC/worker/auth scenarios with isolated state and fixed fixtures                                                                         |
| `make lint`                             | All handwritten language/schema/workflow checks using locked tools; non-mutating                                                                                        |
| `make generate` / `make generate-check` | Regenerate from pinned protobuf/SQL tools; fail if checked-in output differs                                                                                            |
| `make lab`                              | Select manifest and scenario, build actual packages, provision disposable VM(s), exercise and assert, collect evidence, destroy only owned resources                    |
| `make lab-desktop`                      | Invoke versioned openQA graphical/installer scenarios and shared API assertions                                                                                         |
| `make lab-airgap`                       | The lifecycle lab with denied external egress and a complete local mirror/IdP/PKI topology                                                                              |
| `make release-check`                    | Full release gates including required physical evidence references; fail on absent/expired evidence rather than skip                                                    |
| `make package`                          | Native package/image/generation artifacts, OCI/binaries, embedded UI, SBOM and signing inputs; two-clean-build digest comparisons and no implicit production-key access |

Commands support explicit test filters, bounded parallelism and machine-readable
results. A developer reruns a failed scenario by run manifest and seed, not by copying
commands out of CI logs. Dry-run shows which VM/network/disk resources will be touched.
Destroy is limited to harness-owned tagged resources; the developer's host is never a
test endpoint. Missing privilege yields an actionable error, not a swallowed failure.

## 4. Fast loop without weakening evidence

Cache immutable VM images and compiler/module dependencies; use per-test overlays and
fresh enrollment identities. Do not rebuild installer ISOs or download distribution
repositories for every provider edit. Keep a cached representative Debian and RPM
image available locally. PostgreSQL/IdP integration runs in isolated containers;
boot/session/TPM/encryption tests run on VMs/hardware, not containers.

Targets on a documented developer machine: focused cached tests within 5 seconds,
format/lint feedback within 30 seconds, representative cached VM lifecycle within
5 minutes. These are feedback budgets to measure, not current results. Expensive
full-ISO, graphical, cross-distro, soak and physical runs are separate lanes, but
remain mandatory before release. Changed-provider selection cannot omit its real
native-interface smoke test.

Avoid flaky fixed sleeps. Poll an observable state with a deadline and structured
failure evidence. Tests use controlled time where appropriate; full lifecycle still
exercises real reboot/renewal boundaries. Do not mock away OS package transactions or
OIDC validation in tests claiming those integrations work. No test may depend on the
operator's global configuration, production network or shared mutable device.

## 5. Contribution and delivery contract

Every change includes intent, threat/compatibility impact, affected P/L requirements,
actual exercised verification and any unsupported environment. Update docs and release
notes with behavior changes. Keep commits coherent and reviewable; no claim that a
planned gate passed. A release manifest references immutable evidence, not a mutable
"latest successful" badge.

Each implementation slice requires consecutive implementation and review rounds:

1. Complete the affected behavior, exercise its real runtime path, run the affected
   quality gates and commit the verified implementation with evidence.
2. Obtain independent correctness, security, maintainability and scope review.
3. Fix accepted findings, repeat the affected verification and commit corrections
   separately. Repeat review until findings are resolved or explicitly dispositioned.

Do not manufacture empty corrective commits or superficial tests to satisfy this
sequence. Do not mix unverified work into a verified implementation commit. Review
must inspect behavior and failure boundaries, not merely confirm formatting.

The initial specification and automation are committed without selecting a public
software license on the owner's behalf. Before external distribution, choose product
licensing and review all source/content redistribution. Clones used for research live
outside this repo under `~/dev/minor/clones`; no vendored commercial Fleet code or
unattributed documentation copying.
