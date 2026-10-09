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
in links. Owners manage local accounts at `/accounts`: create, enable/disable,
change owner/admin role or break-glass designation, and reset credentials.
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
The VM lane requires accessible KVM, QEMU, `qemu-img` and `cloud-localds`; it neither
changes host security nor substitutes container observations for a real guest.
The integration lane also exercises real `cloud-localds` cancellation: staging stays
inside the owned private run directory and helper descendants stop before cleanup.
It requires `cloud-image-utils`, but not KVM or a booted guest.
`go run ./cmd/lab auth check` exercises the running server's normal SSO/CSRF path
against the fixed development fixture. The reusable development-session helper keeps
passwords/cookies in memory, restricts TLS destinations and credential form actions,
and revokes its console session. It is not an alternate production authentication API.

Local identity tests use a real PostgreSQL schema and a software P-256 WebAuthn
authenticator, not a verifier mock. The `TestLocal*` and `TestBreakGlass*` integration
tests exercise password lockout, one-use enrollment and challenges, replay/expiry,
immediate disable, worker fences and emergency audit. Run these with the same
`LINDM_TEST_DATABASE_URL` used by the integration lane. Browser qualification must
add a Chromium CDP virtual authenticator with user verification enabled and complete
`/enroll`, sign-in, account reset and the persistent emergency banner.

The generated protobuf-JSON HTTP contract is `GET /auth/options`, plus
`POST /auth/local/login/begin`, `/auth/local/login/finish`,
`/auth/local/enroll/begin` and `/auth/local/enroll/finish`. Owner-only account
operations are `GET /auth/accounts` and `POST /auth/accounts/create`,
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
application access, and test-owned users/groups remain prerequisites for R1.
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
and revocation without native effect.
An inert pre-enrollment fixture and independent systemctl/start-witness observations
remain separate from server evidence. `-record` includes build digests, timing and
explicit failure state and never overwrites an earlier run. Owned guests, private
server processes, signing material and databases are cleaned up.
Optional `-hold 45m` reserves the normal development console port and pauses before
revocation, keeping the guest, database and real server available for authenticated
browser assignments. The ordinary dev server must not occupy port 18444. The
printed origin uses the same dev CA and Keycloak owner login; timeout or SIGINT
resumes native re-observation, revocation and cleanup. Holds are bounded to one hour.
Unstarted supersession is covered by the real-Postgres integration test, **not
natively exercised**: acquisition requires the executor-held mTLS signer, so
stopping that executor cannot deterministically hold an unstarted acquired action.
No product fault seam is added. See [the command details](agent-enrollment.md#running-the-connected-service-dispatch-lane).

The authenticated **Profiles** console uses these same catalog RPCs. Editors use
the generated protobuf constraints, including shared custom validation rules,
instead of a second handwritten schema. Resource dependencies are typed references;
the resolver additionally rejects cycles and preserves blocked/conflicting results.
The editor captures one request ID and payload before sending, retains an ambiguous
attempt across route navigation, and only changes its expected head/request identity
on an explicit rebase or replacement. Revision refresh failures do not discard an
unsent draft. These drafts and attempts are tab-memory state, not durable browser
storage: full reload and sign-out clear them. Exact server-side retry receipts and
retained revisions remain durable.

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
