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
