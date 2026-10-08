# Engineering and developer experience

Status: specification-first repository. Only the documentation/tooling commands
listed as available in the root README exist today. The product build/test commands
below are implementation requirements, not fake passing targets.

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
- Public APIs and irreversible migrations require design review. Sensitive execution,
  auth, update, encryption and wipe changes require security-owner review.

### Planned code layout

| Area                                               | Responsibility                                                                                                                     |
| -------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| `cmd/lindmd`, `cmd/lindm-agent`, `cmd/lindmctl`    | Composition and entrypoints only                                                                                                   |
| `api/`, `gen/`                                     | Versioned protobuf sources and generated Go/TypeScript                                                                             |
| `internal/controlplane/`                           | Cohesive identity, fleet, policy, execution and audit domains                                                                      |
| `internal/store/`, `db/migrations/`, `db/queries/` | sqlc-generated pgx persistence and reviewed SQL                                                                                    |
| `internal/agent/`                                  | Unprivileged transport/spool, separately root-owned executor journal/trust, reconciliation and native update supervision           |
| `internal/provider/`                               | Native package/network/service/security adapters with narrow contracts                                                             |
| `web/`                                             | Typed console and browser self-service surfaces                                                                                    |
| `packaging/`, `deploy/`                            | DEB/RPM/Arch and Nix/OSTree delivery, systemd/SELinux/AppArmor, native/OCI/replicated server deployment and local assistance relay |
| `test/lab/`                                        | Declarative image/capability/scenario manifests and reusable Go lifecycle harness                                                  |

Create a package when it owns working behavior. Do not create all directories,
interfaces and empty tests up front merely to match this table.

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

The initial specification and automation are committed without selecting a public
software license on the owner's behalf. Before external distribution, choose product
licensing and review all source/content redistribution. Clones used for research live
outside this repo under `~/dev/minor/clones`; no vendored commercial Fleet code or
unattributed documentation copying.
