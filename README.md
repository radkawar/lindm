# lindm

Greenfield Linux device management: desktop-first, servers included, self-hosted,
single-tenant, connected and air-gapped.

**Internal control-plane gate verified; not a production-ready MDM.** The Go
server and authenticated React console run against real PostgreSQL and Keycloak.
The separate root executor and unprivileged network agent implement packaged
enrollment and inventory. Native management and commercial release gates remain
open. No distro, capacity or destructive capability is certified. The full
specification remains the delivery contract.

## Read the specification

1. [Product requirements and acceptance](docs/product-specification.md)
2. [Backend, agent, identity and RPC architecture](docs/architecture.md)
3. [Security, air-gap, deployment and operations](docs/security-and-operations.md)
4. [Distro matrix and full lifecycle verification](docs/verification.md)
5. [Engineering standards and fast inner loop](docs/engineering.md)
6. [Implementation sequence and decision gates](docs/implementation-plan.md)
7. [Research, sources and tradeoffs](docs/research.md)
8. [Independent review findings and dispositions](docs/review-dispositions.md)
9. [Packaged agent, protected trust and native lifecycle contract](docs/agent-enrollment.md)

The design uses Go, protobuf/Connect, PostgreSQL/pgx/sqlc, OIDC, a separate device
agent and typed native Linux providers. It does not claim a universal Linux MDM
protocol, use arbitrary scripts as its management model, or equate VM tests with
physical wipe/recovery validation.

## Current development commands

Use the Node LTS version in `.node-version`, Go from `go.mod`, npm, Git and Make.
Native inventory requires Linux. Verification and native packaging require `gpg`,
`gpgv`, `gpgconf`, `dpkg-deb`, `dpkg-scanpackages`, `apt-ftparchive`, `rpm`,
`rpmbuild`, `rpmsign`, `rpm2cpio` and `cpio`. `createrepo_c` enables signed RPM
repository publication. The development lab requires Docker with Compose v2 and a
local daemon. The integration lane requires `cloud-localds` (`cloud-image-utils`)
for real seed-cancellation cleanup without booting a VM. Dependencies and build
tools are pinned; global npm packages are not required.

```sh
make bootstrap
make generate
make dev-up
go run ./cmd/lindmd serve -config .cache/dev/server.json
```

`dev-up` builds embedded console assets, generates protected development credentials,
starts digest-pinned PostgreSQL and Keycloak, checks TLS and directory access, migrates
with a separate database role, and binds the initial owner. It does not start the
application process. Repeating it preserves existing credentials and data.

Open `https://localhost:18444` using a development browser profile that trusts
`.cache/dev/transport-ca.crt`. Sign in as `owner`; the generated password is in
`.cache/dev/owner-password`. The application, IdP and database require verified TLS;
there is no production no-auth or insecure-TLS mode. The separate device mTLS listener
is on port 18445. Development ports are loopback-only.

| Command                 | Purpose                                                                                   |
| ----------------------- | ----------------------------------------------------------------------------------------- |
| `make bootstrap`        | Install pinned generators/linters, locked npm dependencies and repository-local Git hooks |
| `make generate`         | Generate protobuf Go/TypeScript contracts and sqlc queries                                |
| `make build`            | Build the console and `artifacts/bin/{lindmd,lindm-agent,lab}`                            |
| `make check`            | Format checks, Go/protobuf/Markdown/TypeScript lint, race tests and dependency audit      |
| `make test-integration` | Start/check the lab and run real PostgreSQL regressions in disposable isolated schemas    |
| `make dev-check`        | Check runtime database TLS and actual OIDC/directory access                               |
| `make dev-trust`        | Create or verify development-only DSSE bootstrap/execution and separate TUF trust         |
| `make dev-down`         | Stop this checkout's lab services while preserving credentials and volumes                |
| `make fmt`              | Apply repository formatting                                                               |

The lab uses `.cache/dev` with mode 0700 and secret files with mode 0600. Never commit
or copy these credentials. Development-only certificates last five years. Moved,
changed or expired fixtures fail explicitly instead of silently rotating credentials
beneath persisted data. Destructive reset is a separate, explicitly confirmed command:
see `go run ./cmd/dev help`. Fixed ports allow one running checkout at a time.

With the real server running, `go run ./cmd/lab auth check` exercises its normal
authorization-code/S256-PKCE login against the fixed Keycloak fixture, reads a bounded
admin device page, then revokes the console session. It uses the protected fixture
owner credential and an in-memory cookie jar; no direct password grant, production
authentication bypass, exported browser cookie or password argument is involved.
Lifecycle scenarios can reuse this helper rather than exporting browser cookies.

These standalone agent commands observe native state and verify bootstrap
authority without enrolling or modifying the host:

```sh
make build dev-trust
artifacts/bin/lindm-agent inspect
artifacts/bin/lindm-agent verify-bootstrap \
  -root .cache/dev/agent-trust/execution-root.json \
  -bundle .cache/dev/agent-trust/bootstrap.dsse.json
```

`inspect` emits protobuf JSON with typed availability/failure states. A failed package
collection emits no partial package list and exits unsuccessfully. Its output can
contain hardware identifiers: treat saved observations as device data.
Development trust is a protected 30-day fixture, not a production signing service.
Repeated `dev-trust` verifies existing files; expiry or modification fails rather
than silently replacing trusted keys.

Native packages install `/usr/libexec/lindm/lindm-agent`, a root executor service,
and a separate `lindm` network service. Root-only `bootstrap` and `resume` use
`/etc/lindm/executor.json`; `run` uses `/etc/lindm/agent.json` as the configured
network account. `status` combines protected executor state with explicitly
unprivileged transport diagnostics; it does not assert online presence or
compliance. Removal and purge retain identity and inventory state, never reset it.
`trust-update -file FILE` relays signed execution-root rotations and online
delegations through the protected executor; it never starts work or replaces TLS
pins. The native lifecycle lane's `-execution-trust` option exercises this command
and retained rollback fences across upgrade, reboot and reinstall.
See the [agent contract](docs/agent-enrollment.md) for ownership, recovery and
native laboratory commands.

The maintained laboratory command authenticates vendor metadata before downloading
large images, then checks every image byte. `verify` uses only local cached artifacts:

```sh
artifacts/bin/lab images fetch -manifest lab/images/ubuntu-noble-amd64.json
artifacts/bin/lab images fetch -manifest lab/images/fedora-44-x86_64.json
artifacts/bin/lab images verify -manifest lab/images/ubuntu-noble-amd64.json
artifacts/bin/lab images verify -manifest lab/images/fedora-44-x86_64.json
```

The dedicated `.cache/lab/images` cache is digest-addressed, locked and never silently
repairs corrupt entries. The VM observation scenario rechecks and pins the immutable
base image, boots a disposable overlay and compares the built agent against complete
native package and host observations before and after collection:

```sh
artifacts/bin/lab vm inspect -manifest lab/images/ubuntu-noble-amd64.json -agent artifacts/bin/lindm-agent
artifacts/bin/lab vm inspect -manifest lab/images/fedora-44-x86_64.json -agent artifacts/bin/lindm-agent
```

This lane requires `qemu-system-x86_64`, `qemu-img`, `cloud-localds` and accessible
`/dev/kvm`; it does not change host permissions or use host sudo. Guest networking is
restricted, SSH uses ephemeral credentials and a pinned host key, and cleanup kills
and reaps the owned VM before removing its private overlay/seed. Add
`-diagnostics EXISTING_DIRECTORY` only when needed: a cloud-init failure then saves a
0600 diagnostic that can contain sensitive guest data and must be removed by its
owner. These commands exercise native inspection, not package installation,
enrollment, desktop qualification or physical recovery.

Pre-commit checks the staged snapshot; pre-push runs `make check`. CI additionally
checks generated-contract drift and real database regressions. Hooks are not a
substitute for protected-branch CI. Dependency audit requires registry/advisory access;
`make lint` and `make test` are separate checks for already provisioned offline work.

With mise installed, use the pinned Node runtime without changing global settings:

```sh
mise install node@24.21.0
mise exec node@24.21.0 -- make bootstrap
mise exec node@24.21.0 -- make check
```

Current behavior includes real OIDC login, lifecycle-fresh directory authorization,
audited enrollment grants, device certificate/inventory RPCs and fleet/audit views.
See the [evidence ledger](docs/implementation-plan.md#2-evidence-ledger) for exercised
paths and remaining gates. Protocol tests are not proof of native agent installation,
full distro management or commercial readiness. Distribution identity/licensing,
enterprise entitlements and physical lab access remain explicit release prerequisites.
