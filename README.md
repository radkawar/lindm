# lindm

Greenfield Linux device management: desktop-first, servers included, self-hosted,
single-tenant, connected and air-gapped.

**Control-plane implementation in progress; not a production-ready MDM.** The Go
server and authenticated React console run against real PostgreSQL and Keycloak.
The separate agent, native management providers and commercial release gates remain
to be implemented and qualified. No distro, capacity or destructive capability is
certified. The full specification remains the delivery contract.

## Read the specification

1. [Product requirements and acceptance](docs/product-specification.md)
2. [Backend, agent, identity and RPC architecture](docs/architecture.md)
3. [Security, air-gap, deployment and operations](docs/security-and-operations.md)
4. [Distro matrix and full lifecycle verification](docs/verification.md)
5. [Engineering standards and fast inner loop](docs/engineering.md)
6. [Implementation sequence and decision gates](docs/implementation-plan.md)
7. [Research, sources and tradeoffs](docs/research.md)
8. [Independent review findings and dispositions](docs/review-dispositions.md)

The design uses Go, protobuf/Connect, PostgreSQL/pgx/sqlc, OIDC, a separate device
agent and typed native Linux providers. It does not claim a universal Linux MDM
protocol, use arbitrary scripts as its management model, or equate VM tests with
physical wipe/recovery validation.

## Current development commands

Use the Node LTS version in `.node-version`, Go from `go.mod`, npm, Git and Make.
The Linux development lab additionally requires Docker with Compose v2 and a local
daemon. Dependencies and build tools are pinned; global npm packages are not required.

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
| `make build`            | Build the console and `artifacts/bin/lindmd`                                              |
| `make check`            | Format checks, Go/protobuf/Markdown/TypeScript lint, race tests and dependency audit      |
| `make test-integration` | Start/check the lab and run real PostgreSQL regressions in disposable isolated schemas    |
| `make dev-check`        | Check runtime database TLS and actual OIDC/directory access                               |
| `make dev-down`         | Stop this checkout's lab services while preserving credentials and volumes                |
| `make fmt`              | Apply repository formatting                                                               |

The lab uses `.cache/dev` with mode 0700 and secret files with mode 0600. Never commit
or copy these credentials. Development-only certificates last five years. Moved,
changed or expired fixtures fail explicitly instead of silently rotating credentials
beneath persisted data. Destructive reset is a separate, explicitly confirmed command:
see `go run ./cmd/dev help`. Fixed ports allow one running checkout at a time.

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
