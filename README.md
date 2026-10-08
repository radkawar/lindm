# lindm

Greenfield Linux device management: desktop-first, servers included, self-hosted,
single-tenant, connected and air-gapped.

**Specification stage. There is no runnable MDM server or agent yet.** No distro,
security, capacity or destructive-action capability is certified. The first delivery
is a researched, independently reviewed implementation contract and repository checks;
implementation follows its decision gates.

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

Use the Node LTS version in `.node-version`, npm, Git and Make. Dependencies are exact
versions with an integrity-bearing lockfile. No global npm packages are required.

```sh
make bootstrap
make lint
make fmt
```

- `make bootstrap`: clean locked dependency installation without lifecycle scripts,
  then explicit repository-local Git hook installation.
- `make lint`: non-mutating Prettier and Markdown lint checks, also run by CI.
- `make test-tooling`: exercise the real commit/push hooks in disposable repositories,
  including invalid staged content, partially staged preservation and dependency exclusion.
- `make fmt`: apply repository formatting.
- `make audit`: check the development dependency lock against current registry
  advisories; requires registry access and is separate from offline linting.
- Pre-commit: lint-staged checks the staged Markdown/JSON/YAML/JavaScript snapshot, including
  partially staged files, without reformatting it.
- Pre-push: run full specification checks. Hooks are not a substitute for protected
  branch CI and can be bypassed locally.

With mise installed, the pinned runtime can be used without changing global settings:

```sh
mise install node@24.21.0
mise exec node@24.21.0 -- make bootstrap
mise exec node@24.21.0 -- make lint
```

These commands validate the specification/tooling only. Future Go/proto/SQL/UI and
machine-lifecycle gates are specified in the engineering document; nonexistent
application checks are not reported as passing. Product license, distribution
identity, enterprise image entitlements and physical laboratory access are explicit
decisions before the affected implementation/release gates.
