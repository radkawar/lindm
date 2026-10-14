# Contribute to lindm

lindm v0.1 is a preview. Do not use it as a production-ready management system.
Read [AGENTS.md](AGENTS.md) and sections 1–5 of
[docs/engineering.md](docs/engineering.md) before you change behavior. Follow the
[Code of Conduct](CODE_OF_CONDUCT.md). Report vulnerabilities privately as described
in [SECURITY.md](SECURITY.md).

## Set up an external clone

Fork the repository on GitHub. Clone your fork and create a topic branch. Use a
normal writable clone. You do not need a maintainer's private worktree, lab host,
Sparks service, signing keys or home-directory configuration.

Use Linux, Git, Make, a C compiler for Go race tests, Go 1.26.9 and Node 24.21.0 with
npm. The repository pins Go in `go.mod` and Make, Node in `.node-version`, Go tools
in Make and npm dependencies in `package-lock.json`. Allow network access to the
Go and npm registries and the pinned container images for initial setup.

Keep at least 12 GiB of memory available before integration starts. The default
admission reserves 4 GiB for the race suite and 8 GiB of host headroom, and waits
while the host swaps out pages. Use a larger machine if this budget is not available.
Do not lower the VM lab's admission checks to force a passing integration result.

Install Docker Engine and the Docker Compose v2 plugin. Check that your account can
run `docker info` and `docker compose version`. Docker access grants broad host
privileges. Use a disposable development machine if that access is not appropriate.
The supported commands below use Docker, not Podman Compose.

On Ubuntu 24.04, install the native package and fixture tools:

```sh
sudo apt-get update
sudo apt-get install --no-install-recommends --yes \
  build-essential git make gnupg gpgv cloud-image-utils apt-utils dpkg-dev \
  rpm rpm2cpio cpio createrepo-c systemd rsync
make bootstrap
```

`make bootstrap` installs pinned Go tools into `.tools/bin`, runs
`npm ci --ignore-scripts` and installs the repository's Git hooks. Do not replace
locked tools with unrelated system versions. Hooks can fail a commit or push;
they do not replace review or hosted CI.

## Build and test

Run the checks that match your change. Run the full local checks before you request
review:

```sh
make check
make test-integration
```

- `make check` builds the embedded console, checks Go/TypeScript/schema/document
  formatting and lint, type-checks the console, runs race-enabled Go and Node unit
  tests, checks generated documents and audits dependencies.
- `make test-integration` starts the checkout-owned Docker Compose PostgreSQL and
  Keycloak fixture, applies explicit migrations and runs the real OIDC smoke and
  integration-tagged tests. It prepares checkout-owned development execution and
  release roots for native-server regressions and builds a release-stamped server.
  It validates existing fixture trust rather than replacing it. These keys are not
  production trust. The fixture uses loopback ports 15432 and 18443. Keep these ports
  free; do not stop someone else's fixture to claim them.
- `make build` writes server, agent and lab binaries into `artifacts/bin`.
- For a focused loop, run commands such as
  `go test -race ./internal/agent/inventory ./internal/trust` or
  `npm run lint:web` and `npm run typecheck:web`.

The fixture creates its own credentials and TLS roots in `.cache/dev`. Do not edit
or commit that directory. Database connections require `sslmode=verify-full`.
Integration tests take an owner-only DSN file through
`LINDM_TEST_DATABASE_URL_FILE`; the harness sets its path. Do not put a password or
DSN in argv, environment variables, logs or issues. Do not replace verified TLS with
`sslmode=disable`, `require` or an unchecked certificate to make a test pass.

Stop only your checkout's services with `make dev-down`. This preserves its data.
Use `go run ./cmd/devenv reset -confirm-delete` only when you intend to delete that
checkout's fixture data and credentials.

For console changes, install the locked browser and run the real Chromium journey:

```sh
./node_modules/.bin/playwright install --with-deps chromium
make dev-up
make dev-trust
make check-web ACCEPTANCE_FLAGS="-engines chromium"
make dev-down
```

`check-web` drives the real server and console on an owned local-auth fixture. It
builds signed development enrollment packages with disposable keys. It does not
run native VMs, refresh the release feed matrix or qualify a release. Read
[docs/design.md](docs/design.md) before changing the UI. Provide the required design
review and before/after light/dark, desktop/mobile evidence. Automated checks do
not grant owner design approval.

## Change source, not generated output

Edit `.proto` schemas, SQL queries and migrations at their source. Run
`make generate` and include the generated result in your pull request. Do not
hand-edit `gen/`, `web/gen/`, sqlc output or `web/src/routeTree.gen.ts`. Use
`go run ./cmd/devenv generate-docs -check` to check generated document regions.
Keep source headers and upstream attribution. Update the relevant docs and release
notes when behavior changes. Update the matching `docs/platforms/` page for
platform-specific changes.

Keep changes small and coherent. Add a deterministic regression test for a bug fix
when practical. Preserve authorization, custody, TLS, audit and rollback boundaries.
Request design review before a public API or irreversible migration change. Sensitive
execution, authentication, update, encryption and wipe changes need security review.

## Sign your commits with the DCO

Certify each commit under the
[Developer Certificate of Origin 1.1](https://developercertificate.org/). Add a
`Signed-off-by: Your Name <your-email>` trailer with `git commit -s`. Use the identity
that can certify your right to contribute the change. This is a certification, not
a cryptographic signature or an assignment of copyright. Contributions to lindm are
under Apache-2.0, as described in section 5 of [LICENSE](LICENSE). No separate CLA is
required beyond the DCO. Preserve the licenses and notices of third-party material.

DCO sign-off is different from `make signoff`. The latter is a maintainer verification
command, not a way to add the DCO trailer.

`cmd/dev land` and `cmd/dev gate-commit` add the configured committer's own DCO
trailer. Before you use these commands, check that your Git identity can certify the
change. They do not add trailers for recorded coauthors.

Hosted DCO checks exempt only commits authored by `dependabot[bot]` with its
canonical GitHub noreply address. Human coauthors and every other commit in the
same pull request still require their own trailers. Dependency pull requests keep
all lint, unit, audit, integration and browser checks.

## Open a pull request

Describe intent, user-visible behavior, threat and compatibility impact, affected
P/L requirements if applicable, and the actual commands you exercised. State failures,
skips and unsupported environments. Link evidence without exposing tokens, credentials,
private device data or recovery secrets. Never claim a planned check passed.

Hosted CI checks author and coauthor DCO trailers, lint and generated output, unit and dependency checks, real
PostgreSQL/Keycloak integration, and the Chromium web-only journey. Root/capability
checks can skip on an unprivileged runner. A skipped check is not a pass. Hosted CI
is not evidence for native package installation, boot, reboot, TPM, encryption,
physical devices or the full platform matrix.

Every push to `main` gets an independent hosted CI run, including when an earlier
run is still active. A later main push cannot replace a pending verification.
Pull-request runs remain grouped by their pull-request ref so a new commit cancels
obsolete checks for that same pull request.

Hosted checks run on pushes to main and pull requests that target main.
Use `workflow_dispatch` for a manual run.
No hosted release publishing job or signing secret is required.

The public `ubuntu-24.04` runner has 16 GB of RAM under GitHub's
[runner specification](https://docs.github.com/en/actions/reference/runners/github-hosted-runners).
Integration still needs 12 GiB available at admission. The standard private
repository runner has 8 GB and cannot meet that budget. Use sufficient capacity;
do not weaken admission or report a timed-out wait as a pass.

## Maintainer-only landing and release evidence

Maintainers use `go run ./cmd/dev worktree add NAME` when they share a protected
checkout. They land through `cmd/dev land`, not by copying files into the shared
checkout. An external contributor uses a fork and pull request instead.

Keep `make signoff`. It checks a pushed commit in a clean worktree against the
maintainer's fixture and posts commit-specific `gh signoff` statuses. Maintainers
need the `gh signoff` extension and suitable GitHub access for that command;
external contributors do not need it to submit a pull request.

Maintainers run the VM/native lab, full Chromium/WebKit/Firefox acceptance, platform
matrix and physical checks with the required privileges, pinned images and owned
resources. Follow [docs/verification.md](docs/verification.md). Do not turn missing
lab access into a passing result, bypass custody checks or treat VM evidence as
physical validation. v0.1 has no official project signing keys. Operators build and
sign their own releases; development fixture keys confer no production trust.
