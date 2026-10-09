# lindm

Greenfield Linux device management: desktop-first, servers included, self-hosted,
single-tenant. The first release (R1) is connected, non-destructive service-state and
inventory management for Ubuntu LTS and Fedora/RHEL; air-gap, more resources, more
distributions (including Arch, Tumbleweed, Fedora Atomic and NixOS) and employee
workflows are gated roadmap.

**Not a production-ready MDM.** The Go server and authenticated React console run
against real PostgreSQL. The root executor and unprivileged agent implement packaged
enrollment and inventory. Service-state assignments now travel from the console
through the server to installed agents and come back as device-signed results.
Admins sign in with built-in local accounts (password plus WebAuthn) or through
optional Keycloak or Entra. No distro, capacity or destructive capability is
certified, and Entra has not been tested against a live tenant; see the
[release allocation](docs/product-specification.md#3-release-requirements-and-allocation).

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

### Authentication modes

The serialized server config requires `authentication` with exactly one primary
source. Local-only deployments use `"authentication": {"local": {}}`; they need no
IdP credentials and never discover or contact an identity provider. Keycloak uses
`"authentication": {"keycloak": {...}}`, with `issuer`, `clientId`,
`clientSecretFile`, `directoryClientId`, `directoryClientSecretFile` and
`administratorGroups`. Login and directory clients must be distinct. The old
top-level `oidc` field is rejected, not migrated implicitly.

The development fixture defaults to Keycloak to preserve the real SSO and
`check-fresh` lanes. To create a fresh local-only fixture instead:

```sh
go run ./cmd/dev up -authentication local
go run ./cmd/lindmd bootstrap-owner -config .cache/dev/server.json -username owner
go run ./cmd/lindmd serve -config .cache/dev/server.json
```

Trust `.cache/dev/transport-ca.crt` in the browser, open the printed enrollment URL
and enter the separately printed one-use secret. The URL never contains the secret.
Set the local password and register a user-verifying WebAuthn authenticator;
password acceptance alone cannot create an administrator session. The CLI prints
the secret only once, with its expiry and account ID. A second owner claim fails.
Keep the secret out of logs, browser storage and shell arguments.

Local `dev up` starts only PostgreSQL and prints the explicit bootstrap command;
repeating it never reissues an enrollment secret. `dev check` checks only the
selected mode's dependencies. `init` and `up` accept `-authentication keycloak`
(the default) or `local`; existing fixtures cannot switch modes. Version-1 fixtures
and changed configs fail validation. Preserve their data or use the explicitly
destructive `go run ./cmd/dev reset -confirm-delete` before generating a new one.
Keycloak-specific lab checks reject a local fixture before contacting an IdP.

An optional separate `breakGlass` policy restricts designated emergency local
owners. Its `allowedPermissions` allowlist always applies; `consoleOnly: true`
additionally requires an actual loopback peer, not a forwarding header.
`maxSessionLifetime` is a required protobuf duration greater than zero and at most
`"3600s"`; `requireIncidentReason` must be `true`. Permissions are `fleet.read`,
`enrollment.manage`, `device.revoke`, `audit.read`, `execution_trust.manage`,
`profiles.manage`, `services.assign` and `accounts.manage`. The policy does not
automatically designate an account or merge emergency grants with external grants.

Changing the primary source does not rebind the initial owner. Startup rejects an
initialized deployment with `owner_authentication_mode_mismatch` when local mode's
initial owner is external, or when external mode has neither an owner bound to its
configured issuer nor an enabled, enrolled, designated local break-glass owner with
a configured policy. Restore the previous configuration on rejection; bootstrap
does not reclaim an initialized deployment. There is no implicit owner migration.
Before leaving local mode, use authenticated account management to designate and
fully enroll a local owner, then configure the emergency policy for the new external
mode. Include `accounts.manage` if that emergency owner must retain account-management
access, and arrange loopback access when `consoleOnly` is enabled.

External-only configurations without a break-glass policy expose no local sign-in
form or enrollment form. Policy denials (including non-loopback emergency requests)
do not spend the password-failure allowance. Once a fifteen-minute credential lock
expires, the next incorrect password starts a fresh five-attempt window.

### Microsoft Entra ID

`authentication.entra` selects the public-cloud, tenant-specific v2 OIDC issuer.
Example authentication section (replace the UUIDs with your tenant's immutable IDs):

```json
{
  "authentication": {
    "entra": {
      "tenantId": "5026e756-92d1-4328-8cc1-5f6c9b5a51a9",
      "clientId": "cd614dd3-f636-4492-999c-5143d67f415a",
      "clientSecretFile": "entra-login-secret",
      "directoryClientId": "a2a762fd-82cb-4616-8ed4-355aaf81d695",
      "directoryClientSecretFile": "entra-directory-secret",
      "administratorGroupObjectIds": ["7cc5c60f-cdd5-483e-a692-d585144c643a"]
    }
  }
}
```

Create two separate single-tenant app registrations. The login app uses a **Web**
redirect URI exactly `${publicUrl}/auth/callback`, authorization code with S256 PKCE,
and `openid profile` scopes. Login binds the signed `tid` to `tenantId` and the
principal to issuer + `oid`; pairwise `sub`, email, UPN and token group claims never
grant authority. See Microsoft's [ID token claim reference](https://learn.microsoft.com/en-us/entra/identity-platform/id-token-claims-reference).
Store each client secret in its own protected file, relative to the config file.
Neither client needs Graph write permissions.

The separate directory app uses client credentials with
`scope=https://graph.microsoft.com/.default`. Admin-consent the Microsoft Graph
**application** permission `User.Read.All`: this is the documented least privilege
for both [Get user](https://learn.microsoft.com/en-us/graph/api/user-get?view=graph-rest-1.0)
and [a user's transitive memberships](https://learn.microsoft.com/en-us/graph/api/user-list-transitivememberof?view=graph-rest-1.0).
The latter returns group IDs even when richer properties are inaccessible; Lindm
requests only IDs. Thus `GroupMember.Read.All` is not needed by this adapter's
narrower read path. Do not grant `Directory.ReadWrite.All` or
`User.EnableDisableAccount.All`; Lindm only reads `accountEnabled`. Hidden-membership
groups require additional `Member.Read.Hidden` according to Microsoft and are not
qualified by this baseline configuration.

Graph calls are `GET /v1.0/users/{oid}?$select=id,accountEnabled,displayName` and
paged `GET /v1.0/users/{oid}/transitiveMemberOf/microsoft.graph.group?$select=id&$count=true&$top=100`
with `ConsistencyLevel: eventual`. Only configured group object IDs map to admin.
Deleted/404 users are absent; disabled users carry no group grants. Reads cap each
body at 1 MiB, membership at five pages/500 objects and the complete observation at
10 seconds. Paging stays on the same user/host/path; redirects are rejected.
An HTTP 401 refreshes the app token once. HTTP 429/503 honors
[Retry-After](https://learn.microsoft.com/en-us/graph/throttling) only within the
request deadline, with at most four HTTP attempts per page; missing/invalid delays,
oversized responses, page overflow or unavailable Graph fail closed. The common
30-second refresh and 60-second maximum snapshot age are unchanged, including
already-open sessions and uncached worker authorization.

Bind the initial owner explicitly, using the **tenant-local user object ID**, not
the application ID or the login token's pairwise subject:

```sh
go run ./cmd/lindmd bootstrap-owner -config server.json \
  -tenant-id 5026e756-92d1-4328-8cc1-5f6c9b5a51a9 \
  -object-id 3949d170-3330-4f73-906c-26382d37b08c
```

This checks the configured tenant and enabled Graph user before pinning the owner;
there is no first-login owner claim. Public-cloud tenant objects are the authority;
guest home-tenant lifecycle and sovereign clouds are not qualified.

**Live R1 qualification is not complete: no live Entra tenant is available here.**
The TLS fixture unit/race tests exercise documented OIDC/Graph shapes, signed claim
correlation, pagination, concurrent token refresh and fail-closed handling, not live
Entra behavior. An operator must run and record this procedure on an isolated tenant:

1. Register the two single-tenant apps and exact redirect above, grant/admin-consent
   the directory read permission, create protected secrets and a migrated Lindm
   deployment, and run `check-config`. Create a test owner, test admin and ordinary
   security group; put the admin in that group through a nested group too.
2. Bootstrap the owner by tenant/object ID, start Lindm, and complete real browser
   login. Verify owner/admin roles, a denied unmapped user, transitive membership,
   and unchanged principal identity after display-name/UPN changes. Confirm a user
   from a different tenant cannot authenticate.
3. Keep the admin's existing session making protected fleet requests. Disable the
   admin in Entra. Record mutation time, when Graph first reports
   `accountEnabled:false`, and Lindm's denial/revocation time. Require denial within
   60 seconds of Graph visibility, without a new login. Re-enable and sign in anew.
4. Remove the admin's direct **and nested** paths to the mapped group. Record when
   this exact transitive Graph query reflects removal and require protected access
   to stop within 60 seconds. Re-add, sign in again, then delete the test user and
   confirm Graph 404 revokes access. Record propagation separately from Lindm's bound.
5. While another test admin session remains open, block Lindm's Graph egress (leave
   browser login reachable). Require denial on failed refresh and never extend a
   snapshot beyond 60 seconds. Restore egress and verify recovery requires current
   enabled/group authority. Exercise stale worker approvals across group removal/
   disable and confirm transaction-fence denial. Preserve nonsecret timestamps and
   audit evidence, then remove only the test-owned objects, apps and deployment.

### Keycloak development checks

With the real server running, `go run ./cmd/lab auth check` exercises its normal
authorization-code/S256-PKCE login against the fixed Keycloak fixture, reads a bounded
admin device page, then revokes the console session. It uses the protected fixture
owner credential and an in-memory cookie jar; no direct password grant, production
authentication bypass, exported browser cookie or password argument is involved.
Lifecycle scenarios can reuse this helper rather than exporting browser cookies.

`go run ./cmd/lab auth check-fresh -repo .` exercises uncached worker authorization
against real Keycloak and PostgreSQL using a temporary user, group and database
schema. It proves immediate observed membership/disable denials, durable authority
versions, stale transaction-fence rejection and cleanup without changing the shared
owner or application schema. The integration command runs the same check.
This verifies the actor-authorization API, not production job dispatch.

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
pins. `trust-status` reads retained versions, digests and validity without native
effects. The network process also synchronizes signed authority automatically from
the configured control plane, independently of inventory collection.
The native lifecycle options `-execution-trust` and
`-control-plane-trust -lindmd /absolute/path/to/lindmd` exercise manual admission and
isolated real-server delivery respectively; they are mutually exclusive.
`service-prepare`, `service-start` and `service-status` relay typed signed work and
read durable results. They cannot create authority or turn queue acceptance into
completion. `service-attest` returns device-signed, nonce-bound retained evidence,
not a fresh native observation or compliance claim. The
[packaged signed service lane](docs/agent-enrollment.md#running-the-packaged-signed-service-lane)
uses `-service-execution` to exercise the installed root/network boundary, replay,
expiry, revocation, crash reconciliation and authenticated history. Production
dispatch and control-plane ingestion of these attestations remain required integrations.
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

The [native service-provider lane](docs/agent-enrollment.md#running-the-native-service-provider-lane)
exercises typed systemd D-Bus reconciliation in fresh Ubuntu/Fedora guests, with
independent native state checks. This is provider qualification, not remote policy
execution or complete G3.

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
