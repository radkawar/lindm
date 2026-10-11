# lindm

Greenfield Linux device management: desktop-first, servers included, self-hosted,
single-tenant. The commercial launch contract is the entire P01–P21 specification
on every named distro family, including encryption escrow, lock/quarantine/wipe,
air-gap, remote assistance, all named identity providers with SCIM, and HA.
Ubuntu LTS and Fedora/RHEL are build-order priorities, not a reduced release boundary.

**Not a production-ready MDM.** The Go server and authenticated React console run
against real PostgreSQL. The root executor and unprivileged agent implement packaged
enrollment and inventory. Service-state assignments now travel from the console
through the server to installed agents and come back as device-signed results.
Admins sign in with built-in local accounts (password plus WebAuthn) or through
optional Keycloak, Entra, Okta or Google Workspace. No distro, capacity or destructive capability is
certified, and Entra/Okta/Google lack live-tenant qualification; see the
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

| Command                   | Purpose                                                                                                                                                                   |
| ------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `make bootstrap`          | Install pinned generators/linters, locked npm dependencies and repository-local Git hooks                                                                                 |
| `make generate`           | Generate protobuf Go/TypeScript contracts and sqlc queries                                                                                                                |
| `make build`              | Build the console and `artifacts/bin/{lindmd,lindm-agent,lab}`                                                                                                            |
| `make check`              | Format checks, Go/protobuf/Markdown/TypeScript lint, race tests and dependency audit                                                                                      |
| `make test-integration`   | Start/check the lab and run real PostgreSQL regressions in disposable isolated schemas                                                                                    |
| `make signoff`            | Local CI: in a clean worktree of the pushed HEAD run `check` and `test-integration` (shared dev fixture), then post `signoff/unit` and `signoff/integration` for that SHA |
| `make signoff-acceptance` | Same clean-worktree flow for the release acceptance gate, then post `signoff/acceptance`                                                                                  |
| `make dev-check`          | Check runtime database TLS and actual OIDC/directory access                                                                                                               |
| `make dev-trust`          | Create or verify development-only DSSE bootstrap/execution and separate TUF trust                                                                                         |
| `make dev-down`           | Stop this checkout's lab services while preserving credentials and volumes                                                                                                |
| `make fmt`                | Apply repository formatting                                                                                                                                               |

The lab uses `.cache/dev` with mode 0700 and secret files with mode 0600. Never commit
or copy these credentials. Development-only certificates last five years. Moved,
changed or expired fixtures fail explicitly instead of silently rotating credentials
beneath persisted data. Destructive reset is a separate, explicitly confirmed command:
see `go run ./cmd/dev help`. Fixed ports allow one running checkout at a time.

When greenfield migrations edited in place leave the shared application schema stale,
stop the shared server and run `go run ./cmd/dev recreate-database -confirm-delete`.
This verifies the running checkout-owned PostgreSQL fixture over verified TLS and
destroys **only `lindm`**, terminating its remaining connections. It recreates the
initial database permissions, explicitly migrates as `lindm_migrator`, restores
runtime migration-metadata restrictions and re-bootstraps the fixed Keycloak owner.
Local mode instead prints the one-shot `bootstrap-owner` command. Other databases
(including `lindm_authority_*` and their test schemas), cluster roles, Keycloak,
volumes, certificates and secrets are preserved. All schemas inside `lindm` are
necessarily deleted with it; coordinate shared-schema tests first. There is no
database-name override. Unlike `reset`, this does not regenerate the fixture.

### Server packages and containers

Native `lindmd` DEB/RPM packages share the signed agent build pipeline:
`go run ./cmd/lab packages build-server` (use `-repo` or a prebuilt `-lindmd`).
The embedded console is part of the server binary. The hardened runtime service
and explicitly invoked migration unit use separate dedicated accounts; install
never migrates or claims an owner. `deploy/server/` contains the digest-pinned,
non-root OCI definition and PostgreSQL/TLS single-host Compose topology.
Follow the [installation, upgrade and backup/restore runbooks](docs/security-and-operations.md#native-single-host-installation),
not the development fixture, for production configuration/key custody.

Maintained proofs: `lab vm server -manifest lab/images/ubuntu-noble-amd64.json`
and `lab server compose`, each with `-record NEW_FILE`. See
[engineering prerequisites and scope](docs/engineering.md#server-deployment-laboratory).

### Reproducible releases and agent updates

`lab release build` compares two clean builds of server/agent/CLI DEB/RPM packages
for amd64/arm64 and server/CLI OCI archives, with separately verified signatures,
dependency SBOMs and provenance. Production requires independently pinned signing
trust inventory and explicitly pinned OCI CA material; development key generation
is not production custody. See the
[release command and evidence contract](docs/engineering.md#clean-release-exports-and-custody-p20l17).

Mutable-host unattended updates are an explicit protected-config opt-in.
Unprivileged transport supplies bytes; root verifies TUF and invokes a separately
supervised native package transaction with persistent interrupted-update recovery.
Offline artifact keys remain separate from online rollout authority. Follow the
[update and compatibility runbook](docs/security-and-operations.md#7-hosted-agent-updates-and-release-compatibility)
and [native qualification lane](docs/engineering.md#native-unattended-update-verification-p20l08l17);
archive reproducibility does not certify an untested platform or transaction.

### Integrations, scheduled reports and audit archives

Set `"integrations": {"encryptionKeyFile": "/etc/lindm/integrations.key"}` to
enable delivery/report RPCs and workers. The protected file contains exactly
32 cryptographically random **raw bytes**, not hexadecimal or newline-terminated
text. All replicas need the same key. Back it up separately with the database:
losing it loses access to stored webhook credentials. Restore the same key; merely
replacing it is not credential rotation. Webhook secret rotation is an audited
console/API operation, independent of this storage-encryption root.

The `/integrations` console requires unrestricted `integrations.manage` authority
(owner/admin by default). It manages signed HTTPS webhook and TLS syslog
destinations, pause/delete, overlapping secret rotation, delivery history,
dead-letter replay, periodic inventory/compliance/findings reports and audit
exports. Mutations use request IDs and version fences. After an ambiguous response,
retry the exact request; the console retains it only while the component remains
mounted. Signing secrets are write-only, kept out of query caches and URLs, and
encrypted with AES-256-GCM at rest.

Webhooks authenticate the exact UTF-8 request body with HMAC-SHA256 over
`Lindm-Timestamp + "." + body`. `Lindm-Signature` is `v1=` followed by the
hexadecimal MAC; during an overlap window `Lindm-Signature-Previous` authenticates
the same bytes with the previous secret. Independently check the MAC in constant
time, enforce a bounded timestamp tolerance (for example five minutes), and persist
deduplication of the authenticated **body `event_id`**, scoped to this destination,
before accepting the event. Check that `Lindm-Event-ID` matches that signed value.
Retries reuse event IDs but receive a fresh timestamp/signature. Delivery-ID and
replay-count headers are informational, not covered by the MAC; do not use an
unsigned delivery header alone to reject replays. Configure receiver CA trust
explicitly where system roots are unsuitable. Trust bundles accept only certificate
PEM blocks; private-key blocks or unparsed text are rejected before persistence.

Delivery is at least once, ordered per destination/resource key, with ten bounded
attempts and exponential equal-jitter backoff capped at fifteen minutes. A
dead-letter blocks newer events on the same ordering key until authorized replay
resolves it. Disabling stops new fan-out and acquisition, not a send already in
flight. Deleting cancels outstanding work and erases stored signing credentials.
Syslog uses RFC 5424 messages over verified TLS 1.3 and RFC 6587 octet-counted
framing; its `tls://host:port` endpoint requires a pinned CA PEM. A completed write
is transport delivery, not proof that a SIEM durably indexed an event.

Reports are atomically published, with a limit of 100,000 rows and 32 MiB per
artifact; a limit failure is visible, never a silently truncated successful report.
Downloads use bounded 256 KiB chunks. Scheduled reports reauthorize the creator at
execution time. Retention deletes expired artifacts; save required archives outside
Lindm before expiration. CSV cells that could execute spreadsheet formulas are
prefixed with an apostrophe; JSON preserves source values.

For audit archives, save **both** the JSONL artifact and signed manifest. Verify
the manifest signature against an independently pinned server signing public key,
then the artifact SHA-256/byte count and every audit-chain link using the exact
decoded payload bytes and the domain-separated format in
`api/lindm/integrations/v1/reports.proto`. The manifest binds the chain UUID, prior
checkpoint and captured head. Continue with its final sequence/hash; do not treat
a bounded page as the complete head unless those checkpoints agree. Genesis is
sequence zero and a 32-byte zero hash. Retain checkpoints externally to detect
rollback or replacement of the database. Included certificates/public keys describe
the signature but do not independently establish trust. TLS signing-key rotation
requires archive operators to approve the new SPKI SHA-256 pin out of band; old
artifacts retain their original verification material. This is tamper-evidence, not
protection against a database administrator who also controls all trusted signing
keys and external checkpoints.

### Authentication modes

The serialized server config requires `authentication` with exactly one primary
source. Local-only deployments use `"authentication": {"local": {}}`; they need no
IdP credentials and never discover or contact an identity provider. Keycloak uses
`"authentication": {"keycloak": {...}}`, with `issuer`, `clientId`,
`clientSecretFile`, `directoryClientId` and `directoryClientSecretFile`.
Login and directory clients must be distinct. Role mappings belong to
`authorization.groupBindings`, for example
`{"group": "/mdm-admins", "role": "admin"}`. Keycloak mappings use exact directory
paths; Entra mappings use immutable group object IDs, never display names.
The old top-level `oidc` and provider-specific administrator-group fields are
rejected, not migrated implicitly.

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
`profiles.manage`, `resources.assign` and `accounts.manage`. The policy does not
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
      "directoryClientSecretFile": "entra-directory-secret"
    }
  },
  "authorization": {
    "groupBindings": [{ "group": "7cc5c60f-cdd5-483e-a692-d585144c643a", "role": "admin" }]
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

The maintained live qualification command uses the Azure CLI's current tenant and
signed-in identity (`az account show`), real Microsoft Graph and real Chromium
authorization-code login—never ROPC:

```sh
go build -o /private/lindmd ./cmd/lindmd
LINDM_ENTRA_CHROMIUM=/path/to/chrome go run ./cmd/lab auth check-entra \
  -repo . -lindmd /private/lindmd -record /private/new-entra-evidence.json
go run ./cmd/lab auth check-entra \
  -cleanup-prefix lindm-entra-check-FULL-UUID -record /private/new-entra-cleanup.json
```

Run only against a tenant where creating/deleting test objects is authorized.
The existing development PostgreSQL and protected trust files must be available;
the command never resets them or binds the shared `:18444`. It creates an isolated
database/server on dynamic loopback ports, two single-tenant applications with
separate secrets, their service principals, one security group and two users.
Only the directory application receives Graph application `User.Read.All`.
The login app registers exactly the isolated HTTPS `/auth/callback` URI.
The owner is bootstrapped by tenant/object ID. Chromium uses a private profile and
fixture-certificate SPKI trust; credentials and cookies stay in memory or private
run files, never evidence or command arguments.
Browser startup is checked before any tenant write. If this host's policy blocks
Chromium's sandbox, an explicitly authorized **lab-only**
`-chromium-no-sandbox` run is available; there is no automatic fallback and no
host AppArmor/sysctl change. Evidence labels it `no-sandbox lab browser`.
The browser remains unprivileged, headless, ephemeral and restricted by CDP Fetch
to the isolated origin, Microsoft sign-in/security-info and allowlisted static assets.
Its child-only umask is `077`, including browser-created profile files. This lab
exception is not a production browser-security recommendation.

The provisioning identity needs application creation/management, user creation
and enable/disable, group membership management, and authority to consent Graph
application roles. Global Administrator or Privileged Role Administrator can
grant Graph application consent; Application Administrator alone cannot grant
Microsoft Graph application permissions ([Microsoft's consent prerequisites](https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/grant-admin-consent)).
The command reports the failed operation, Graph error code and applicable
role/delegated-permission prerequisites rather than silently skipping it.
Software TOTP enrollment uses the real security-info flow and a maintained
RFC 6238 library, keeping each test user's secret in memory between logins.
Unsupported MFA, conditional access, password changes or interactive consent
produce a sanitized blocker; the command never weakens tenant policy.

Existing authenticated sessions make protected fleet reads while the command
removes the admin's group membership, then disables the admin in a separately
established session. A local CONNECT proxy finally blocks only the server's Graph
connections (including already-open tunnels) while retaining the original owner's
session. Evidence separates mutation-to-Graph propagation from visibility-to-denial,
with a 60-second enforcement bound. A negative enforcement interval means Lindm
observed the change before the independent Graph probe. No new login occurs during
a mutation scenario. Owned resources are cleaned even on failure/cancellation;
SIGKILL or network/permission failure can require the explicit full-prefix cleanup
command above. It never accepts a broad prefix. Nonsecret records include failures
and cleanup status and never overwrite an existing path.

This command qualifies the measured direct-group/disable/outage scenarios only.
TLS fixture tests are not live vendor evidence. The broader launch procedure also
requires these additional tenant cases:

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

### Okta

Select `authentication.okta` with `issuer`, `clientId`, `clientSecretFile`,
`orgUrl`, `directoryClientId`, `directoryKeyId` and
`directoryPrivateKeyFile`. The login issuer may be the org authorization server
(`https://example.okta.com`) or a custom authorization server
(`https://example.okta.com/oauth2/default`). Register a confidential OIDC web app
with Authorization Code, PKCE and the exact `https://LINDM/auth/callback` redirect.
Principals bind the verified issuer plus immutable user `sub`, never login/email.

Create a **separate API Services app**, register its RSA public JWK and keep the
matching PEM private key in an owned, mode-0600 file. Grant only
`okta.users.read okta.groups.read`; assign a read-only custom admin role/resource
set covering the required users and groups. Do not enable automatic Super Admin
assignment. Lindm uses `private_key_jwt` client credentials against
`orgUrl/oauth2/v1/token`, regardless of the login issuer. See
[Okta service-app authorization and roles](https://developer.okta.com/docs/guides/implement-oauth-for-okta-serviceapp/main/).
Map `authorization.groupBindings[].group` to immutable Okta group IDs. Only
`ACTIVE` users are enabled; suspended, deprovisioned and all other statuses deny.
The source reads `/api/v1/users/{sub}` and `/api/v1/users/{sub}/groups`;
bounded Link pagination cannot leave the configured origin/collection. Rate-limit
waiting is deadline-bound and never extends cached authority.

**No live Okta tenant evidence is available.** TLS fixtures are not certification.
The operator procedure is:

1. Create the two apps, least-privilege grants, protected credentials and an
   isolated migrated Lindm deployment. Run `lindmd check-config -config FILE`.
   Create a test owner/admin/group; bootstrap the owner with
   `lindmd bootstrap-owner -config FILE -issuer ISSUER -subject IMMUTABLE_SUB`.
2. Exercise real browser login for both org and custom issuer configurations
   separately. Confirm the signed `sub` equals the Management API user ID;
   a customized subject mapping must fail closed, not resolve by username.
   Verify an unmapped user denies and rename/recycled email does not change identity.
3. Keep the admin's existing session issuing protected requests. Remove its mapped
   group, suspend, unsuspend and then deactivate/delete the owned user, with fresh
   login only between scenarios. Record mutation time, the first corresponding
   Management API response, and Lindm denial. Require denial within 60 seconds of
   authoritative visibility, with no new login needed to revoke.
4. Exercise multiple group pages, a constrained service-app rate limit, and blocked
   Management API egress while login remains reachable. Failed/stale refresh must
   deny. Restore only current authority; old sessions/approvals must stay revoked.
   Retain nonsecret request times/audit and delete only owned objects/deployment.

### Google Workspace

Select `authentication.google` with `clientId`, `clientSecretFile`,
`serviceAccountEmail`, `privateKeyId`, `privateKeyFile`, `delegatedSubject` and
`hostedDomain`. The login issuer is `https://accounts.google.com`; configure the
exact callback in a confidential Google OIDC web app. A verified `hd` claim must
equal `hostedDomain` exactly. An email suffix or the optional login `hd` hint is
not proof. Bind the immutable signed `sub`, not primary email.

Enable the Admin SDK Directory API in the service-account project. A Workspace
super administrator must authorize that account's OAuth client ID for domain-wide
delegation with exactly
`https://www.googleapis.com/auth/admin.directory.user.readonly` and
`https://www.googleapis.com/auth/admin.directory.group.member.readonly`.
Use a delegated administrator with only the corresponding user/group read
privileges as `delegatedSubject`, not a production super administrator. Store the
service-account RSA PEM key privately; the downloaded service-account JSON is not
the Lindm config file. See
[Google domain-wide delegation](https://developers.google.com/identity/protocols/oauth2/service-account#delegatingauthority).

Map only immutable Directory API group IDs. Lindm reads
`users/{sub}` and checks each configured group with
`groups/{groupID}/hasMember/{sub}`. Suspended, archived and deleted users deny.
[The hasMember contract](https://developers.google.com/workspace/admin/directory/reference/rest/v1/members/hasMember)
includes direct and same-domain nested membership; cross-domain nested membership
is not qualified and an API error denies. It does not enumerate arbitrary groups
or request a broader group-list scope. Upstream propagation is measured separately;
quota/backoff cannot relax Lindm's 30/60-second freshness bounds.
Google documents [quota and nested-membership propagation limits](https://developers.google.com/workspace/admin/directory/v1/limits);
nested changes may take up to ten minutes upstream. Record that separately from
the local enforcement interval rather than claiming an end-to-end 60-second bound.

**No live Google Workspace tenant evidence is available.** An operator must:

1. Configure the OIDC app, DWD scopes, delegated read-only administrator, protected
   PEM and exact hosted domain in an isolated migrated deployment; run check-config.
   Bootstrap a test owner using the Google issuer and immutable numeric user ID.
2. Complete real browser login; prove a consumer account, absent/wrong `hd`, and
   unmapped user deny. Rename a test administrator and recreate its former email
   on a different user; only the original immutable ID retains its own identity.
3. Create direct and same-domain nested group paths. During an active admin session,
   remove every granting path, suspend, archive and delete test users in separate
   scenarios. Record mutation, first authoritative `users.get`/`hasMember` visibility
   and Lindm denial times; enforce the 60-second bound after API visibility.
4. Exercise quota responses, DWD withdrawal and blocked Admin SDK egress while OIDC
   remains reachable. Require fail-closed active-session/worker authorization.
   Re-enable/regrant only via current authoritative state and sign in anew; retain
   nonsecret evidence and clean up the owned users/groups/apps/deployment.

### SCIM provisioning

SCIM supplements the selected external source; it is never a primary freshness
source or an additive source of authorization groups. Configure
`authentication.scim.connectors` with a stable connector `id` and explicit
`correlations` entries (`providerId`, `issuer`, `subject`). Never
map by userName, display name or email. The accepted `externalId` must identify the
connector's configured immutable provider object; an arbitrary sender value cannot
bind a principal. Keep sender-side ID mappings under privileged configuration.
User `externalId` remains immutable; `userName eq` is case-insensitive while
`externalId eq` is exact. Limits are 128 KiB per request, 100 results per page,
startIndex at most 1,000,001, 100 PATCH operations and 1,000 same-connector User
members per Group. Nested SCIM Groups are not an authorization fallback.
PUT/PATCH/DELETE require the exact returned weak `If-Match: W/"version"` value.

An unrestricted `accounts.manage` administrator issues/rotates the connector's
dedicated bearer through `POST /auth/scim/credentials/rotate`, using the normal
session, exact Origin and CSRF header. The response exposes the credential once;
the database keeps only its hash, and rotation immediately rejects the previous
credential. Store it in the sender's secret store, not URLs, logs or browser storage.
Provision at `https://LINDM/scim/v2`; discovery exposes ServiceProviderConfig,
ResourceTypes and Schemas. Users/Groups support bounded pagination, supported
`eq` filters and conditional PATCH with `ETag`/`If-Match`. Groups remain
provisioning records, not directory grants. Accepted disable/delete atomically
revokes sessions and pending actor authority; a later OIDC claim cannot revive it.
Only the authorized connector may reactivate, and that still requires a new
authoritative directory observation before any access.

Qualify each real sender separately: configure its immutable ID mapping, issue a
dedicated credential, read discovery, create/rename users and bounded groups, then
filter by userName/externalId. Send two PATCHes with the same ETag and require only
one to commit. Test foreign-connector IDs, duplicate correlations and recycled
email rejection; disable/delete while an existing session is active; attempt login
with stale claims; reactivate and prove no grants before the original directory
allows them. Rotate the credential and require old-token denial. Keep nonsecret
SCIM status/ETag and audit evidence. Real-Postgres tests are protocol/transaction
evidence, not proof that an Okta/Entra sender has been configured successfully.
Keycloak and Google are not assumed to provide SCIM senders.

### Keycloak development checks

The dedicated broker lane is
`go run ./cmd/lab auth check-broker -repo . -lindmd artifacts/bin/lindmd`.
It requires the current maintained fixture with separate `lindm-upstream` and
`lindm-broker` realms; do not reset a fixture being used by another lab lane.
It uses an isolated database/server on an ephemeral port and an owned OIDC client
with one exact redirect, performs real SAML-to-OIDC login, and checks upstream group
removal, disable and outage during existing sessions while broker imports remain
healthy. It prints its owned prefix and bounded cleanup result. After interruption,
`lab auth check-broker -repo . -cleanup-prefix lindm-broker-check-UUID`
removes only that exact run's users/groups/clients in the dedicated realms.
There is no master-admin credential or mutation of the shared `lindm` realm.

With the real server running, `go run ./cmd/lab auth check` exercises its normal
authorization-code/S256-PKCE login against the fixed Keycloak fixture, reads a bounded
admin device page, then revokes the console session. It uses the protected fixture
owner credential and an in-memory cookie jar; no direct password grant, production
authentication bypass, exported browser cookie or password argument is involved.
Lifecycle scenarios can reuse this helper rather than exporting browser cookies.

`go run ./cmd/lab auth check-fresh -repo .` exercises uncached worker authorization
against real Keycloak and PostgreSQL using a temporary user, group and database
schema. The temporary group maps to a custom role with explicit permissions and
an exact device/label scope. The check proves preserved scoped grants, no
undeclared account/destructive permission, immediate observed membership/disable
denials, durable authority versions, stale transaction-fence rejection and cleanup
without changing the shared owner or application schema. The integration command
runs the same check. This verifies the actor-authorization API, not native device
execution.

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

For local/remote scheduling, set `LINDM_LAB_CONFIG` to `lab/hosts.example.json`,
run `lab hosts`, then target a lane with `-arch arm64` or `-host dgx20`.
The maintained `lab hosts baseline` command prepares explicitly authorized native
hosts; see [lab host configuration](docs/engineering.md#lab-host-configuration)
for pinned prerequisites, per-host slot leases and the complete ARM KVM command.

This lane requires `qemu-system-x86_64`, `qemu-img`, `cloud-localds` and accessible
`/dev/kvm`; it does not change host permissions or use host sudo. Guest networking is
restricted, SSH uses ephemeral credentials and a pinned host key, and cleanup kills
and reaps the owned VM before removing its private overlay/seed. Add
`-diagnostics EXISTING_DIRECTORY` only when needed: a cloud-init failure then saves a
0600 diagnostic that can contain sensitive guest data and must be removed by its
owner. These commands exercise native inspection, not package installation,
enrollment, desktop qualification or physical recovery.

Inventory includes explicit-status CPU/memory, disks/filesystems/encryption,
interfaces, firmware/Secure Boot, TPM, chassis/battery, session counts, public local
account fields, uptime and native application/backend observations. Flatpak scope is
system applications only; employee home directories are not traversed and session
identities are not retained. Optional `-record NEW_FILE` saves nonsensitive run evidence;
`-inventory-record NEW_FILE` additionally saves private `0600` protobuf JSON after
the comparison and cleanup succeed. The latter includes local account/network
identifiers and must be retained accordingly. Both outputs reject existing files.
See [inventory oracle and emulation options](docs/verification.md#fault-injection-and-oracle-requirements)
for TPM, Secure Boot, disk bus, encrypted extra-disk and aarch64 variants.

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

## Administrative CLI

`lindmctl` uses the existing administrator identity and authorization, not a separate
API key. Build it with `go build -o artifacts/bin/lindmctl ./cmd/lindmctl`, or run the
same commands through `go run ./cmd/lindmctl`. First login pins the exact HTTPS
origin and the supplied PEM CA contents:

```sh
lindmctl login --server https://localhost:18444 --ca .cache/dev/transport-ca.crt
lindmctl whoami
lindmctl devices list --page-size 50
lindmctl devices get --device-id DEVICE_UUID -o json
lindmctl device revoke --device-id DEVICE_UUID --reason 'retiring device'
lindmctl enrollment grant create --lifetime-seconds 600 --reason 'new workstation'
lindmctl enrollment grant revoke --grant-id GRANT_UUID --reason 'unused grant'
lindmctl profiles list
lindmctl profiles get --profile-id PROFILE_UUID
lindmctl profiles publish --profile-id PROFILE_UUID --file profile.json --reason 'initial service policy'
lindmctl profiles publish --profile-id PROFILE_UUID --expected-revision-id OLD_REVISION_UUID --file profile.json --reason 'updated service policy'
lindmctl assignments set --device-id DEVICE_UUID --profile-id PROFILE_UUID --revision-id REVISION_UUID --reason 'activate policy'
lindmctl assignments get --device-id DEVICE_UUID
lindmctl assignments clear --device-id DEVICE_UUID --expected-assignment-id ASSIGNMENT_UUID --reason 'stop management'
lindmctl audit list --page-size 50 -o json
lindmctl logout
```

Replace the uppercase UUID placeholders with actual resource IDs. `--file` accepts
strict `lindm.policy.v1.ResourceProfile` protobuf JSON, not an entire publish
request; unknown fields and schema-invalid resources are rejected. Publishing a
revision does not activate it. Existing assignments require
`--expected-assignment-id`; setting pins an exact revision and accepts
`--interval-seconds` (default 900). Clearing records ownership-safe release requests;
legacy service effects remain `baseline_unknown` and are not silently restored or
deleted. Profile reads accept `--revision-id` for a retained
revision. List commands return one bounded page with its `next_page_token`; pass
that value through `--page-token` to continue.

Output defaults to a terminal-safe field/value table. `-o json` emits the generated
response's protobuf JSON. Mutation commands accept `--request-id` for an explicit
idempotency UUID and otherwise generate one; mutations are never automatically
retried. Enrollment creation prints its one-time secret only to stdout, once, and
does not save it. Treat captured stdout as sensitive. A response with
`secret_delivery_unknown` is not a recovered secret.

Login launches `xdg-open`, listens only on an ephemeral `127.0.0.1` port, and uses
state plus S256 PKCE with a five-minute deadline. Complete normal browser sign-in
and explicitly approve the CLI request. The callback contains only a one-use code
and state; session tokens and verifiers never enter URLs. Subsequent `login` calls
reuse the pin without flags. The client refuses all HTTP redirects for credential
and RPC requests, and refuses silent origin or CA replacement.

The configuration is strict `lindm.auth.v1.CLIConfig` protobuf JSON at
`$XDG_CONFIG_HOME/lindm/config.json` (normally `~/.config/lindm/config.json`), with an
owned 0700 directory and a singly linked, owned 0600 file. Symlinked configuration
paths and unsafe ownership/modes are rejected. `--config` selects a separate private
file for another server or an intentional CA change; log out of the old
configuration first. Logout revokes the server session before clearing the saved
token and retains the origin/CA pin.

The reusable `internal/ctl.Client.Login(ctx, openBrowser)` API accepts a
context-aware browser callback for the real lab browser flow without launching a
graphical browser. It does not replace server identity verification or approval.
