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
Sonner's stylesheet is bundled from `globals.css`: the console CSP (`style-src 'self'`)
blocks the runtime-injected `<style>` it would otherwise add, which left toasts unstyled.
The sidebar's in-flow gap carries the sidebar surface, so the column reaches the
bottom of long pages. Full-page captures must start at scroll position zero: like any
fixed or sticky element, the sidebar and header otherwise render at the scroll offset.
Forms compose the official shadcn Select rather than native dropdowns; controlled
enum conversions, disabled state, and named uncontrolled form values are preserved.
Explanations of how a feature works are not inline page text: keep at most one short
helper sentence per control, put on-demand help in an info tooltip, and keep
destructive confirmation warnings visible. Long or multi-step forms on a detail page
open in a dialog from the page action that names them (for example, Assign profile).

Console copy is written for administrators, not for engineers. It is outcome-first,
concise, sentence case and names the operator's next action ("Assignment saved. The
device applies it at its next check-in."). Primary UI text (titles, descriptions,
labels, badges, buttons, toasts and alerts) must not use internal model terms
(for example desired state, generation or receipt) and never shows request IDs,
record UUIDs or raw enum names. The maintained banned-term list and identifier
patterns are in [`web/acceptance/copy-rules.json`](../web/acceptance/copy-rules.json);
`lab console review` enforces them. Identifiers, sequences, hashes, protocol
values and server/device clock distinctions live only in a collapsed `TechnicalDetails`
disclosure (or `RpcError` "Details for support"), with values selectable for copy.
Exceptions are values the operator must type or copy to act, such as a shown-once
secret or a confirmation ID. Title records by name: devices use the hostname and fall
back to "Unnamed device"; lifecycle states read Waiting to enroll, Enrolled, Revoked
and Recovery hold. Toasts state the outcome in a few words ("Assignment saved",
"Couldn't confirm the assignment") with a description only when it adds a next step.
Use commas, colons or periods rather than em or en dashes; ESLint checks string literals,
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

Audit reasons contain only the operator's supplied explanation, unchanged; events
without an operator reason store an empty string. Server-generated context belongs
in the audit row's structured `details` object, with the device UUID in
`target_device_id`. Assistance records `mode` (`view` or `control`) and
`duration_seconds` separately from consent, fingerprint and end-cause details.
The audit console resolves the device's current hostname server-side and links it
to the device page, falling back to "Unnamed device"; mode and duration read
"View"/"Control" and "15 min". UUIDs and other protocol context remain in Details.
Audit exports hash the exact PostgreSQL JSON bytes of the complete immutable row,
including `target_device_id` and `details`; current hostname is display context,
not historical evidence. Preserve original payload bytes when verifying the chain.

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
Enrollment starts with two goals: a single-use code for one device now, or a bounded
reusable provisioning token for automated installation. Creation forms name the
credential type, show lifetime/use defaults and keep assignment identifiers in
Advanced settings. Server-backed grant and token tabs show state, usage, expiry
and creator; revocation belongs to the selected row, not a pasted UUID form.
Show each issued secret and its matching instructions in one shown-once dialog
with explicit copy controls. Secrets and generated installer seeds remain in
component memory, never query caches, URLs or browser storage. Keep frozen issue
requests across dialog dismissal so an ambiguous response cannot become a new
issuance. Install snippets use the server's configured repository/signing trust
and exact CLI commands; missing setup stays explicit, never guessed. Downloading
an execution root does not authenticate it. Offline enrollment stays a separate
disclosure below the main enrollment methods.
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
Each administrator keeps at most 256 live search cursors (15 minutes each); a new
search evicts that administrator's oldest, so browsing never locks the list. A page
of an expired or evicted search fails as `page_expired` with a Start a new search action.
Revocation is a row action dialog retaining its existing approval/reason flow and
ambiguous request identity after dismissal. The device header has one permission-aware
Actions menu. Short actions open dialogs; storage, encryption and recovery actions
open dedicated pages with exact target review. Accepted actions link to their status
page; no control claims that acceptance proves native completion. Tabs separate
Overview, Inventory, Services, Encryption, Actions, Findings and History.
Inventory mounts on first activation (or an explicit package-search deep link),
so opening Overview does not silently start an inventory cursor. Encryption and
recovery secrets are cleared on navigation, blur and their existing expiry timers.

Inventory distinguishes missing optional observations from collection failures.
Unavailable fields are hidden by default behind **Show unavailable fields**;
installed-backend and OS observations provide context for “Not installed” and
“Not applicable on Ubuntu.” Successful zero/false values remain visible.
Permission, timeout and native-command failures remain visible as warnings with
their reported collection status. Do not invent stderr or a cause when the API
does not include it.

Advisory source freshness does not imply complete coverage. A current source with
rejected records keeps a warning badge and an expandable record ID, reason and
package list; unscoped rejections say that affected packages could not be identified.
Findings rejected by the source remain **Unknown (source record rejected)**, never
unaffected or eligible for risk acceptance. Exposure counts may be incomplete.

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
random encryption key; no destinations or schedules are preconfigured. It also
generates its own protected escrow transport and wrapping keys so managed secrets
and local-admin password custody work. Reveal approval is off so the single
console owner can reveal; add `-reveal-approval` to require a second human (create
and enroll another administrator from the console) before any reveal.

For a historical inventory presentation check, add `-host-observation FILE` with
a captured `lindm.inventory.v1.HostObservation` protobuf JSON document. The lab
rejects unknown fields, invalid observations and files above 1 MiB. It publishes
the unchanged fields and original collection timestamps for exactly one enrolled
simulator through its authenticated inventory RPC, then labels that device
`historical-inventory-replay` and prints its ID. This is a historical replay,
not a live recollection or native qualification; package data and service work
remain synthetic. Keep capture provenance alongside screenshots.

To try remote assistance hands-on with one real enrolled desktop, hold the
maintained assistance lane (`docs/verification.md`) instead of running its
scenarios. Use `make acceptance-build` and the lane's usual flags:

```sh
artifacts/bin/lab vm assistance -host local -hold \
  -manifest lab/images/ubuntu-noble-encrypted-amd64.json \
  -repo . -lab artifacts/bin/lab -lindmd artifacts/bin/lindmd \
  -cache .cache/lab/images -golden-cache .cache/lab/encrypted -require-cached-golden \
  -firmware-code /usr/share/OVMF/OVMF_CODE_4M.ms.fd \
  -firmware-vars /usr/share/OVMF/OVMF_VARS_4M.ms.fd -firmware-package ovmf \
  -firmware-version 2024.02-2ubuntu0.10 -secure-boot -evidence /new/private/dir
```

It provisions exactly like the lane: an encrypted GNOME (Wayland) clone with the
signed agent and `lindm-session.service`, the release's capture stack (the
agent's recommended GStreamer and portal packages, from the release's signed
archive; Debian's GNOME task lacks `gst-launch-1.0`), an isolated `lindmd` with
the embedded TURN relay, and GDM autologin with locking off. Held demos also
enable the platform's maintained online advisory feeds, complete an initial real
refresh and wait for the enrolled device's current evaluation before printing
"running" and the affected/accepted/unknown/clear finding counts. Missing feed
coverage or an unknown evaluation is a gate, never an empty successful result.
Before starting either a co-located or split held `lindmd`, the fixture also
publishes the current source build's signed APT/RPM agent packages for the guest
architecture at its own HTTPS `/repo` endpoints. Subsequent **Enroll** commands
therefore install from that customer's demo server; no external agent hosting is
required. `-build-repo` selects the source when development trust lives in a
different checkout. The initial assistance guest's existing signed-package
installation path is unchanged; holding the fixture makes the console install
path available for additional devices.
Feeds use a persistent revalidating HTTP cache under the configured controller
lab work directory's `advisory-cache` (the lab host's directory in co-located
mode), or the explicit `-advisory-cache DIRECTORY` override. An SSH-only host
configuration requires that override to identify the controller's persistent
cache. Unchanged vendor exports are reused after revalidation. Only `lindmd`
restarts when enabling this configuration; the fixture database and enrolled
device are retained.

The demo holds one lab slot, with no lane deadline, until Ctrl-C tears everything
down. Held runs need a native lab host (local or SSH) and never write a
qualification record. Stdout gets these nonsecret details:

- the loopback console origin; trust the development CA as for `lab console`;
- the loopback TURN port and a placeholder SSH forward line for both ports. The
  relay advertises TURN over UDP and TCP; an SSH `-L` forward carries only TCP,
  so a remote browser reaches the relay with TURN over TCP while the console
  stays relay-only;
- the `console-owner` enrollment URL and its expiry;
- the device hostname and ID;
- `vncviewer SOCKET` for the guest display. This is QEMU's VNC server on a Unix
  socket inside the VM's private 0700 directory, with no TCP listener. It needs
  TigerVNC 1.11 or later (`tigervnc-viewer`); `remote-viewer` cannot open VNC
  sockets;
- for headless hosts, `lab vm assistance-respond -evidence DIR ACTION`. It acts
  as the guest's local user through the held VM's QMP display, exactly like the
  lane. `allow` completes consent in one step: **Allow** on the notification,
  then in the desktop's own dialog **Allow Remote Interaction** when the dialog
  offers it (a Control request's RemoteDesktop dialog; a view request's
  ScreenCast dialog has no such switch; GNOME 46 and later place it first,
  GNOME 42 and 43 after the monitor list) and **Share**. `decline` and `stop`
  answer the consent and in-progress notifications, and `screenshot` only
  captures. `share`, `share-control` and `cancel` answer an already open dialog,
  for debugging. Each run saves a guest screenshot in `DIR`. `allow`, `decline`
  and `stop` click whichever notification is showing, so take a screenshot first.

The one-time enrollment secret and a fresh desktop-user password go only to
`EVIDENCE/owner-access` (mode 0400). Nothing is seeded for the device. Every
request still needs the guest user's own **Allow** and the portal dialog. To
check the path before handing it over, add `-scenarios decline` (or `control`).
The lane's `assistance-operator` browser then runs that scenario in the guest,
which leaves that real session in history. Its console and guest screenshots go
to the same directory. Add `-console-turn-tcp` to restrict that browser to TURN
over TCP, as behind an SSH forward; the scenario then also requires the selected
console relay candidate to use TCP.

When the local x86 host is full, choose the arm64 manifest explicitly. With no
`-host`, the scheduler prefers a free matching native KVM host, so the configured
Sparks are selected without waiting for local capacity. An explicit amd64 manifest
is never silently replaced by arm64 media. To force one Spark, add `-host dgx20`
or `-host dgx21`:

```sh
artifacts/bin/lab vm assistance -hold \
  -manifest lab/images/ubuntu-noble-encrypted-arm64.json \
  -repo . -lab artifacts/bin/lab -lindmd artifacts/bin/lindmd \
  -cache .cache/lab/images \
  -firmware-code /usr/share/AAVMF/AAVMF_CODE.secboot.fd \
  -firmware-vars /usr/share/AAVMF/AAVMF_VARS.ms.fd \
  -firmware-package qemu-efi-aarch64 -firmware-version 2024.02-2ubuntu0.10 \
  -secure-boot -evidence /new/private/dir
```

The scheduler stages the current source and native binaries under the configured
host work directory (`/home/r/lindm-lab` on the Sparks), reuses its verified image
and encrypted-golden caches, and keeps the remote lease through teardown.
SSH-native assistance runs default to **split topology**: PostgreSQL, `lindmd`
and its embedded TURN relay run on the controller workstation; only QEMU, QMP
and the scenario browser run on the Spark. `-colocated` explicitly restores the
isolated host-local topology; local-host runs are unchanged.

The controller uses the local source IPv4 address of the route to the SSH
alias's configured `HostName`; `-controller-address IP` overrides that selection.
The device listener and TURN bind that specific address, never a wildcard.
The guest dials out through QEMU user-network NAT, the Spark and the routed LAN
to the controller device and TURN ports. Steady-state device mTLS traffic never
uses an SSH tunnel. One-time enrollment retains the signed localhost console
origin: the guest's localhost alias reaches QEMU's host alias `10.0.2.2` and
the console's SSH reverse forward. A run-scoped leaf signed by the development
transport CA covers the controller IP and loopback names; shared development
certificates are unchanged. The bootstrap signs the real `https://IP:PORT`
device origin.

The admin listener stays on `127.0.0.1` with WebAuthn origin
`https://localhost:PORT`. The scheduler opens
`-R ADMIN:127.0.0.1:ADMIN -R TURN:CONTROLLER_IP:TURN` with
`ExitOnForwardFailure=yes`, so the Spark's operator browser reaches admin HTTPS
and TURN TCP through SSH. Split scenarios require TURN TCP and the selected
localhost candidate URL; their test driver filters ICE server URLs to that
forwarded endpoint while leaving the console's relay-only policy intact.
The assistance prerequisite step provisions private SHA-256-pinned Node 24.21.0
and package-lock-selected Playwright Chromium under `assistance-browser/`.
It changes neither system packages nor global PATH; missing browser libraries
are a prerequisite failure, not permission to install packages.

For the owner, use the printed
`ssh -L ADMIN:localhost:ADMIN -L TURN:CONTROLLER_IP:TURN <user>@<controller-host>`
placeholders with your workstation SSH alias, then open the loopback console.
Both ports must be forwarded unchanged. The printed
`ssh <user>@<lab-host> … vm assistance-respond -evidence REMOTE_DIR ACTION`
acts through the guest's QMP display and writes its screenshot on the Spark.
The controller creates the owner's enrollment only when the remote VM reports
that it is held. Owner credentials stay in the workstation's private
`EVIDENCE/owner-access` (0400), never in remote logs or streamed output.
The remote lane gets a distinct, already-enrolled owner-role account through a
single-use 0600 control-plane handle containing private lab WebAuthn credentials.
Pre-enrollment prevents FIFO admission or a cold advisory refresh from consuming
an enrollment secret's lifetime. The handle is consumed and removed remotely;
the controller disables this account at teardown. The connected lane cannot
reconfigure or own the controller fixture. A separate private, atomically
published held marker transfers the desktop password over SSH and is removed
after receipt.

On exit the lane returns screenshots and records, excluding `owner-access` and
the private held marker, then removes its owned remote run directory.
Interrupted transport or failed evidence transfer retains that exact directory
and reports its path. In `-colocated` mode the owner's access file remains on the
lab host, as before; retrieve it deliberately over SSH, never from logs.
Ctrl-C closes the worker's stdin lease and waits for remote VM teardown before
closing the controller fixture and dropping its private database. A controller
server exit cancels the remote lane. A failed SSH existence check is a transport
failure, never proof that evidence is absent or permission to delete the run.

Console UI review: `make ui-review` replaces the manual console review. It builds the embedded console
and runs `lab console review -lindmd artifacts/bin/lindmd -evidence NEW_DIR` from the
checkout under review (needs running development PostgreSQL, protected dev trust
and Playwright Chromium from `make browser-baseline`). The command opens the same
isolated console fixture with `-demo` data, issues a one-time enrollment for
`console-owner`, and drives `web/acceptance/review.mjs`, which enrolls and signs in
through the real password and WebAuthn flow (CDP virtual authenticator). Credentials
stay in a private 0600 file that is removed afterwards; the report is redacted and
screenshots mask sensitive and password fields. `lab console -demo` serves the same
seeded fleet interactively.

From a private worktree, use
`make ui-review UI_REVIEW_REPO=/path/to/development-trust-checkout`.
Only fixture trust and the running development PostgreSQL connection come from
that directory; the embedded console, browser runner and published agent packages
come from the checkout under review. The review also opens a separate real signed
APT/RPM fixture for the OS chooser, clipboard command and trust disclosure. The
unpublished fixture covers missing-artifact remedies and Settings readiness, so a
mocked repository response cannot make this review pass.

The demo seed (`loadlab.SeedDemo`) is deterministic and uses only product RPCs on
the isolated fixture: synthetic-labelled Ubuntu, Fedora, RHEL and Debian devices
that are enrolled, pending approval, compliance-stale and revoked (with approval);
encrypted, unencrypted and unknown roots, with an escrowed key; three profiles whose
assignments are compliant, drifting and failed; advisory findings from the checked-in
feed fixtures served by a fixture-owned loopback origin, with one accepted risk;
lock, refresh, escrow-rotate and a wipe awaiting approval; a completed control-mode
and a declined assistance session; a one-time code, an automatic provisioning token,
a group, rollout, secret, webhook, report schedule and audit export. Contact-stale
devices need 24 hours of silence and are not seeded; the one-time code expires
after 15 minutes and the pending wipe's action after 10. `-host-observation FILE`
replays a captured host on one demo device. The route device (`ubuntu-ws-01`) keeps
checking in while the fixture runs, so remote assistance can be requested from it;
no user answers, so requested sessions stay waiting.

The runner reads every route from `web/src/routeTree.gen.ts`. Parameterised routes use
the seeded IDs; `$kind` expands to every complex device action. A route the run cannot
render (missing seed value, redirect or route error) fails it, so new pages are
covered by adding their seed. Each tab of a page with a tab list is a separate
capture. Every route and tab is checked in light and dark at 1440x900 and 390x844,
each starting from scroll position zero:

- viewport and full-page screenshots;
- layout: no horizontal overflow, no overlapping controls or text, and on desktop the
  sidebar column spans the document;
- axe-core (exact-pinned dev dependency, WCAG 2.2 AA and best-practice rules): no
  serious or critical violations, including inside each opened dialog;
- keyboard: the skip link is the first stop and lands in main content, Tab reaches
  every focusable control with a visible focus change that nothing covers, and every
  control or menu item declaring `aria-haspopup="dialog"` opens a named dialog that
  takes focus, traps Tab and Shift+Tab when modal, closes on Escape and returns focus;
- copy: `copy-rules.json` applied to visible text, placeholders, labels and titles,
  excluding `TechnicalDetails`, `RpcError` support details and `pre`/`code`/`kbd`.

Once per theme and viewport it also checks the Control-K and Command-K palette
(open, search, Escape, focus restore) and saves device details to raise a real
toast that must be styled and on screen. Controls that open dialogs must declare
`aria-haspopup="dialog"` so the review exercises them. The review also requests a
control-mode assistance session from the device page as the signed-in owner and
reviews the live viewer in every theme and viewport: **Take control** must be
present, and while it is disabled a visible reason must be linked with
`aria-describedby`. The evidence directory holds
`report.json` (per route, theme and viewport results) and `index.html`, a contact
sheet with each route's four captures side by side. Any finding exits nonzero and
prints one line per finding. Fix findings in `web/src`; never relax a rule or exclude
an element to get a pass. The only acceptable exception is a documented upstream
library defect, recorded here with its cited reason.

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

`CHECKSUM_MODE_DETACHED_IMAGE` is for vendors that sign the image bytes
themselves (Omarchy's `.iso.sig`). One streaming read feeds `gpgv` (data on
stdin) and the required SHA-256 pin, so the signed and pinned bytes are the same
bytes; offline cache reuse repeats both. The pinned full fingerprint and
independent provenance are mandatory as in the other signed modes. The checksum
URL names the vendor's unsigned SHA-256 sidecar, which must agree with the pin
but is never treated as authentication.

openSUSE Tumbleweed has no official ARM cloud/KVM image, so
`lab/images/opensuse-tumbleweed-20261007-aarch64.json` pins the signed
Snapshot20261007 **DVD** (manifest edition `dvd`; the openSUSE key signs the
`.sha256`) and the same installer-to-golden machinery
(`internal/vmlab/installed_image_linux.go`) builds `<image-cache>/tumbleweed-installed`
through an AutoYaST profile (`tumbleweed_installer_linux.go`). The base system comes
only from the authenticated DVD repository, so it is pinned by the ISO digest. The
DVD lacks cloud-init, which the lab needs for fresh NoCloud credentials, so the
profile adds the official online OSS tree at a lower priority (120 versus the DVD's
99), which supplies only cloud-init's closure. The lab requires that tree's
`repomd.xml`, signed by the manifest's pinned key, to name the manifest snapshot
(`cpe:/o:opensuse:opensuse:20261007`) both before and after installation. Published
snapshots only advance, so this bounds the metadata libzypp resolved; once the
tree moves on, building a new golden fails closed. Maintaining the cell means bumping
the manifest to the current snapshot DVD, while an existing golden keeps being
reused from its integrity-pinned cache.
The vendor ARM DVD catalogs its EFI FAT image with El Torito platform 0 and points a
hybrid USB MBR partition at that file, which `xorriso -boot_image any replay`
rejects. The remaster therefore re-declares the unchanged vendor FAT image as the
single UEFI El Torito entry, without the MBR, patches `EFI/BOOT/grub.cfg` both inside
that image and on the ISO, and adds `autoyast=cd:/lindm-seed/autoinst.xml textmode=1
self_update=0`. The profile must validate against the media's yast2-schema
(e.g. `update_nvram` is an untyped string, `install_recommended` is the element
name, and `halt` rather than `final_halt` powers off after a single stage), or
YaST stops on an invalid-profile dialog. YaST installs GRUB to the removable path on
aarch64. The profile names `cloud-init-config-suse` explicitly; otherwise the solver
satisfies cloud-init with MicroOS's configuration. Provisioning adds an
`sshd.service` drop-in ordering it after `systemd-user-sessions.service`: Tumbleweed
starts both in parallel, and while `/run/nologin` exists `pam_nologin` (requisite in
the sshd account stack) rejects the lab key ("Access denied … by PAM account
configuration"). A reboot probe landing in that window failed a lifecycle lane, and
the lab correctly treats authentication failure as terminal rather than retrying it.
Validation proves VERSION_ID equals the snapshot, the source marker, the Btrfs root,
zypper/rpm, sudo, the sshd ordering, `cloud-init-config-suse` and
`EFI/BOOT/bootaa64.efi` on a fresh-NVRAM first boot. Dispatch records the kernel's
SELinux state from `/sys/fs/selinux/enforce` for non-DNF guests, because Leap 16
and Tumbleweed enforce SELinux and Tumbleweed ships no `getenforce`. Only the DNF
family additionally requires `Enforcing`.

Omarchy 4.0.4 (`lab/images/omarchy-4.0.4-x86_64.json` and the
`hyprland-encrypted-lab` edition) uses the vendor's documented unattended mode
instead of a remaster (`omarchy_installer_linux.go`, registry installer
`omarchy-cidata`). The authenticated ISO is attached unmodified by its verified
descriptor, next to a FAT drive labeled `CIDATA` carrying the configurator's own
archinstall files (full-disk Btrfs layout, Limine, `lindm-lab` user, its lab SSH
key, and for the encrypted edition the `disk_encryption` block and
`user_encrypt_installation.txt`). QEMU runs with `-no-reboot`, so the vendor
dashboard's automatic reboot ends the install. Lab provisioning is then
explicit and minimal: libguestfs writes only a pinned SSH host key, a NOPASSWD
sudo rule for `lindm-lab` and the root-only source marker into the stopped root
(subvolume `@`, opened with the LUKS passphrase on stdin); one provisioning boot
with the ISO as a non-boot CD-ROM installs signed packages with `pacman
-S --needed` from the ISO's own offline repository (package signatures
required), never a partial upgrade from the rolling mirrors. The cloud golden
gets cloud-init (NoCloud only, network rendering disabled) and the registry's
device-action prerequisites, then removes the provisioning key, host keys and
sudo rule. The encrypted golden keeps its credentials and adds the serial
console and portable storage modules through the vendor's
`/etc/limine-entry-tool.d` and `/etc/mkinitcpio.conf.d` drop-ins and
`limine-update`; its single provisioning boot reaches that console because the
lab first appends it to the LUKS entries' cmdline in the unencrypted ESP
`limine.conf` (Limine hands it to the UKI stub, honoured with Secure Boot off),
which `limine-update` then regenerates. In that bootstrap boot the vendor
initramfs asks through plymouth, whose password display redraws "A password is
required to access the root volume:" for every keystroke, so the lab submits the
offline-proven passphrase once and ignores redraws. Provisioning then drops the
`plymouth` hook from the lab initramfs (`/etc/mkinitcpio.conf.d/zz-lindm-lab.conf`,
sorted after Omarchy's HOOKS file); the `encrypt` hook's console fallback prompts
through cryptsetup and reports a wrong key explicitly, which every later cold boot
relies on. Omarchy has no TPM early-boot variant (registry `Lab.TPM.Unsupported`):
the device-action lane binds a real TPM2 token and records the observed
passphrase prompt as unsupported.

The additional `*-aarch64.json` Rocky 8.10/9.8/10.2, AlmaLinux 8.10/9.8/10.2 and
openSUSE Leap 16.0 manifests independently pin official native cloud-image bytes,
signed checksum metadata and vendor trust anchors. They are not architecture
aliases for the x86_64 images. Run acquisition and offline verification before
native ARM KVM qualification with the execution host's pinned AAVMF firmware.
Neither manifest presence nor a passing x86_64 lane proves the ARM cell.
Cloud-image overlays get at least 10 GiB of virtual disk (larger bases keep their
size), as vendor images expect to be resized before first boot; Leap 16.0's
1.5 GiB Minimal-VM disk otherwise cannot hold one agent RPM.

Native inspection independently observes per-interface default-route membership
through iproute2's netlink JSON (IPv4 main table, IPv6 all tables), rather than
reusing the agent's proc-table parser. Active-session truth uses `loginctl`
properties independently of the agent's `busctl` decoder; on systemd before v240
(EL8) the agent reads busctl's text format after `busctl --version`, and both the
agent and the oracle use legacy `lsblk` columns before util-linux 2.37, each only
after the modern native command failed. Missing optional
properties retain unavailable status; neither oracle chooses a preferred interface
or infers session activity from session counts. The control-plane publication
comparison uses the inspection host rule, including Arch's honest `UNAVAILABLE`
OS version, and an inventory wait cut off by its own deadline reports the last
observed mismatch rather than the interrupted query.

Native equality is not health: matching permission, timeout, malformed-output,
capacity or command failures fail inspection. Only exact `UNAVAILABLE` fields in
`internal/vmlab/inventory_unavailable_linux.go` may pass, with an explicit distro,
documented reason and applicable native capability guards. Backend detection must
succeed even when the backend is absent. Missing LUKS metadata on LUKS media and
missing Fedora DNF5 repository observations are failures, not not-applicable
capabilities. `CheckInventoryHealth` applies the same policy to fresh host and
package evidence and also rejects omitted current inventory categories; it does
not replace independent native value comparisons.
Session seats additionally admit `NOT_APPLICABLE` only when that same session's
successful native Class/Type/Remote evidence proves a manager/background, remote
or tty context. This is not a global field exemption; local graphical missing
seats and missing or failed contextual evidence remain failures.

`lab vm inspect` executes its fixed uploaded `lindm-agent inspect` with `sudo -n`
and an empty, fixed environment. Full native inventory requires the root privilege
used by the production executor for DMI/sysfs serials and block metadata; running
this lane as the SSH user would measure expected permission denials instead.
Standalone agent `inspect` still retains the caller's privilege. This laboratory
invocation does not grant new privilege to the unprivileged production network
process or weaken the strict per-field health checks.

Before its first native sample, inspection waits on
`systemctl is-system-running --wait` and, when installed, `nm-online -s -q
--timeout=30`. Commands and their output are bounded; the complete readiness
operation has a one-minute deadline. Systemd `running` or `degraded` is a settled
startup state—`degraded` does not certify service health. systemd before v240
(EL8's 239) accepts `--wait` but ignores it for `is-system-running` and answers
`starting` at once. Only after such a transient answer, and only when
`systemctl --version` reports a release below 240, the gate polls once per second
within the same deadline. A newer manager answering `starting` stays unsettled.
The record retains
system state, NetworkManager startup completion or native binary absence, and
start/completion timestamps in `NativeReadiness`. SSH and cloud-init completion
alone did not prevent a real RHEL9.8 IPv6 startup transition. Network and all other
inventory fields still undergo unchanged independent before/agent/after
comparison; changing evidence yields no collector verdict.

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

`systemd-ukify` (host-side recovery UKI builds) is not a static pin: the baseline
derives `systemd-ukify=<installed systemd version>` so it never pulls a systemd
upgrade onto a shared host. Every pin, static or derived, must have its exact
`Version:` stanza in the configured archive before APT runs (`apt-cache show`
alone exits zero for an unknown version); a retired version stops the baseline
without package changes, and the host needs a separately scheduled systemd update.
Ubuntu installs `/boot/vmlinuz-*` root-only, so the baseline also downloads the
running kernel's `linux-image-<release>` at its installed version through the same
scoped sources, publishes its `vmlinuz` only when the bytes match dpkg's recorded
MD5 of the installed file, and stores it as `<work>/supermin/vmlinuz-<release>`
(mode 0600). Evidence records release, package version, SHA-256 and dpkg digest.
`/boot` is never read or changed.

`-arch arm64` (also `aarch64`; `amd64`/`x86_64` are equivalent) must match the
pinned image manifest. Selection prefers matching KVM hosts over TCG, then a free
configured host; `-host dgx20` overrides selection. `-accelerator kvm` explicitly
refuses foreign-architecture TCG. Capacity never changes acceleration: lanes whose
own `-accelerator` default is `kvm` (`encrypted`, `inspect-storage`,
`device-actions`, `assistance`), and architecture-defaulted lanes for an
architecture some configured host runs natively, wait for a native KVM slot
instead of moving to a foreign TCG host; only explicit `-accelerator tcg` or an
architecture with no native host selects TCG. `lab hosts` shows reachability, configured native
architectures, observed KVM access, active leases, observed QEMU processes and free
managed capacity. Old QEMU processes started without this command are visible but
cannot be retroactively leased.

A host-local flock slot is held for the entire lane through VM/fixture teardown.
Remote workers take the same locks over SSH on the target, not on the controller.
Kernel locks release after process death, QEMU helpers have parent-death killing,
and SSH stdin closure cancels the worker before its cleanup/lease release. Full
hosts queue for at most 12 hours, printing each changed wait reason; the lane's
3-hour deadline starts only at admission, so queue time never shortens a lane
(remote workers apply the same split on the target). Agents do not coordinate
by `pgrep`.

Admission also samples native `MemAvailable` and `pswpout`: available memory must
cover the configured per-guest RAM ceiling plus 8 GiB of headroom, with no
swap-out counter increase over the 100 ms admission sample. The ceiling is
conservative for lanes using less RAM. Each held slot records its admission
timestamp, PID, available/guest/headroom bytes, swap counters and sample duration.
Admissions are serialized and count still-held slots outside a reduced configured
limit, so lowering capacity does not silently ignore existing guests.

A lane takes one slot per concurrent guest (the firewall resource lane boots a
probe peer, so it needs two) and admits them all at once or not at all; the
memory guard covers the sum of its guests. Taking leases one at a time was a
hold-and-wait deadlock: two pair lanes on a three-slot host could each hold one
slot forever. Waiting lanes are served first come, first served: each holds a
flocked `waiter-<arrival>-<pid>-<guests>.lock` ticket (locked before it is
published), and a lane is admitted only if the slots left after older waiters'
demand cover its own guests, so a stream of single-guest lanes cannot starve a
pair. A ticket whose holder died has no flock and is swept. Lanes report their
current wait reason (slots held, memory, older waiters) when it changes.

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
always uses that private local authority (`-local-authority`, staged `lindmd`): with
`-control-plane-trust`, and also for manual `-execution-trust`/`-service-execution`,
whose offline-signed trust and intents use the same staged fixture execution root;
the record's `control_plane` names the server used. Successful and partial lane
records are copied to the requested new local `-record` file before exact
run-directory cleanup. The record includes host/runtime,
elapsed time, source revision and binary-diff SHA-256. Persistent image/golden caches
and slot identities are retained. A lost transport or failed evidence copy reports
the exact retained run path instead of deleting evidence or guessing at live state.

The arm64 hosts sit behind a management link that can drop briefly: on
2026-10-11 dgx20 stopped answering SSH for several minutes without rebooting
(uptime and guests intact), and lanes starting then failed at transport. Remote
lanes should retry SSH **connection setup** (TCP connect, authentication, host-key
check) with bounded exponential backoff, a small attempt cap and the lane's own
deadline. Never retry an operation once the remote command may have started:
staging copies, guest commands, registration, package or resource effects and
cleanup are mutations, and a lost session there is reported with the retained run
path, as above, not replayed. Interrupting the local controller of a remote lane
kills the remote worker without guest cleanup; for registered RHEL lanes that
leaves a hosted consumer that `lab images redhat cleanup` must delete.

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
`lab/images/fedora-44-encrypted-x86_64.json`, `rhel-{9.8,10.2}-encrypted-x86_64.json`,
`ubuntu-jammy-encrypted-amd64.json`,
`debian-{12,13}-amd64.json` netinst, or the Rocky/AlmaLinux 9.8/10.2
`*-encrypted-x86_64.json` DVDs). Admission is the release's platform
`Encryption` gate; the recipe is its registry `Lab` row. `-installer-log NEW_FILE`
keeps a bounded private (0600) copy of the installer serial console for
diagnosis; it can echo lab configuration and is never evidence. Ubuntu
late commands and Debian late scripts send stderr (never credential payloads)
to that console, and a failed autoinstall dumps the installer journal tail
there. The golden installer deadline is 90 minutes: Debian netinst fetches its
whole desktop task from the signed archive during installation. Image downloads
get a size-bounded deadline (2 MiB/s floor, at least 30 minutes) and continue an
interrupted body with an exact HTTP Range request (at most eight times, only
when the first response declared the length and the server answers with the
matching `Content-Range`); the whole image is still digest-verified. Supply `-firmware-code`,
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
Remote `lab host-exec` sets them from the baseline's staged copy of the running
kernel when it exists and neither is already set; a copy for another kernel
release is never selected.
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
It cannot inject arbitrary kernel arguments. The recovery image's `/init` is the
static `lindm-agent` itself; there is no BusyBox, shell, DHCP script or second
agent copy, so the same image recipe works on distributions without BusyBox.
The archive carries only two static character nodes, `/dev/console` (5:1, 0600)
and `/dev/null` (1:3, 0666), so the Go runtime has standard streams before PID 1
mounts devtmpfs and rebinds them to the kernel console; precise init failures
therefore reach the console before forced poweroff. Image-specific init inputs
are the signed `etc/lindm/recovery-init` parameters (boot mode, ESP volume
serial, optional off-target ext4 UUID), and `etc/lindm/modules.load` lists module
files loaded unchanged with `finit_module(2)` in dependency order; no
`modules.dep`, `modprobe` or decompressor is archived. Image and stager
Authenticode checks use the in-process verifier, not `sbverify`; only host-side
`sbsign` remains a build prerequisite. Tests for this init inject the syscall
boundary and never need root.

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
directory outside the server's release-content directory for its TUF rollback checkpoint.
The deployment's verified execution bootstrap supplies the release-root anchor;
an absent catalog or readiness observation refuses approval rather than trusting
a client-supplied image size. The maintained action fixture creates its own
isolated signed repository and waits for fresh root-observed readiness before
asking for either human's approval.

For measured GRUB recovery, build the initramfs with
`lindm-recovery-build -boot-mode measured-grub` (no stub, certificate, key, ESP
UUID or serial console; `-state-uuid` required) and publish
`-target recovery/<initrd-sha256>.initrd=/path/initrd` first, then
`-target recovery/<initrd-sha256>.kernel=/path/vendor-kernel`, where the kernel is
in GRUB's measured form: `zcat` a gzip-compressed vendor `vmlinuz` first, as
the lab's `measuredVendorKernel` does. The publisher
refuses a `.kernel` descriptor whose `.initrd` is not already signed. The device
`recoveryBoot` uses `bootMode: RECOVERY_BOOT_MODE_MEASURED_GRUB`, `espDirectory:
"/boot"`, `kernelSha256` and an optional `serialConsole`; `lindm-agent
action-sandbox -install` then exposes only `/dev/tpmrm0`. The platform
registry's `Quirks.RecoveryGRUB` selects the BLS or grub.d `custom.cfg` flavor
and the `grub-editenv` path, which the executor runs in a short-lived transient
unit. In the lab, `lab vm device-actions -recovery-boot-mode measured-grub` with
`-wipe-phase recovery-sata`, `recovery-nvme` or `recovery-attestation-refusal`
runs the stock shim+GRUB fixture; the registry's `Lab.Guest.MeasuredBoot` holds
the guest package recipe.

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
-version MINOR [-edition kvm|dvd] -token-file FILE -manifest NEW_FILE [-cache DIR]`
obtains the authorized download (`kvm`, the default, is the KVM guest qcow2;
`dvd` is the self-contained Binary DVD installer ISO used by the encrypted
kickstart lane, never the network-dependent Boot ISO), verifies its
published SHA-256 and exact CDN Content-Length, and imports it into the same
digest-addressed cache used by VM lanes. The default cache is `.cache/lab/images`;
the manifest parent must already exist. The token file must be a current-user-owned
mode-0600 regular file, not a symlink. An eligible RHEL subscription (including an
activated Developer subscription) and **Download Software and Updates** permission
are required; an offline token alone does not grant download entitlement.
The command bounds a KVM transfer at 45 minutes and a Binary DVD (about 11-16 GB)
at 4 hours; the client refuses an unbounded download context.

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
accept `-redhat-token-file FILE` for RHEL. `lab vm device-actions` requires it
only for RHEL original-device recovery: the vendor cloud guest registers just
for its owned-boot package transaction and unregisters (activation key deleted)
before boot conversion. Also supply `-allow-network` explicitly:
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
`LINDM_TEST_DATABASE_URL_FILE` used by the integration lane. Browser qualification must
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
`-root` names the checkout owning the running `.cache/dev` fixture (its lock,
credentials and `LINDM_NATIVE_REPOSITORY`); `-code DIR` (default `-root`) names
the checkout whose `lindmd` is built and whose packages are tested, so a clean
worktree is qualified against the shared fixture without copying fixture secrets.
`internal/testdb.New` owns reusable isolated-schema creation/cleanup; integration
tests retain the `testdb.Open(t)` wrapper. This is schema isolation, not a separate
PostgreSQL database. The fresh-authorization proof does not qualify job dispatch,
device execution or finer commercial authorization scopes.

Private worktrees live in `<main>.worktrees/NAME` (here
`~/dev/minor/lindm.worktrees`), never in the research-clone directory. `go run
./cmd/dev worktree add NAME [-base REV]` creates one detached at `REV` (default
`HEAD`) and links the main checkout's `node_modules` only when `package.json` and
`package-lock.json` are byte-identical; otherwise it runs `npm ci --ignore-scripts`
in the worktree, because a shared install from another lockfile would test the
wrong packages. `.tools` is not shared: `add` runs `make tools`, so the worktree's own
Makefile pins the tools its hooks and gates use. `worktree list` shows HEAD, ahead/behind `main`, dirty state, newest
mtime outside `node_modules` and allocated size. `worktree prune [-older-than D]
[-dry-run] [-archive-dirty] [PATH...]` (default: every worktree under
`<main>.worktrees`) removes clean worktrees whose HEAD is an ancestor of `main`.
A dirty or diverged worktree is kept unless `-archive-dirty`, which first writes
`git diff --binary HEAD`, a tar of untracked non-ignored files, the HEAD SHA and a
bundle of commits `main` lacks to `~/.cache/lindm-worktree-archive/<name>-<ts>/`,
then removes it. Prune never touches a worktree used by a live process (any
`/proc/*/cwd`, root, executable or open file beneath it, rechecked immediately
before removal) or whose development Compose project is running, and ends with
`git worktree prune`.

`make signoff` (`go run ./cmd/dev signoff` after `dev-up`) is local CI for the
pushed HEAD, never the shared dirty tree. It refuses a HEAD that no
remote-tracking branch contains, creates a temporary clean worktree at that SHA,
runs `make check` there, runs `test-integration` with that worktree as `-code`
against the main checkout's fixture, and only then posts `gh signoff create
--commit SHA unit integration` from the main checkout and prints `gh signoff
status`. `make signoff-acceptance` runs `make acceptance` in the clean worktree
with `lab acceptance -fixture <main>` and the main checkout's image and golden
caches, writes evidence to `<main>/artifacts/acceptance-<ts>`, and posts the
`acceptance` context. The temporary worktree is removed afterwards, also on
failure or interrupt.

The pre-push hook (`make pre-push`, `go run ./cmd/dev pre-push`) reads git's
pushed refs and, for each pushed SHA without a green `signoff/unit` status, runs
`make check` in a temporary clean worktree of that SHA, so the shared dirty tree
never decides a push. Clean-worktree `make check` (pre-push and signoff) runs
golangci-lint with `--allow-parallel-runners` and a cache reserved for those
gates (`~/.cache/lindm-clean-golangci`), so concurrent interactive lint runs
neither block nor fail it.

Integration runs (`dev test-integration` and `dev signoff`) pass heavy-job
admission first and then take the exclusive host lock
`~/.cache/lindm-integration.lock`, because every run shares the one fixed-port dev
PostgreSQL. Queueing is bounded separately, at 3 hours, and prints the queued
time and the holder's record each time it changes. The run under the lock is
bounded by `-timeout` (default 40m), and larger values are rejected: no run may
hold the lock for more than 45 minutes, and a slower suite needs fixing or
sharding instead. While it holds the lock, the run prints each package result as
`[n/total] ok|FAIL pkg seconds`, with a failing package's output, and writes the
latest of these lines into the lock's holder record, which queued runs and
`dev status` show.
`dev test-integration`, `dev signoff` and `dev pre-push` run their race-enabled
suites (integration and clean-worktree `make check`) after heavy-job admission on
the local lab host. Gates do not take a lab slot or queue in the lanes' FIFO,
which would hold a signoff behind hours of lanes; they wait only for the host's
memory admission (one guest-equivalent `max_memory_mib` plus the lab headroom, no
swap-out during the sample), printing each changed reason, and then run at nice
10 with all their children, so VM lanes keep CPU priority. Suite deadlines are
not raised to absorb an oversubscribed host.

The shared main checkout changes only through `go run ./cmd/dev land -from
WORKTREE -m MSG [-paths a,b]`. It and `go run ./cmd/dev gate-commit -m MSG` hold
the exclusive flock `<main>/.git/lindm-landing.lock`, whose file names the holder
while it is waited for. `land` refuses unless the shared checkout is on `main`,
has no uncommitted change (it prints them) and contains its freshly fetched
upstream; local commits ahead of it (an unpushed `gate-commit`) are pushed with
the landing. It computes the worktree's complete change against its merge base with
`main` using a scratch index (commits, staged, unstaged and untracked non-ignored
files, renames and deletions; the worktree's own index is untouched) and applies
it atomically with `git apply`: a conflict refuses with nothing applied. It then
runs the quick gate on the touched files in the shared tree (build, golangci-lint
run for both tags and fmt on touched packages, buf when protos changed,
prettier/markdownlint on touched docs and web files, `generate-docs -check`
always, and race tests of the touched packages plus every module package whose
build or tests import them, directly or transitively), commits exactly the touched files with MSG and pushes to `main`'s
upstream without hooks, since the gate just ran. A gate, commit or push failure
restores the local branch and the checkout. Because every worktree links the
shared `node_modules`, each landing first checks it with `npm ls` and reinstalls
with `npm ci --ignore-scripts` when it drifts from `package-lock.json`; a landing
that changes `package.json` or `package-lock.json` reinstalls after applying and
before the gate, and again after a rollback. From apply until commit, rollback or
refusal, `<main>/.git/lindm-landing.current` records the landing's owner, pid,
worktree, message, files and start time; `go run ./cmd/dev status` prints it
(flagged stale if no process holds the landing lock) together with HEAD against
upstream, the landing and integration lock holders and uncommitted files, and
`worktree audit` prints it first. `gate-commit` is the post-hoc full
gate: it runs `make check` under the lock and commits any remaining change only
when green.

`go run ./cmd/dev worktree audit [PATH...]` answers whether work is stranded,
which ahead/dirty counts cannot because most work landed by copying. For every
registered worktree (and extra PATHs) it snapshots the complete change set against
the merge base with `main` (commits, staged, unstaged and untracked files) and
counts a file as landed when `main` holds the same blob, also lacks a deleted
file, or the file's change reverse-applies to `main` (checked in a scratch index).
Trees are LANDED, PARTIAL (unlanded files listed), UNLANDED, SNAPSHOT (no change),
MISSING or UNREGISTERED (separate clone or plain copy), with an owner inferred
from the directory name; the table is also written to
`~/.cache/lindm-worktree-audit/<ts>.json`. A PARTIAL/UNLANDED tree whose owner is
evidently working in it (a live process uses it, or a file outside `.git` and
`node_modules` changed within two hours) is work in progress: the JSON records
why, and the table hides it unless `-all`. The audit is the parent's periodic
job, not a per-landing step. `worktree prune` uses the same audit: a dirty or
diverged tree audited LANDED or SNAPSHOT is archived and removed without
`-archive-dirty`.

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

### Bare-machine enrollment from the console

`lab console-enrollment` holds an initially empty local-auth console with the
current source checkout's real signed native packages. Keep the development trust
fixture and the source being qualified explicit:

```sh
artifacts/bin/lab console-enrollment \
  -repo "$FIXTURE" -code "$SOURCE" -lindmd "$SOURCE/artifacts/bin/lindmd" \
  -architectures arm64 -publication-record "$PRIVATE/publication.json"
```

The printed one-time owner enrollment and all copied device commands are secrets.
Use the production console to issue a fresh device code and select the exact
target OS. `lab vm enroll-from-console` boots a verified fresh cloud image and
refuses a preinstalled agent or prior identity. It requires `-browser-config FILE`:
an owned mode-0600 Chromium owner configuration with `origin`, `username`,
`password`, `credentialPath` and a new `evidenceDirectory`. Enroll the disposable
browser owner first through the maintained
[browser runner](verification.md#customer-journey-release-acceptance), retaining
its private virtual-passkey state. After guest readiness the lane selects the
manifest's exact OS, presses **Copy install command**, captures redacted
screenshots and runs those exact clipboard bytes over private SSH stdin.
Records retain command SHA-256, not the code, and bind the capture digest to the
executed bytes. Only afterward may the lane upload its read-only observer to
require the local identity and active agent units. Before guest teardown, the
browser signs in again and confirms the exact device's server-side **Enrolled**
state, retaining a redacted screenshot. Package installation or a local identity
alone is not a pass; there is no command-file-only mode that bypasses this proof.

The `enroll-from-console` matrix cell targets Ubuntu 24.04 and Fedora 44, including
native aarch64 on a configured Spark. Use the declared pinned AAVMF arguments and
normal host admission; never substitute an amd64 guest or pre-provision CA, agent
packages or bootstrap trust into the machine under test. The copied command must
perform those steps. Fixture loopback ports can be forwarded without changing
their signed HTTPS origins. Keep browser capture inputs and command files private,
retain redacted light/dark desktop/mobile dialog screenshots separately, and link
completed native records in [verification](verification.md).

For `lab matrix run`, use `-console-browser-config-dir DIR` containing
`ubuntu-24.04-aarch64.json` and `fedora-44-aarch64.json`, plus
`-console-admin-address 127.0.0.1:PORT` and
`-console-device-address 127.0.0.1:PORT` for a loopback fixture.
The remote runner preserves those HTTPS ports with explicit IPv4-loopback
reverse forwards. It stages browser credentials privately, returns the updated
authenticator counter to its original protected file, and returns only redacted
screenshots through the evidence directory. Run lanes sharing one authenticator
sequentially; never share its mutable state between concurrent browsers.

### Lab qualification matrix

The platform × cell matrix is declarative. `lab/matrix.json` (strict protobuf JSON
`LabMatrix`, `api/lindm/lab/v1/matrix.proto`) maps each cell to its registry
capabilities, image kind and an existing `lab vm` lane with fixed arguments.
Platforms are the Tier 1/2 rows of `internal/platform`; images are the
`lab/images/*.json` manifests the registry identifies, one cell per (platform,
cell, registry architecture). Edition suffix `encrypted-lab` marks an
encrypted-installer manifest; every other manifest is a cloud/installed image.
Per-release lane inputs are derived in `cmd/lab/matrix.go`, never written per
distribution: lifecycle package formats and repositories from the row's native
package backend, `-redhat-token-file` from the row's lab entitlement, resource
`-kinds` from the row's implemented resource capabilities, and the device-action
recovery image from the same release's cloud manifest. `architectureArgs` holds
execution-host arguments every hardware-selecting lane receives for a guest
architecture (the Sparks' pinned AAVMF firmware for aarch64). A cell whose
capability the registry gates is `gated`; a cell without a maintained lane, or
whose lane has no recipe in the row's `Lab.Lanes`, is `no lane`; a release
without a pinned image for that architecture is `no image`; and a runnable cell
without a ledger entry is `not run`. None of these is a pass.

```sh
artifacts/bin/lab matrix plan [-platform ubuntu-24.04] [-cells lifecycle,dispatch]
artifacts/bin/lab matrix run -platform ubuntu-24.04 -cells lifecycle,dispatch \
  -evidence "$HOME/.cache/lindm-matrix/run-$(date -u +%Y%m%dT%H%M%SZ)" \
  -repo "$FIXTURE" -cache "$FIXTURE/.cache/lab/images"
artifacts/bin/lab matrix report
```

`FIXTURE` is the checkout that owns the running development fixture and the
verified image cache.

`run` needs `make build` (embedded console assets and the `lab` executable) and
the running development fixture in `-repo`; `-root` (default `.`) is the source
checkout whose matrix, manifests and ledger are used and whose sources lanes
build. It prepares shared inputs once in the new `-evidence` directory:
release-stamped `lindmd` and `lindm-agent` built from `-root` (native fixtures
refuse unstamped servers) and, through the in-process `lab packages` paths, a
development signer, agent versions 0.1.0 and 0.1.1 in every needed format and
architecture, the APT and pacman repositories and the rejection fixtures. Each
selected runnable cell then runs as a child
`lab vm <lane>` through the normal host admission (`-parallel`, default 4, bounds
concurrent cells; host slots still bound guests). The child's output is kept in
`<platform>/<cell>-<arch>.log` beside its record. Every finished cell appends one
entry to `lab/ledger.json` (strict protobuf JSON `MatrixLedger`): platform key,
cell, architecture, manifest id, `pass` only for a zero exit with a record,
otherwise `fail` with the record or log as evidence, the evidence SHA-256, time,
source revision (`-dirty` for local changes) and source. Writers lock the ledger
directory and replace the file atomically. An interrupted run records nothing.
Remote lanes stage source from `-repo` (see above), so keep that tree buildable
while aarch64 cells run.

`lab matrix import -platform KEY -cell CELL -architecture ARCH -evidence PATH
[-sha256 HEX] [-recorded DATE] [-scope TEXT] [-reference #ANCHOR]` adds evidence
recorded outside `run`. A readable file is hashed (and must match `-sha256`);
an unreadable one needs the documented digest and date and is stored unverified.
`lab matrix report` regenerates the verification ledger's
[Tier capability matrix](verification.md#tier-capability-matrix);
`go run ./cmd/dev generate-docs -check` fails when it is stale. Commit the
ledger and the regenerated table together.

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

Feed publication and device finding reads use database-backed feed configuration,
so an explicit refresh command can enable a new source without restarting the
serving replica. Its in-memory scheduled refresh configuration is loaded only at
startup: until a planned restart, repeat the explicit command to refresh the new
source. A device findings read evaluates the current published snapshot immediately.

`lindmd advisories-import -config FILE -feed ID -file FILE` admits cached vendor
bytes only when that feed has an out-of-band `expectedSha256` pin (protobuf JSON
base64). The raw compressed/ZIP bytes are hashed before decompression. For repository
metadata, configure `FEED_FORMAT_RPM_UPDATEINFO` and pin the referenced updateinfo
bytes; bare repomd without its companion is not importable. A byte pin does not
prove acquisition time: file imports contribute findings but cannot establish
current complete coverage, even for a complete archive. This prevents an old file
from becoming an apparently fresh clean result merely by reimporting it. Signed
offline bundles (below) are the replay-fenced path that carries acquisition time.

Offline-bundle snapshots use `advisory.Service.ImportSnapshot`: the configured
`FeedSource` must be byte-identical (deterministic protobuf) to the bundle's, the
signed `acquired_at` must not be in the future and freshness ends at
`acquired_at + maxAgeSeconds` (`advisory_snapshot_stale` otherwise). The same
parser runs; complete coverage is kept as parsed because acquisition time is
authenticated by the bundle signature, and an older acquisition never replaces a
newer publication. `feed.Client.Acquire` writes exactly the bytes `ParseStream`
accepts (OSV ZIP/JSON, updateinfo — the RPM_REPOMD companion is verified against
repomd — Debian tracker, Arch `all.json` without the dates companion, and signed
SUSE CSAF with its signer and signed time). Red Hat CSAF/VEX formats return
`feed: offline_snapshot_unsupported`.

Online Red Hat/SUSE proofs use pinned vendor OpenPGP keys retained under
`internal/advisory/feed/keys`; its provenance records the trust-bootstrap limits.
The console exposes artifact digests, signer fingerprints and signed snapshot time
separately from last successful fetch. Composite feed status SHA-256 hashes the
deterministically encoded protobuf `FeedManifest`; `expectedSha256` pins that
manifest for Red Hat archives, and raw primary bytes for other formats. Offline
individual CSAF imports still require externally authenticated operator pins and
do not claim signature provenance; paired Red Hat archive bundles are not yet
supported.

Malformed OSV records are rejected individually, never repaired or interpreted as
clean. Feed status exposes each rejected record's ID, reason and parseable package
names; a current feed with rejections is labeled “Current, N records rejected”.
Packages matching either an observed binary or source name from a rejected record
receive an unknown assessment with reason `source_record_rejected`. Valid unrelated
records remain usable. A rejection without trustworthy package scope makes coverage
partial rather than allowing a clean result. `FeedSource.maxRejectedRecords`
defaults to 1000 (0 fails on the first rejection; maximum 10000). Rejection metadata
is additionally capped at 48 KiB, with at most 64 names per record; exceeding the
metadata/count budget fails the refresh and retains the previous publication.
An invalid record discards all of its partially normalized claims before adding
conservative unknown assessments. Older serving binaries can read these unknown
assessments but need a planned upgrade to render the new rejection-status fields.

Ordinary non-ZIP input is capped at 128 MiB compressed, 512 MiB expanded and
500,000 normalized records. OSV ZIP exports are streamed to a private temporary
file (removed on success and failure), with a default 1 GiB compressed limit;
`FeedSource.maxArchiveBytes` can select 1 MiB–4 GiB. ZIP processing admits at most
250,000 entries, 4 MiB per entry, 16 GiB total expanded bytes and a 1000:1 compression
ratio. Only one source entry's normalized claims are held in memory (at most
128 MiB); production publication does not retain a whole-feed list or deduplication
map. `FeedSource.totalClaimsLimit` bounds emitted claims, including duplicates,
at 5,000,000 by default, configurable from 1 to 20,000,000.
Entries are read individually and checked for damage, with ecosystem filtering
before decoding native ranges and binary maps. Acquisition uses verified HTTPS
and verifies `expectedSha256` when configured, plus the GCS CRC32C checksum when
supplied. ZIP CRCs are corruption checks,
not vendor signatures. Only the canonical complete ecosystem export can establish
complete coverage. Ubuntu 24.04 uses
`https://osv-vulnerabilities.storage.googleapis.com/Ubuntu/all.zip`,
`FEED_FORMAT_OSV_ZIP`, distro `ubuntu`, release `24.04` and architecture `amd64`.
Bounded OSV fetches share a five-minute deadline. Streamed OSV publication is
governed by the refresh idle-progress watchdog: archive transfers report
progress every 16 MiB and use no fixed whole-request timeout, because a fixed
two-minute transfer cap failed the ~780 MB Ubuntu export on a slower link
(observed twice on dgx21, 2026-10-11).
Signed individual SUSE CSAF is capped at 32 MiB with 64 KiB proofs.
Red Hat accepts 128 MiB documents, incrementally walks JSON product metadata and
one vulnerability at a time, and verifies original-byte proofs before publication.
Acquisition stages at most one 512 MiB compressed archive in a private temporary
file, removes it on every exit, and bounds each archive to 32 GiB expanded and
250,000 entries. A private disk-backed reconciliation index is capped at 2 GiB
with an 8 MiB cache; source-wide claims are never held in a Go map. The configured
total-claims limit bounds publication independently. Only materializing callers
retain the 128 MiB/500,000-claim result cap. Eight logical requests (forty including
redirects) and parsing share one five-minute deadline. Database insertion uses
bounded COPY batches. The background evaluator polls every five seconds in
batches of 32 devices; reads serve only persisted evaluations (see
architecture: devices bind content-addressed finding sets, so only a new
(feed generation, package set) pair is matched). Expiry is rechecked at read
time independently of evaluation progress.
Findings pages are row- and byte-bounded. Failed refreshes preserve historical
evidence and expose an error without resetting freshness.

Forward migration `00011` stores advisory claims by publication generation and
exposes the canonical `advisory_records` view for the active feed revision only.
Publication COPYs at most 500 claims per batch into staging, deduplicates exact
claims in PostgreSQL, and switches the active generation only after complete
source verification and parsing. Failed or canceled staging never replaces the
previous generation. Source configuration and refresh-start fences still apply;
concurrent work cannot publish under changed authority. Previous and failed
generations are removed through bounded cleanup. The maintained refresh command
logs emitted/unique/rejected counts and publication duration; process peak RSS is
measured independently in real-feed qualification.

Migration `00013` makes generation cleanup durable and retryable. Startup,
explicit refresh and the periodic worker drain at most 5,000 rows per transaction
with a 30-second per-drain deadline; pending keys survive deadline or process loss.
New staging owns a ten-minute lease renewed with every COPY batch and before the
final switch. An expired lease cannot resume or publish a partially reclaimed
generation. Retirement is queued in the same transaction as the active-generation
switch; SQL always protects the active revision. Historical inactive generations
receive a 35-minute migration grace period covering the older 30-minute import
command, rather than being mistaken for abandoned concurrent staging immediately.

Streaming refreshes (Red Hat CSAF/VEX archives, OSV ZIP) have no size-derived
deadline. A progress watchdog aborts a source only when no complete source
document is parsed and no publication batch commits for
`progress_timeout_seconds` (default 300); received bytes are not progress. An
overall `refresh_timeout_seconds` ceiling (default 7,200) applies regardless.
The staging lease is renewed by a one-minute heartbeat throughout parsing.

Real-source RHEL qualification is explicitly opt-in:
`LINDM_TEST_DATABASE_URL_FILE=.cache/dev/migration-database-url go test -tags=integration,livefeed ./internal/advisory -run '^TestLiveRHEL9SignedArchivePublication$' -count=1 -v -timeout=2h10m`.
It acquires both real signed archives and publishes through the production service
inside an owned disposable test schema. It requires network access and a test role
with schema-creation privileges, never the demo database or an owner's session.

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

### Offline bundles (G6/P20)

`internal/offlinebundle` owns the signed bundle format, export, verification,
staging, import and the read-only `/offline/` handler; operations are in the
[security and operations runbook](security-and-operations.md#offline-bundle-operations-runbook).
`lindmctl bundle export|verify|development-key` runs on the connected station;
`lindmd bundle-import -config FILE -bundle DIR` runs on the site with the server's
own configuration, database, online TUF custody and advisory service and performs
no network request.

`releaseupdate.ExportOffline` fully refreshes the station repository from an
authenticated root (private temporary state) and writes the root chain, the
snapshot-bound targets metadata, every top-level target and the verified channel
catalogs for the requested rings. `releaseupdate.ImportOffline` holds the
repository lock, starts from the site's root (or the execution-bootstrap release
root for an empty repository), applies newer roots, verifies targets signatures,
expiry and the rollout delegation against the site's online signers, rejects a
lower targets version (`offline_targets_rollback`) or same-version different bytes,
copies targets with hash checks and commits targets plus paused 0% channel
proposals in one online-signed publication. Existing channels must stay valid
against the new targets. An identical targets version is `Unchanged`.

Migration `00017` adds `offline_bundle_imports`, the per-deployment replay ledger
(sequence, bundle ID, manifest SHA-256, signer, validity, state). Admission and
completion run under a session advisory lock for the whole import plus a
transaction lock; completion inserts the `offline_bundle.imported` audit event.
`Bundle.Open` authenticates the manifest and tree shape only; `Stage` copies into
`offline_bundles.directory/.staging-*` while hashing, and only staged bytes are
used. `repositories/` and `release/` are published with `RENAME_EXCHANGE`.
`/offline/` serves only those trees: GET/HEAD, no query, no dot or link component,
regular files only.

`lab vm airgap` qualifies one guest per run. Without `-network-container` it creates
an exact-owned Docker `--network none` holder and re-runs itself through
`sudo -n nsenter --net=/proc/PID/ns/net -- setpriv --reuid --regid --init-groups`;
sudo is used only to enter that namespace. Inside, the lane records interfaces,
`/proc/net/route`/`ipv6_route` and failed public IPv4/IPv6/DNS probes and fails
on any default route or success. The dedicated tmpfs PostgreSQL joins the holder's
namespace (`--network container:ID`), lindmd and the QEMU guest run in it, and the
restricted-slirp guest separately proves failed public DNS/TCP. The first bundle
initializes the empty site before `serve`; the guest installs only from
`/offline/repositories`, enrolls, sees the paused channel, then the lane records
an identical resubmission no-op, optional expired and older-sequence rejections, a
same-size repository byte change and an unsigned manifest edit, imports the second
bundle, waits for device findings bound to each signed acquisition time and starts
the audited rollout. The image must already be in the verified cache; the lane never
downloads inside the namespace.

```sh
artifacts/bin/lab vm airgap -manifest lab/images/ubuntu-noble-amd64.json \
  -repo . -work-dir /private/work -lindmd /private/lindmd \
  -first-bundle /private/b1 -second-bundle /private/b3 \
  -expired-bundle /private/b-expired -replay-bundle /private/b2 \
  -bundle-public-key bundle.pub -bundle-key-id ID \
  -release-public-key attestation.pub -release-key-id ID \
  -release-root tuf-root.json -release-online-keys tuf-online \
  -package-public-key package.asc -package-fingerprint FPR \
  -advisories advisories.json -record /private/airgap-ubuntu.json
```

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

The lane admits only the release/architecture pairs that `internal/platform`
registers with `LaneUpdates` (`Lab.LaneArchitectures` restricts the architecture).
It accepts the shared hardware flags and is scheduled like the other
hardware-capable lanes. aarch64 guests need pinned EFI firmware, for example
on an arm64 KVM host:

```sh
go run ./cmd/lab vm updates -host dgx20 -arch arm64 -repo . -allow-network \
  -manifest lab/images/debian-12-arm64.json \
  -firmware-code /usr/share/AAVMF/AAVMF_CODE.secboot.fd \
  -firmware-vars /usr/share/AAVMF/AAVMF_VARS.fd \
  -firmware-package qemu-efi-aarch64 -firmware-version 2024.02-2ubuntu0.10 \
  -record artifacts/updates-debian12-arm64.json
```

The update lane throttles writes on the root disk `/dev/vda`, so it refuses any
storage bus other than virtio-blk. DNF-family guests must run SELinux Enforcing.

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

Read-only update-status probes discard a closed SSH transport and
reconnect with the original host-key pin inside their existing deadlines. Native
mutations are never replayed after an ambiguous transport failure. A completed
status command may observe an unavailable executor during package replacement;
invalid status JSON, authentication and host-key failures are terminal. Deadline
errors retain the last successful update state. Reset recovery uses the common
fresh-pinned-connection, changed-boot-ID oracle, not old-socket FIN. Private failure
diagnostics independently reconnect and capture uptime/load, process/unit state,
update-helper and kernel journals; they do not reuse the failed connection.

Metadata-negative/hold observations fence on the first post-mutation guest
observation and require a newly started cycle, not merely a finish newer than an
old caller sample. Otherwise a cycle completed during intervening inventory work,
or an in-flight cycle using old metadata, can falsely attest to a later mutation.
Durable installed state after native recovery is checked separately; it does not
require another metadata cycle.
Metadata fault fixtures freeze/thaw the owned network-service cgroup rather than
repeatedly restarting that service. This keeps the native upgrade's legitimate
restart inside the unchanged product service-start budget; it neither resets nor
raises `StartLimitBurst`.

The resident `guest update-unpack` probe watches native binary writes with inotify.
It resolves systemd's actual `ControlGroup` for the root-admitted transaction unit.
After observing a nonempty temporary executable, it freezes only that exact
update-helper cgroup, waits for kernel `frozen 1`, and rechecks both the partial
regular file and a native manager in that cgroup.
A vanished/renamed file is no witness and the cgroup is thawed; other observation
errors fail visibly.
Only a verified witness leaves the helper frozen for the host's owned QMP reset.
This probe is fault injection, not read-only polling: ambiguous SSH loss never
replays it. The fixed ten-minute deadline is unchanged. It also reads protected
update status once per second; native failure or installation without a witness
terminates the lane rather than masquerading as an SSH timeout. No package
mutation is replayed and no completed installation counts as interrupted recovery.

Self-update failures carry `NativeUpdateDiagnostic`: a fixed native executable
name, failed operation phase, exit code (`-1` when no exit status exists), at most
eight final error lines of 512 bytes each, and an explicit truncation flag. Native
output is sanitized before durable helper/journal storage; URLs, credentials,
environment assignments and control/terminal escapes are withheld. Neither raw
command arguments nor process environment are appended. The copied recovery helper
and root update status retain the historical diagnostic through restart/checking.
Only successful replacement clears the retained failure.
After executor replacement, read-only root status also validates the durable helper
checkpoint and surfaces its failure before the network process reconnects. This
projection performs no recovery action or journal/high-water mutation and never
promotes a helper success marker without independent native package/payload checks.

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

### Native package resource provider

`internal/agent/packageprovider` implements the typed `package.native.v1`
resource for mutable APT and DNF5 systems. A root-provisioned approved repository
and its checked signing key are prerequisites, not authority supplied by a
profile. Immutable OSTree and Nix installations are rejected. Existing native
records with unprovable repository provenance remain explicitly unknown and
cannot be acquired by inventing a signer or copying the desired repository.

Preparation runs asynchronously in the bounded native helper, keyed by the exact
signed action and its preparation deadline. It downloads authenticated metadata
and package artifacts into protected state, computes the complete dependency
transaction, and binds its exact bytes, source revision, database revision and
native transaction receipt. Package download sizes come from authenticated APT
URI declarations or a fixed, isolated `python3-libdnf5` native resolver. The latter
only resolves goals and reads native package sizes; it cannot download or execute
transactions. Declared artifact bytes and observed staging bytes are distinct:
the observed total also includes metadata and native cache copies. Free-space
prechecks, per-file limits, bounded output and active aggregate cancellation are
bounded staging defenses, not a filesystem quota or a reservation guarantee.
The metadata bootstrap is bounded by the entire signed staging byte ceiling and
requires that ceiling plus a fixed 64 MiB free-space margin before native refresh;
metadata sizes are authenticated and observed after refresh, not represented as
predeclared artifact bytes. Exact package-size totals are checked before payload
downloads. The staging ceiling is at most 512 MiB; manifests are at most 256 KiB.
Plans expose `change_packages` derived from the complete digest-bound native
manifest and `change_pin` separately. The provider rejects disagreement with
manifest operations before verification or application, so a truly idempotent
reconcile does not request a final native-effect grant.

The executor sandbox is unchanged. The separately bounded transient helper
performs final preflight before its private one-use permit handshake consumes the
signed `beforeEffect` gate. Its APPLY phase is offline. Native distro package
maintainer scripts remain privileged code; authenticated distribution artifacts
are not a promise that scriptlets are side-effect-free. The ownership journal
records an unknown effect before authority consumption; a restart, timeout or
lost completion receipt never causes an uncertain installation to be replayed.

APT uses an isolated source/configuration and `apt-get` simulation and
download-only interfaces. The digest-bound `Inst`/`Conf` ordering preserves
predependency configuration barriers. Fixed `dpkg --unpack`, `--configure` and
owned `--remove` operations run with the documented frontend lock held and
`DPKG_FRONTEND_LOCKED=true`; each child still acquires the inner database lock.
There is no purge, autoremove, implicit downgrade or force-dependency bypass.
Dependencies are retained rather than acquiring APT automatic-removal ownership.
Dependencies with independent active ownership are refused, both at planning and
again at the final authority gate; their ownership is never silently transferred.
This is not a claim of equivalence with arbitrary APT hooks or automatic-mark
behavior. See [dpkg's native frontend contract](https://manpages.debian.org/bookworm/dpkg/dpkg.1.en.html).

DNF5 uses authenticated metadata, the native solver's exact transaction sizes,
`--store` and strict offline `replay`, without ignore/skip flags. Both metadata
and package signatures are mandatory. A repository that does not publish signed
metadata, including common default Fedora repository configurations, does not
meet that contract; qualification uses a genuinely signed repository rather than
disabling `repo_gpgcheck`. The package key must already have been provisioned into
system RPM trust. See the [DNF5 replay](https://dnf5.readthedocs.io/en/latest/commands/replay.8.html)
and [versionlock](https://dnf5.readthedocs.io/en/latest/commands/versionlock.8.html)
interfaces. DNF4 does not inherit DNF5 transaction support.
To change an existing DNF5 exact pin, PREPARE can see a read-only projection of the
candidate versionlock at the fixed existing native path. The original root-owned
file identity and candidate digest are both bound into the plan; preparation does
not mutate the host pin. Only APPLY replaces that owned pin after its final gate.

Exact native pins are persistent, owned and atomically replaced. Release binds
the original baseline and last applied dimensions, refuses external changes,
restores recorded pin bytes and permissions, and respects retain-installation.
Dependency installations are not recursively removed. Restoring an older
baseline never implicitly authorizes a downgrade. Native configured-state
readiness is not application launch or health evidence; native qualification
must independently exercise the selected application's behavior and a real
dependency-bearing transaction. Unit parser/ownership coverage does not certify
Ubuntu or Fedora VM behavior. Those native qualification checks remain required.

### Read-only root encryption compliance

`internal/agent/encryptionprovider` implements `encryption.compliance.v1` as
observation and evaluation only. It does not encrypt disks, enroll or disclose
keys, upload escrow, acquire native ownership, or restore a fabricated baseline
on release. A signed plan binds fresh observations and the signed ownership
context; unmet requirements remain noncompliant after Apply. Release reports
not applicable, not proof that the former requirements were satisfied.
Before launching its transient reader, the executor derives exact device paths
from the kernel root graph and bounded sysfs uevents without opening `/dev`.
Only the root backing node, its exact kernel-proven parent disk for GPT identity
reads, mapper control and an existing TPM resource-manager node are admitted.
No block-device class wildcard is needed. An unencrypted root
admits no devices. The helper independently recomputes topology, checks root-owned
block-node custody and pins durable identity rather than trusting that allowlist.

The action provider's read-only adapter follows the mounted root's kernel block
dependency graph, including LVM above dm-crypt. Every backing leaf must be
protected by the single identified LUKS2 mapping. An encrypted data disk is not
root encryption. Mixed, ambiguous and unsupported graphs remain unavailable.
The exact existing action target basis is preserved: WWN plus serial, or the
existing `SERIAL_GPT_LUKS` tuple when native WWN absence is established. The latter
requires a unique physical serial, exact GPT disk GUID, whole-disk and selected
container sizes, and LUKS UUID. Native block-level serial facts are used on virtio;
no WWN is fabricated. The pinned parent-disk reader checks GPT header CRC/GUID and
kernel partition ancestry. Duplicate serials, uncertain WWN reads and basis
downgrades refuse. Public observations explicitly project the basis, GUID and
disk size; remediation references reconstruct the exact existing action target.
Pinned native descriptors and bounded LUKS2 metadata are cross-checked;
human-readable lsblk tables are not parsed.
The complete root mapper table must have one crypt segment covering its whole
native size and the exact backing device; a CRYPT UUID label alone is insufficient.
The fixed [dmsetup table](https://manpages.debian.org/bookworm/dmsetup/dmsetup.8.en.html)
query selects the kernel major/minor, never requests `--showkeys`, and retains
only a digest, not table text or native key references.

Escrow requires the executor-authenticated successful rotation history and
server-signed durable receipt for the exact root target, current active slot and
recovery-key fingerprint. Local recovery configuration is never escrow proof.
The current metadata fingerprint must equal the rotation's final verified
metadata, so later header changes invalidate that proof conservatively. For a
fixture requiring both TPM and escrow, enroll TPM before the acknowledged
rotation. An unchanged token label cannot conceal a replaced native keyslot.

TPM compliance requires an active systemd-tpm2 token with a nonempty, unique PCR
selection and an actual current-TPM unlock test through cryptsetup's token plugin.
The fixed `open --test-passphrase --token-only --token-id` invocation creates no
mapping and prints no key. A stale sealed token, wrong TPM, changed PCR state,
missing plugin or missing native TPM cannot be promoted from token counts.
Typed findings reference only the existing escrow-rotation and TPM-binding
action workflows; they grant no action authority. An unencrypted root requires
separately authorized offline installation/encryption, not an invented action.

Qualification requires the installed Ubuntu/Fedora encrypted-root fixture,
independent root/data-disk identity and header oracles, real signed escrow
receipt custody, the systemd cryptsetup token plugin and a real native or VM TPM.
Exercise LVM-on-LUKS2, unrelated encrypted disks, stale receipt/slot metadata,
PCR/TPM mismatch, and read-only refusal without changing the executor sandbox.
Unit fixtures do not certify native TPM, cold boot, recovery or physical safety.

### Dedicated typed firewall zones

`internal/agent/firewallprovider` implements the typed `firewall.zone.v1` native
boundary for mutable Ubuntu and Fedora. Implementation is not a qualified platform
claim. Expressions use the maintained Google nftables library; a narrow
mdlayher/netlink object adapter supplies table/chain userdata, generation-fenced
atomic batches, and lossless expression readback that the library's object API
does not expose. There are no nft text scripts or profile-supplied native options.

Only `inet lindm_z_<zone UUID without hyphens>` tables belong to this provider.
Every chain and rule carries its exact owner binding and generation. Reconciliation
uses one generation-CAS delete/create batch after inspecting all objects; release
requires unchanged owned dimensions, including raw read-back expression digests.
Foreign sets, flowtables, unknown expressions, userdata, generation, file metadata,
or state changes block destructive work. Approved adoption is limited to a complete
prior provider-format table with matching root-custody typed persistent state. It
does not acquire firewalld, UFW, arbitrary nftables tables, or the global firewall.
An approved, provable baseline can be restored; an absent baseline restores absence.

Input, output and forward base chains have priority `10` and accept policy.
Profile accept ends only that chain: another owner's drop is still final. In
particular the existing action-owned `lindm_q_<action>` timed quarantine at priority
`-10` remains authoritative and is neither removed nor modified. Zone interface and
remote-network bindings form a union inside the root-approved interface boundary;
output uses the remote destination address, and forward uses ingress binding and
the default ingress verdict. Rules sort by priority then UUID. Selector stages
grow linearly with CIDR/port alternatives rather than their Cartesian product.
IPv4/IPv6, TCP/UDP ranges and typed ICMP selectors compile to native expressions.

The helper preserves its own management path using root-pinned TCP endpoints and
DNS servers, established replies, loopback, DHCP on approved links, IPv6 neighbor
discovery with hop-limit 255, and related ICMP errors for path-MTU discovery. These
exceptions cannot override another owner's rules or quarantine. Root provisioning
must keep enrollment endpoint addresses and approved interface identity current;
the provider does not turn a profile-controlled address into a management exception.
Independent fresh allow and deny packet receipts are required for convergence.
Missing probes remain unknown; kernel readback alone is not connectivity proof.
Every native apply arms the independent root-custody connectivity supervisor before
the final effect gate. After exact kernel readback it records the applied owned
snapshot and waits for fresh authenticated controller confirmation and external
packet proof. Only that confirmation permits COMMITTED state and ownership-ledger
success. Timeout, helper death, or reboot causes the supervisor to restore only the
exact recorded owned baseline; changed userdata, generation, or expression bytes
refuse rollback rather than overwrite another actor.

An interrupted transaction leaves its ownership ledger UNKNOWN. The next signed
plan for the same owner resolves it only from the supervisor's terminal record of
that exact transaction: ROLLED_BACK with the zone's kernel objects and persistent
file equal to the protected before-image, or COMMITTED with them equal to its
target, and only once the interrupted action is itself terminal
OUTCOME_UNKNOWN. The executor reads that record through its read-only view of
`/var`, without the record lock. Resolution records the observed state under the
unchanged owner lineage; the interrupted action stays OUTCOME_UNKNOWN and is never
retried, and a changed desired state is applied by the new action as a fresh
generation under its own start grant. A missing, reused or non-terminal guard
record, a failed inverse or any mismatch leaves the ledger UNKNOWN. An external
edit of the zone's own table (an added or a deleted rule) is a conflict:
reconciliation refuses before any authority with a signed precondition failure,
release is refused, and nothing overwrites the edit. A deleted owned rule is
recovered only by boot replay of the committed state.

Persistence is the installed fixed `lindm-firewall-restore.service` and root-owned
`/var/lib/lindm/firewall/<zone UUID>.pb`, not a claim about kernel state surviving
reboot. The service, exact enablement link, fixed executable, and state directory
must pass custody checks. A durable PENDING state precedes the kernel batch; exact
readback and connectivity-supervisor confirmation both precede COMMITTED state.
PENDING or journal UNKNOWN never causes a forward replay. The supervisor starts
before committed-state restoration and resolves interrupted owned transactions
first. Boot restoration accepts only committed typed state under unchanged root
configuration, refuses same-boot recreation, and records the new boot only after
exact replay. No command strings or serialized raw expressions are executed from
that file. SELinux creation metadata uses shared nativefile custody. Kernel and
filesystem effects are not one atomic transaction.

The ordinary executor sandbox is unchanged. Its fixed firewall helper has
CAP_NET_ADMIN/CAP_NET_RAW and AF_UNIX/AF_INET/AF_INET6/AF_NETLINK in the host network
namespace. The check compares the per-namespace `/proc/self/net/dev` and
`/proc/1/net/dev` kernel entries: `/proc/1/ns/net` is ptrace-gated, so a
capability-bounded root helper, guard or restore unit gets `EACCES` without
CAP_SYS_PTRACE, which none of them is granted. PrivateNetwork is forbidden for host
firewall effects and target-specific packet verification. The provider retains the
existing bounded plan, private snapshot, transaction and ownership admission caps;
an oversized native expansion fails before the final authority gate.

Qualification requires disposable installed Ubuntu/Fedora VMs, not access to an
owner's live host. Use separate management and data links, dual-stack probe peers,
real preexisting UFW/firewalld rules, and the actual timed quarantine action.
Exercise allow/deny and source/interface/port selection, idempotent plans, drift,
generation-CAS races, unassignment, approved baseline restoration, daemon reload,
SELinux labels, cold reboot restoration, missing unit custody, and termination
between guard arm, pending-file write, netlink acknowledgement, authenticated
confirmation, committed-file write, and guard disarm. Force missed confirmation
and restart the agent and supervisor independently; require persisted exact owned
rollback without replaying an uncertain forward batch.
Retain native JSON rule/handle/userdata evidence and independent packet captures.
The isolated kernel test exercises netlink atomicity and coexistence only; it does
not certify installed service, reboot persistence, packet reachability or a
platform matrix cell.

### Firewall connectivity guard and independent packet witnesses

`internal/agent/connectivityguard` owns one durable root-only rollback slot at
`/var/lib/lindm/connectivity-guard/firewall-guard.pb`. The separately installed
`lindm-connectivity-guard.service` runs before firewall restoration and reports
systemd readiness only after startup recovery. Helper admission requires its
live readiness lock. The default deadline is 120 seconds, with explicit root
configuration restricted to 30–300 seconds; CLOCK_BOOTTIME includes suspend.
Absent firewall configuration permits an installed supervisor to announce
readiness and monitor only an empty recovery store. Any retained record under
missing configuration is a recovery hold, not permission to discard custody.
Same-boot supervisor restart, helper death, deadline expiry, and reboot recover
uncommitted work. A same-boot worker is stopped through a PID/start-time-checked
pidfd before inverse application, preventing a rollback/forward-effect race.
SIGTERM withdraws admission and drains the exact inverse under an independent
25-second context; the unit allows 35 seconds for stopping. An already-running
inverse is not interrupted by cancellation of the supervisor's signal context.
The live readiness lock also contains the exact native root configuration, so
a helper cannot arm against a disabled or stale supervisor after reprovisioning.
The native provider recompiles only the protected exact inverse and rejects
foreign generation, expression, namespace or persistent-file changes. Failed
or uncertain recovery remains CONFLICT custody, not an automatically replayed
forward operation. CONFIRMED is not COMMITTED: the native persistent replacement
and durable guard COMMITTED receipt both precede disarm.
Before the active guard slot becomes COMMITTED/reusable, the helper must also
fsync its signed confirmation into protected per-action history. Failed
retention leaves recovery armed. This local custody write runs without holding
the guard record lock, so a stalled worker cannot block deadline recovery;
signature/binding, unchanged record and remaining deadline are checked before
the terminal transition. A read-only verifier never requires or invokes the
retention operation.

The root helper reads DeviceOrigin, transport CA, active device certificate and
session epoch through the root-authenticated executor Unix socket. The existing
purpose-restricted TLS message signer retains private identity keys in the
executor. Confirmation opens a new TLS 1.3 TCP connection without session
resumption, proxying or redirects; it does not borrow the network process's
connection. The server checks the actual TLS exporter, enrolled device,
current certificate/session and still-open granted action. Its DSSE receipt binds
action, resource reference, exact applied native generation/digest, fresh nonce,
session epoch, connection exporter and packet proofs. Root provisioning pins the
confirmation key and independent probe peer origins/keys; no profile URL is an
authority source. The long wait occurs only in the bounded native worker;
ordinary executor RPCs and heartbeats continue independently.

Packet probes support TCP SYN and UDP, IPv4/IPv6, and INPUT/OUTPUT/FORWARD.
Every experiment places an unpredictable 32-byte nonce in the actual packet and
matches exact source/destination addresses, ports, protocol, family and nonce.
A separate kernel socket-owned nft diagnostic table only sets nftrace; it never
changes a packet verdict or flushes another table. Its lifetime is tied to the
worker's netlink socket, including automatic removal on death or reboot. Trace
IDs are admitted only from that exact marker rule and correlated to actual
native hook, chain, rule handle and verdict. Owned-table handles must still
match the applied snapshot. Foreign verdicts remain evidence of effective
policy, not ownership of the foreign table. A last-priority diagnostic observation
point permits proof after releasing a table to absence without inventing an
owned rule. An ACCEPT never overrides a later foreign DROP.
The trace netlink header identifies the base-chain family, separately from the
packet family; foreign `ip`, `ip6` and `inet` tables are queried in their actual
family. This follows the kernel's
[nf_tables trace notification contract](https://kernel.googlesource.com/pub/scm/linux/kernel/git/stable/linux-stable.git/+/refs/tags/v4.14.173/net/netfilter/nf_tables_trace.c).

Dedicated external peers run the no-argument root command
`lindm-agent connectivity-probe` using `AgentConfig.connectivity_probe` in
`/etc/lindm/executor.json`. The optional `lindm-connectivity-probe.service` is not
enabled on ordinary managed devices. Its only capabilities are CAP_NET_RAW and
CAP_NET_BIND_SERVICE; lindmd and the ordinary executor gain no probe privileges.
The typed peer configuration fixes deployment, public origin, listen IP/port,
targets, TLS certificate/key files, device-CA file and Ed25519 PKCS8 proof-key
file. Credential reads reject replaceable ancestry, symlinks, hardlinks, oversized
files and group/world-readable private keys. The leaf must authenticate the
configured HTTPS origin; the proof key must match the configured peer identity.
Sixty-four listener connections and thirty-two admitted peer requests/jobs bound
resource use. Shutdown closes receive sockets and clears the owned proof-key
copy. Provision the peer control HTTPS addresses among the trusted management
dependencies so packet-deny experiments cannot cut their own control protocol.

The external `ProbeServer` authenticates enrolled clients using mTLS and permits
only its preconfigured packet endpoints, never an arbitrary scan destination.
INPUT requires a signed external transmission witness; OUTPUT requires a signed
external receive witness for allow; FORWARD requires both external peers.
External receivers also sign exact target/nonce readiness after opening the
actual native receive socket, including for denied probes. This prevents an
unavailable OUTPUT-deny peer from being mistaken for a completed independent
experiment. Readiness alone proves neither delivery nor denial.
Receivers use native post-filter raw sockets, not pre-filter packet visibility.
An allow requires actual receive evidence as well as the appropriate native
trace; deny requires an explicit kernel DROP/REJECT trace of the exact nonce
packet. Silence, a TCP timeout, an absent application listener, or a failed send
does not prove denial. Thirty-two bounded peer jobs expire within ten seconds
even when clients disappear. Root policy requires independent IPv4 and IPv6
allow/deny targets. Trace loss, unsupported kernel socket ownership, packet
rewriting, unapproved topology, or unavailable peers fails closed.

Periodic verification runs a new packet experiment under exact native
before/after custody and returns `ConnectivityVerificationEvidence`. It never
reuses or retimestamps an earlier guard receipt and does not arm a mutation
rollback. The two public probe receipts bind the complete evidence digest; the
protected helper result retains the exact observation/native-state hashes and
signed packet witnesses. Unit/TLS and isolated network-namespace tests are
authored separately from installed native qualification. No test, build,
formatter, code generation or native qualification result is claimed by this
source change. Qualification must still exercise real external routed peers,
FORWARD traffic, partitions, reboot, worker/supervisor loss, foreign changes,
and all persistence/confirmation crash boundaries on each advertised platform.

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
outside this repo under `~/dev/minor/clones` (third-party sources only; lindm
worktrees use `cmd/dev worktree`); no vendored commercial Fleet code or
unattributed documentation copying.
