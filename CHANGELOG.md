# Changelog

## [0.1.1] - Unreleased

### Changed in 0.1.1

- Check remote-assistance capture tools and GStreamer elements before asking the desktop user for consent; show the native Arch, Debian or RPM package remedy instead of failing after Allow.
- Close automatic RHEL 9 and 10 CSAF/VEX snapshots against verified vendor indexes, preserve publisher paths even when filing and advisory identity years differ, apply signed post-archive replacements and preserve conservative source expiry.
- Acquire signed RHEL replacements in a process-wide four-file window, retain deterministic normalization and honour vendor rate limits without extending source deadlines.
- Verify installed RPM header signatures and exact product-component identities before applying RHEL vendor absence; list third-party, undeclared and unusable vendor components as unchecked instead of silently clean.
- Contain rejected vendor documents to their exhaustive component scope where provable, retaining whole-source uncertainty only for unbounded errors and showing the document count and cause.
- Distinguish published incomplete vulnerability coverage from unpublished or stale source data in the console and native deployment diagnostics.
- Allow native server lifecycle proof to enroll an independently pinned managed-device image, keeping all real Findings gates and separate server/device identities; preserve partial device advisory limitations and route entitlement input only to entitled guests.
- Qualify connected x86_64 Ubuntu 26.04 servers with native PostgreSQL 18, a matching-major encrypted backup drill, signed upgrade and fresh-host restore, retaining full evaluated Findings on the original Ubuntu 24.04 managed device.
- Generate a separate server-install support table from per-release registry recipes, distinguishing lifecycle qualification from device support; admit connected x86_64 Debian 12/13, Ubuntu 22.04/26.04, RHEL 10 and Rocky Linux/AlmaLinux 9/10 qualification lanes without claiming unrun native proofs.
- Let native deployment qualification use an explicitly digest-pinned official PostgreSQL recovery client in an off-server networkless, swap-zero container for exact-major offline drills, without installing extra clients or adding third-party sources on the operator host.
- Admit PostgreSQL 16, 17 and 18 with exact backup/restore client/server major matching; prefer distribution-native supported majors, using a dedicated fingerprint-pinned PGDG APT source only for Ubuntu 22.04 and Debian 12 whose native clients lack the required authentication control.
- Derive native deployment Findings expectations only from registry feeds with maintained exports, matching the connected source configuration; keep Debian's primary OSV export without requiring its unexported secondary tracker, and retain all browser and durable evaluation checks.
- Activate Debian's maintained primary vendor OSV export automatically after real inventory, without requiring an unexported secondary tracker; invalidate derived identity eligibility and retain unknown assessments until actual publication and evaluation.
- Route explicit package-pinned UEFI firmware through native deployment, first-run setup, enrolled-device and fresh-host recovery guests, preserving x86_64 KVM admission, private NVRAM copies, server disk floors and connected/air-gap network policy.
- Budget 128 GiB source and restore server overlays for complete vendor imports, measure the post-import database size, and account for both disks in ordinary lab admission without weakening the installer's upgrade capacity gate.
- Refuse undersized fresh server filesystems before the native installation journal or authority custody, publish the measured 32 GiB sizing baseline, and show actual database/available/required upgrade bytes while retaining the existing twice-database-plus-4-GiB upgrade rule.
- Qualify connected x86_64 Debian 13 server installation with native PostgreSQL 17 through stock-browser setup, real device Findings, backup, matching-major offline drill, signed upgrade and fresh-host recovery.
- Qualify connected x86_64 Ubuntu 22.04 server installation using fingerprint-pinned PGDG PostgreSQL 16, the measured fresh-storage policy, full real managed-device Findings, encrypted backup, signed upgrade and fresh-host restore.
- Qualify connected x86_64 Debian 12 server installation using fingerprint-pinned PGDG PostgreSQL 16, full same-device vendor Findings, encrypted backup and matching-major drill, signed upgrade and independently authorized fresh-host recovery.
- Qualify connected x86_64 RHEL 10 server installation with native PostgreSQL 16 RPMs, verified enforcing SELinux confinement, full independent-device Findings, encrypted backup, signed RPM upgrade and fresh-host recovery; retain separate RHEL-device coverage evidence.
- Qualify connected x86_64 Rocky Linux 10 servers with native PostgreSQL 16, enforcing SELinux, real independent-device Findings, encrypted backup and exact-major drill, signed upgrade and fresh-host restore; retain Rocky device advisory limitations.

## [0.1.0] - 2026-10-15

### Known limitations

The server install is supported on Ubuntu 24.04, including the AWS deployment. RHEL 9 server install is a preview in this release: install, setup, enrollment and device management work; vulnerability findings for RHEL devices on a fresh install and backup/restore on a RHEL server are still being verified.

- PostgreSQL 16 is required, with matching native backup/restore clients.
- RHEL 9 server installation is connected-only; offline installation is refused before changes are made.
- Operators must build and sign their own releases. There are no official project signing keys or project-signed release bundles.

### Added

- Apache-2.0 project license, source-header checks and third-party notices in native packages and release exports.
- Contribution, private security disclosure and community conduct guides, with issue and pull request templates.
- GitHub Actions checks for lint, generated output, unit tests, container integration and the Chromium console journey.
- Public platform status and operator documentation for self-built, operator-signed releases.
- Require DCO trailers for each new commit's author and recorded coauthors in public CI.
- Weekly Dependabot version updates for Go modules, npm and GitHub Actions.
- Create the native integrations encryption key automatically, retain root-only custody through systemd credentials, and preserve the original key with encrypted backups and restores.
- Add stock-Chromium console TLS qualification and a strict-TLS browser proof for real device inventory, vendor advisory publication and findings matched to native package identities, with explicit partial-coverage evidence.
- Observe an enrolled device's authoritative console lifecycle independently from managed work in native deployment browser proof, without treating enrollment as inventory or action completion.
- Add an AWS Terraform deployment for Ubuntu 24.04 with private RDS PostgreSQL, SSM-only access, root-only external database credentials, required verified TLS and a signed Turnkey installation runbook.
- Record the complete real AWS PostgreSQL 16 lifecycle: signed install, stock-Chromium setup, actual EC2 enrollment, managed inventory and evaluated vendor findings, encrypted backup, quorum-approved fresh EC2 and RDS restore, original integration-secret decryption and new original-device inventory and findings; destroy the stack and independently confirm zero leftovers in 20 native AWS resource categories.
- Record the complete Ubuntu 24.04 native signed-install, stock-browser owner setup, clipboard enrollment, real management and Findings, encrypted backup, upgrade and fresh-host recovery proof; retain the failed fresh-RHEL source evidence separately.

### Changed

- Track Cinnamon's upstream 6.7.9 logind lock-state fix separately from Mint 22.3's unconfirmed 6.6.x locker; add a version-bound native lock-confirmation cell that retries unavailable vendor backports without treating a prerequisite gate or a newer version alone as a pass.
- Give matrix and remote-VM fixture binaries the same explicit development revision as the authenticated stock agent artifact; retain exact installed-release compatibility checks instead of relying on an unrelated checkout revision.
- Let held desktop assistance demos start when their platform explicitly lacks advisory coverage, without configuring substitute feeds or claiming vulnerability findings; supported releases still require their real exports and completed findings.
- Put the disposable assistance guest's NSS hosts-file lookup before synthetic localhost resolution, preserving the original modules and action clauses and retaining the verified QEMU-host route.
- Retain AWS native installer failure diagnostics in create-exclusive root-only custody instead of discarding the cause; keep child output out of public errors and refuse overwrites or capture into memory.
- Select RHEL 9's signed distro PostgreSQL 16 stream explicitly; refuse conflicting modules, older PostgreSQL installs and unrelated clusters without resetting or migrating them. Check PostgreSQL server and backup clients before provisioning and upgrade backup. v0.1.0 RHEL server installation is connected-only; offline installation refuses before mutation. Ubuntu air-gap behavior is unchanged.
- Make **v0.1.0** the browser-compatible managed-upgrade baseline. Earlier shared-TLS installs are refused before upgrade changes: install fresh and re-enroll devices. Use an independent P-256/SHA-256 console CA and leaf, retain Ed25519 device transport and client/signing authorities, and sign separate per-origin console and device HTTPS roots into new bootstrap bundles. Native deployment proof now imports the actual installed console CA instead of supplying laboratory certificates.
- Reject Ed25519 console certificates, generate P-256 database leaves, name the console CA in setup and status, and warn that first-owner passkeys require a DNS console URL rather than an IP address.
- Activate the authenticated installed agent/server release series automatically, so a fresh turnkey device can receive management work without a hidden owner registration step. Preserve immutable release history, exact protocol admission and ninety-day retirement notices.
- Automatically acquire registry-backed real vendor advisories for enrolled supported inventory on fresh connected turnkey installations; preserve air-gap and explicit operator policy. Keep per-source initial scheduling independent, expose live exact-config refresh start/lease authority, and retain unknown, failed, stale and partial assessment semantics.
- Require real automatically acquired vendor publication and matching completed native managed-inventory Findings before deployment backup, after upgrade and after recovery; retain explicit partial coverage, bounded cold-feed waits and measured observation/evaluation latency without seeding feeds or findings.
- Observe the first native vendor download through its actual visible status title, rather than requiring a heading that the console does not render; compare its start with the console's canonical protobuf millisecond rounding, retaining exact source, lease and timestamp checks without a tolerance.
- Retain the actual action identity and expand its existing result before taking failed native management screenshots; never resubmit expired, failed or unknown work to obtain evidence.
- Continue bounded, read-only observation of the same managed inventory action after start authority makes its outcome temporarily unknown; only verified completion passes, and unknown never permits a retry.
- Scope the post-evaluation native inventory screenshot to the actual package-list card, not the identically titled status card; preserve exact snapshot and installed-package matching checks.
- Create a new private native-lab backup output directory before invoking the unchanged root-owned-directory gate; refuse reused or symlink targets, and encrypt bounded failed backup diagnostics to the off-server lab operator.
- Serialize an advisory publication's heartbeat with its own bounded batch transaction, so a slow verified RDS COPY cannot cancel itself by waiting on its own lease row; retain lost-lease detection and the independent progress watchdog.
- Restrict the supported AWS deployment to PostgreSQL 16 with matching native backup clients and a `db.t4g.small` or larger database class; reject other engine majors and micro instances before provisioning.
- Refresh only a disconnected pre-send action review while an upgraded device reconnects; require the real Send control to become enabled, retain policy refusals, and never retry an accepted action.
- Give each native browser invocation a distinct screenshot scope, so upgrade and restore evidence cannot overwrite installed evidence; retain safe failure categories and owned source positions without exposing exception text or adding retries.
- Capture native-lab evidence from the original browser UI fetch's response clone rather than Chromium's ephemeral CDP response resource; observe only the three read-only evidence RPCs at the console origin, with no extra requests, error-body capture, retries or weaker snapshot matching.
- Compare native-lab RPC origins in the same canonical URL form as Chromium, so an explicit default HTTPS port does not discard valid evidence; other origins remain excluded.
- Retain failed native-lab restore command diagnostics only as bounded ciphertext encrypted to the off-server lab operator before clearing memory; preserve the restore refusal without plaintext logs or retries.
- Stage live restore archives in a root-only data-filesystem directory instead of exhausting the shared `/run` tmpfs; preflight disk capacity, create files exclusively without following symlinks, and remove temporary plaintext on returned success or failure.
- Keep private restore staging in a separate `/var/lib/lindmd-restore` tree, preserving service-readable operational-state permissions and excluding recovery plaintext from backup inventory.
- Observe strict-TLS readiness after native service starts before the independent exact-certificate probe; fail immediately on trust or HTTP refusals, retry no mutations, and retain failed restored-service journals only as operator-encrypted lab evidence.
- Create a missing protected `/var/backups` parent on fresh RHEL without widening existing permissions; retain root-only backup storage and refuse unsafe parents.
- Match the vendor PostgreSQL NNP setting only on verified SELinux-Enforcing RHEL, require the running service's `postgresql_t` domain before creating database authority, and retain every other sandbox directive. No custom SELinux policy module is installed.
- Retain bounded PostgreSQL journals, process identity and filesystem/audit diagnostics only as operator-encrypted native-lab evidence before teardown; preserve source-specific Ubuntu full lifecycle passes and failed RHEL boundaries without qualification shortcuts.
- Put RHEL's private PostgreSQL socket in the distro-labelled `/run/postgresql/lindm` namespace; use one platform path for the native unit, database configuration, readiness and peer SQL, without custom SELinux policy or extra sandbox exceptions.
- Retain bounded nofollow PostgreSQL collector logs and actual owned-service metadata only in encrypted lab evidence. Record SDK22's full Ubuntu native lifecycle PASS and unchanged RHEL startup FAIL, without promoting inherited journald stream labels to process-confinement evidence.
- Pin application, migration, backup and restore PostgreSQL sessions to UTC, so the unchanged ninety-day release-support constraint is consistent across daylight-saving changes without changing an operator's cluster time zone. Record SDK23's full Ubuntu lifecycle pass and RHEL's distinct release-activation failure.
- Add an explicitly scoped `lab deploy -without-findings` server-lifecycle observation that retains management, security, backup, upgrade and fresh-host recovery checks. Records and imports cannot promote it to full lifecycle or vulnerability qualification; preserve SDK24's full Ubuntu pass and RHEL partial-feed failure separately.
- Keep implicit RPM upgrade-preflight payload directories traversable by the restricted service user. Only the authenticated nonsecret extraction child uses umask 022; installer secret permissions and all checker hardening remain unchanged. Retain the separate SDK24 RHEL encrypted-backup pass and native-upgrade failure.
- Prepare the verified RPM upgrade executable with the installed service binary's SELinux context on enforcing hosts, preserving every checker sandbox directive. A one-slot RHEL control reproduced exit 203 for `var_lib_t` and success after only copying the native context; encrypted failure diagnostics now retain the bounded transient checker journal.
- Record SDK26's fresh RHEL 9.8 connected server lifecycle pass: native install, protected browser setup, enrollment, new management/inventory, encrypted backup, RPM upgrade and fresh-host recovery with the original device still managed. Findings stay explicitly excluded, full qualification stays false, and the separate partial-feed failure remains recorded.
- Record the matching SDK26 full Ubuntu 24.04 native lifecycle pass with real same-device Findings before and after upgrade and fresh-host recovery, including restored integration-secret decryption. Update measured first-evaluation latency to 6 minutes 27 seconds overall and 3 minutes 21 seconds from first refresh to durable evaluation; these are observations, not guarantees.

- Show enrollment, profile rollouts, vulnerability response, lost-device requests, remote assistance and account administration in the README, with a generated per-release support table and arm64 build list. Count scoped feature passes and retain successful subsets; unsupported subfeatures use footnotes rather than rejecting the whole feature.
- State common advisory-feed and assistance-desktop conditions once below the README support table, and identify the fresh-install package-database prerequisite for Omarchy console enrollment.
- Install the real software TPM for hosted integration tests and retain separate query-cost diagnostics for 10,000-device impact report pages and rollout saves, without changing deadlines or assertions.
- Avoid scanning all retained impact devices on every unrestricted report page; scoped grants still recheck the complete report against current device visibility before exposing rows or totals.
- Preserve existing disabled PostgreSQL cluster policies spelled `off`, `false`, `no` or `0`, while refusing enabled, empty or invalid values.
- Validate protected PostgreSQL cluster policies before installing native tools, so fresh external-database hosts do not need a manual `postgresql-common` prerequisite. Reject ambiguous directives before package changes.
- Run every pushed-main CI workflow independently so a later push cannot replace a pending verification; continue canceling obsolete pull-request runs.
- Upgrade Go and npm dependencies and pinned GitHub Actions, regenerate Connect code and bundled dependency notices, and migrate the TURN relay to v5 without enabling TCP relay allocations.
- Record the installed Playwright version in browser evidence instead of retaining a stale pre-upgrade version literal.
- Exempt only Dependabot's canonical commit author from DCO trailers; human coauthors and all other required checks remain enforced.
- Retain Go 1.26.9 and Node 24.21.0 at their latest patch releases. Hold TypeScript at 6.0.3 for the ESLint parser's supported peer range and Sigstore at its Go-1.26-compatible v1.10.11 maintenance release.
- Bound golden-schema initialization queueing by the calling test and start the unchanged migration/snapshot deadline after lock admission, so waiting packages retain their actual work budget.
- Serialize golden integration-schema migration, PostgreSQL snapshot and removal across package processes to avoid exhausting shared relation locks, without serializing normal test cases or restarting the fixture.
- Connect dashboard security findings to named, scope-filtered advisory exposure. Keep accepted risks and unknown coverage separate, link findings to patch review and maintenance policies, explain native patch-status and reboot reasons without showing raw codes as primary text, and verify time-limited risk exceptions through independent approval in the console walkthrough.
- Let the interactive demo complete its refused package-scan state after a finding's risk was accepted, instead of waiting for a finding that acceptance removed from the open population.
- Explain the first connected vulnerability-data download on the dashboard, advisory source cards and scoped device findings. Show a real publisher start and live lease without inventing percentage progress, and keep retained, failed, refresh-disabled and offline sources in their existing evidence states.
- Keep advisory coverage reasons tied to the last device evaluation. When a new source for that OS is preparing its first data, show its actual download state without claiming that it already covers every device or that the server has no source.
- Keep remote-help requests focused on consent, collapse optional session tools, show support reasons in compact session history and prevent search from stacking over task dialogs.
- Return from an assistance record directly to the device's assistance tab, preserving support context without an extra navigation step.
- Apply a confirmed assistance stop to cached session history as well as its record, so returning immediately never shows the stopped request as waiting for consent.
- Distinguish initial screen-sharing setup from an interrupted live connection, remove empty assistance guidance panels and wrap history timestamps to keep record actions visible on desktop.
- Add a clearly marked, independently authored Critical supplement alongside the unchanged real-vendor review feeds. Its two explicitly synthetic Fedora devices retain open Critical risk for the vulnerability walkthrough, which requires Critical evidence rather than falling back to High and checks the exact two-to-one affected count after an approved exception.
- Put the most severe advisories first across the full fleet summary, with matching versioned cursor pagination, so dashboard Critical review does not bury urgent work among alphabetically earlier records.
- Replace advisory fixtures with unclear redistribution grants with independently authored regression data. Keep explicitly licensed vendor data and native comparator fixtures under their own terms.
- Generate Authenticode test binaries from project-authored PE bytes and temporary test certificates.
- Capture tracked source deletions before git stages them, so a release snapshot matches the working tree.
- Distinguish maintainer-local, hash-referenced lab evidence, dirty-source records and scoped passes from clean-release qualification.
- Keep README screenshots proportional and the thumbnail row within GitHub's desktop and mobile columns.
- Make configuration-permission, Git remote and native GPG test fixtures independent of the caller's umask, Git defaults and temporary-path length.
- Preserve safe backup cancellation and timeout causes without relaying PostgreSQL diagnostics; let the real archive drill retain opt-in private native-tool diagnostics.
- Use the separately staged root-only migration credential for complete native PostgreSQL backups, require the same runtime database and schema, and retain protected migration-ledger sequence privileges.
- Retain cold release launcher failures as lab-only encrypted diagnostics, including failures before the guest creates its custody export.
- Raise the cold guest's own memlock allowance before custody, rather than losing an inherited allowance through a new PAM session.
- Distinguish an already-closed SSH channel from a failed native artifact transfer, so encrypted cold-build diagnostics survive guest cleanup.
- Budget a 32 GiB cold-release guest overlay for two isolated full builds without changing other native lane disks or sharing compiler caches.
- Restore canonical public embedded-repository and signed executable modes after private cold transport, with unchanged signed release provenance and custody permissions.
- Preserve authenticated public bundle modes inside the installer's private immutable snapshot without preserving source ownership or weakening provenance verification.
- Retain secret-safe, encrypted lab database failure classifications before owned guest cleanup, without changing installer authorization gates.
- Sign local PostgreSQL certificates with a constrained P-256/SHA-256 authority so SCRAM-PLUS succeeds without disabling TLS verification, channel binding or sealed PKI custody.
- Require database channel binding by default, reject disabled binding, and require SCRAM-PLUS for local credentials; explicit pooler `prefer` choices remain visible in startup logs and server status.
- Use runtime-only credential staging for fresh role checks and metadata restrictions; the migrator-only boundary still refuses missing migration credentials.
- Admit systemd's exact root-owned named-service credential ACLs without accepting ordinary group-readable files or relaxing persistent root-only secret custody.
- Wait for visible action acceptance and settled action-history queries in the native deployment browser proof, without accepting enrollment or an older restored action as evidence of live management.
- Prepare checkout-owned development trust for container integration without a maintainer cache.
- Preserve first-owner audit records when testing bounded exports, and release only each acquired test lease in concurrent capacity checks.
- Add the committer's DCO sign-off to verified maintainer landings and gate commits.
- Keep an admitted main-branch CI run active when another commit arrives. Cancel superseded runs only for pull requests.
- Delete bounded advisory cleanup victims directly, without rescanning the batch for each staged record.
- Preload impact inputs in scoped, locked pages and retain impact rows through count- and byte-bounded PostgreSQL COPY batches. Keep the existing build deadline and report limits.
- Give local-authentication fixtures the test's lifetime instead of sharing one login-operation deadline across independent password-hashing flows.
- Freeze device and static-group rollout cohorts from bounded identity and membership pages. Keep full inventory evaluation for dynamic cohorts, all excluded fleet rows and the existing save deadline.
- Build temporary development signing custody outside long user-cache paths. Keep private-key cleanup and atomic native repository cache publication.
- Serialize signed device-action preparation and start with the inventory owner so ordinary publication cannot claim a Refresh inventory slot before executor consumption. Recover an interrupted Refresh from its existing signed publication receipt without collecting again, uploading again or authorizing another start.
