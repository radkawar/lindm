# Changelog

## Unreleased

There is no tagged public release yet. The repository is a v0.1 preview.

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

### Changed

- Make **v0.1.0** the browser-compatible managed-upgrade baseline. Earlier shared-TLS installs are refused before upgrade changes: install fresh and re-enroll devices. Use an independent P-256/SHA-256 console CA and leaf, retain Ed25519 device transport and client/signing authorities, and sign separate per-origin console and device HTTPS roots into new bootstrap bundles. Native deployment proof now imports the actual installed console CA instead of supplying laboratory certificates.
- Reject Ed25519 console certificates, generate P-256 database leaves, name the console CA in setup and status, and warn that first-owner passkeys require a DNS console URL rather than an IP address.
- Activate the authenticated installed agent/server release series automatically, so a fresh turnkey device can receive management work without a hidden owner registration step. Preserve immutable release history, exact protocol admission and ninety-day retirement notices.
- Automatically acquire registry-backed real vendor advisories for enrolled supported inventory on fresh connected turnkey installations; preserve air-gap and explicit operator policy. Keep per-source initial scheduling independent, expose live exact-config refresh start/lease authority, and retain unknown, failed, stale and partial assessment semantics.
- Require real automatically acquired vendor publication and matching completed native managed-inventory Findings before deployment backup, after upgrade and after recovery; retain explicit partial coverage, bounded cold-feed waits and measured observation/evaluation latency without seeding feeds or findings.
- Observe the first native vendor download through its actual visible status title, rather than requiring a heading that the console does not render; compare its start with the console's canonical protobuf millisecond rounding, retaining exact source, lease and timestamp checks without a tolerance.
- Retain the actual action identity and expand its existing result before taking failed native management screenshots; never resubmit expired, failed or unknown work to obtain evidence.
- Continue bounded, read-only observation of the same managed inventory action after start authority makes its outcome temporarily unknown; only verified completion passes, and unknown never permits a retry.

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
- Budget 32 GiB source and restore server overlays for full signed turnkey bundles while preserving the installer's free-disk preflight and normal lab admission.
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
