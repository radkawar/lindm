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

### Changed

- Replace advisory fixtures with unclear redistribution grants with independently authored regression data. Keep explicitly licensed vendor data and native comparator fixtures under their own terms.
- Generate Authenticode test binaries from project-authored PE bytes and temporary test certificates.
- Capture tracked source deletions before git stages them, so a release snapshot matches the working tree.
- Distinguish maintainer-local, hash-referenced lab evidence, dirty-source records and scoped passes from clean-release qualification.
- Keep README screenshots proportional and the thumbnail row within GitHub's desktop and mobile columns.
- Make configuration-permission, Git remote and native GPG test fixtures independent of the caller's umask, Git defaults and temporary-path length.
- Preserve safe backup cancellation and timeout causes without relaying PostgreSQL diagnostics; let the real archive drill retain opt-in private native-tool diagnostics.
- Retain cold release launcher failures as lab-only encrypted diagnostics, including failures before the guest creates its custody export.
- Raise the cold guest's own memlock allowance before custody, rather than losing an inherited allowance through a new PAM session.
- Distinguish an already-closed SSH channel from a failed native artifact transfer, so encrypted cold-build diagnostics survive guest cleanup.
- Budget a 32 GiB cold-release guest overlay for two isolated full builds without changing other native lane disks or sharing compiler caches.
- Prepare checkout-owned development trust for container integration without a maintainer cache.
- Preserve first-owner audit records when testing bounded exports, and release only each acquired test lease in concurrent capacity checks.
- Add the committer's DCO sign-off to verified maintainer landings and gate commits.
- Keep an admitted main-branch CI run active when another commit arrives. Cancel superseded runs only for pull requests.
- Delete bounded advisory cleanup victims directly, without rescanning the batch for each staged record.
- Preload impact inputs in scoped, locked pages and retain impact rows through count- and byte-bounded PostgreSQL COPY batches. Keep the existing build deadline and report limits.
- Give local-authentication fixtures the test's lifetime instead of sharing one login-operation deadline across independent password-hashing flows.
- Freeze device and static-group rollout cohorts from bounded identity and membership pages. Keep full inventory evaluation for dynamic cohorts, all excluded fleet rows and the existing save deadline.
- Build temporary development signing custody outside long user-cache paths. Keep private-key cleanup and atomic native repository cache publication.
