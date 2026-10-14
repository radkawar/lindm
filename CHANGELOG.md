# Changelog

## Unreleased

There is no tagged public release yet. The repository is a v0.1 preview.

### Added

- Apache-2.0 project license, source-header checks and third-party notices in native packages and release exports.
- Contribution, private security disclosure and community conduct guides, with issue and pull request templates.
- GitHub Actions checks for lint, generated output, unit tests, container integration and the Chromium console journey.
- Public platform status and operator documentation for self-built, operator-signed releases.

### Changed

- Replace advisory fixtures with unclear redistribution grants with independently authored regression data. Keep explicitly licensed vendor data and native comparator fixtures under their own terms.
- Generate Authenticode test binaries from project-authored PE bytes and temporary test certificates.
- Capture tracked source deletions before git stages them, so a release snapshot matches the working tree.
- Distinguish maintainer-local, hash-referenced lab evidence, dirty-source records and scoped passes from clean-release qualification.
- Keep README screenshots proportional and the thumbnail row within GitHub's desktop and mobile columns.
