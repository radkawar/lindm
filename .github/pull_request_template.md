# Pull request

## Intent and behavior

Describe the user need, complete behavior change and scope. Link the issue and
relevant P/L requirements if applicable.

## Compatibility and security

State affected platforms, migrations, privileges, trust/custody boundaries and
rollback limits. State unsupported environments and unresolved design decisions.
Do not post vulnerabilities here; use the private reporting action in SECURITY.md.

## Verification and evidence

List the exact commands you ran and their results. Report failures and skips.
Separate unit, PostgreSQL/OIDC integration, web-only browser and native/VM/physical
results. Link sanitized evidence. A planned command or skipped test is not a pass.

For console changes, include the required design review from AGENTS.md and
before/after light/dark, desktop/mobile evidence. Hosted Chromium CI does not
replace owner design approval or full release acceptance.

## Contribution checklist

- [ ] Each commit has a DCO `Signed-off-by` trailer (`git commit -s`).
- [ ] Source headers and upstream license notices are preserved.
- [ ] Source schemas/queries, generated output and relevant docs are updated.
- [ ] A deterministic regression test covers a bug fix, or the reason it is not practical is stated.
- [ ] Verification claims describe only commands actually exercised.
- [ ] No credentials, enrollment/recovery secrets, private device data or `.cache/dev` files are included.

Maintainers: retain `make signoff` for commit-specific local CI and the required
native/VM/physical release evidence. Contributors do not need private worktrees,
maintainer signing keys or a lab host to open a pull request.
