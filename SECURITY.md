# Security policy

## Supported line

| Version | Security fixes |
| ------- | -------------- |
| v0.1.x  | Preview line   |
| Other   | Not supported  |

v0.1 is a preview, not a production-ready release. Report problems against the
latest v0.1 code or patch release. No other release line receives security fixes.
This policy does not promise a response deadline, support SLA or safe production
operation.

There are no official project signing keys or project-signed binary releases.
Operators build and sign their own releases and establish their own trust roots.
Development and lab signing keys are disposable fixture keys, not production trust.

## Report a vulnerability privately

Use this repository's GitHub **Security → Advisories → Report a vulnerability**
action to submit a private GitHub Security Advisory report. Sign in to GitHub to
use it. Do not file a public issue or pull request for a vulnerability. Do not paste
credentials, device identifiers, recovery keys or sensitive deployment data into a
public discussion.

Include:

- The affected version or commit and relevant Linux distribution.
- The vulnerable component and trust boundary.
- Minimal reproduction steps, expected behavior and observed behavior.
- Impact, required privileges and any mitigations you found.
- Sanitized logs or a proof of concept, when needed to reproduce the problem.

Keep the report private while maintainers assess it and coordinate a fix and
publication with you. Do not test against systems or devices you do not own or have
permission to assess.

The repository owner must enable GitHub private vulnerability reporting before the
public release. If the private report action is unavailable, do not disclose the
vulnerability in a public issue. No alternative private mailbox is advertised.

## Community safety reports

Use the same private advisory action for harassment or other community safety
reports under [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). Mark the report as a
community safety report, not a software vulnerability. Include only the information
needed to investigate. Maintainers must preserve the reporter's privacy and limit
sharing to the people needed to handle the report.
