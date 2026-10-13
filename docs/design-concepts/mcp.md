# Safe assistant access

MCP lets an assistant read fleet evidence and submit requests for human review. It
is not a second execution API. All traffic stays on the customer's own lindmd.

## Transport and identity

The implementation uses stateless MCP Streamable HTTP at `/mcp` on the existing
administrative TLS listener. JSON responses are supported; persistent event
streams and transport sessions are not needed. Each request authenticates with an
existing browser session (including Origin and CSRF checks) or an opaque, expiring
MCP token issued from Settings. Tokens are stored as hashes, never plaintext, and
can be revoked. They belong to their issuing principal and select read-only or
read-and-propose access. Current identity status, role and device scopes still
apply on every call; a token never grants a new permission. Tokens cannot be used
for ordinary Connect APIs. No anonymous discovery or elevated service account is
provided. Browser and CLI identity ceremonies remain the existing identity
service's responsibility; no independent OAuth issuer is introduced.

Tokens expire within 30 days, and each principal can hold at most 100 active
tokens. Browser sign-out does not revoke dedicated tokens. Account credential
invalidation, directory lifecycle changes and runtime authorization replacement
revoke them. Break-glass credentials cannot issue or authenticate assistant
tokens. Tokens do not satisfy browser-only or recent step-up requirements.

The console permission gate for changing the deployment enable switch is
`integrations.manage` with unrestricted scope. A principal can issue or revoke
only their own tokens, and needs that same permission to use this Settings page.
MCP is disabled by default. Disabling it denies both tokens and browser sessions.

## Tools and authorization

Read tools map to existing Connect AdminService methods: fleet summary, paginated
device search, device details, advisory findings, rollout records, audit search,
and device resource compliance. The adapter invokes the existing authenticated
handler, preserving protobuf validation, fresh authorization fences, independent
permission checks and SQL scope filtering. Results do not expand a caller's scope.
There is no generic method invocation tool or arbitrary URL access.

Restart proposals call CreateApproval with the exact restart-device payload.
Rollout proposals first call StartRollout to retain the exact reviewed plan, then
CreateApproval with that same payload. The rollout domain forces every
MCP-origin plan to await independent approval, even when ordinary console changes
would not require approval. No assignment is saved and no stage is admitted
before approval. Both operations retain the existing request ID replay binding.
An interrupted preparation can leave only a paused proposal; exact-request
recovery creates its approval, and an unapproved plan expires without execution.

Proposal tools never dispatch an action, approve a request or activate a rollout.
Request IDs and reasons bind the same payload that the console reviews. Existing
two-person rules, scope checks, step-up requirements and approval consumption
remain unchanged. Reveals, recovery keys, passwords, secret contents and wipes
are not exposed. Read results exclude secret-bearing APIs. Compliance results
also exclude desired configuration and execution output. Approval decisions and
subsequent execution remain in the console or existing authorized API.

## Audit and bounds

Every authenticated MCP request, including discovery and denied tool calls, writes
an audit event with the principal, method/tool, bounded client tag and outcome.
An audit write failure fails closed before an API call. Proposal creation also
produces the normal domain approval audit. No token, request payload or returned
device text is copied into audit reasons. Token issuance, revocation and enable
changes are audited by identity.

Transport bodies are limited to 64 KiB, each tool result to 512 KiB, and the full
HTTP response to a bounded envelope. Lists default to 50 records when omitted,
within each existing API's protobuf bounds. Each principal can make 60 HTTP
requests per minute; additional tokens cannot evade this limit. The limiter
stores at most 4096 principal windows. Requests have a 25-second deadline and
retain the administrative listener's in-flight bounds. Oversized results fail
with an instruction to narrow or page the query, never silently truncate
evidence. If a proposal response cannot be confirmed, retain the request ID and
inspect the console approval record rather than submit a new request.
MCP errors do not reveal internal failures.

## Untrusted content

Hostnames, inventory text, finding descriptions, audit reasons and other reported
strings are untrusted data, not instructions. Every tool declares this boundary;
results are data envelopes with an explicit warning. Assistants must not obey
embedded instructions or infer authority from device text. Human review remains
necessary even when a proposal was prepared from apparently credible evidence.

## Console job

Settings shows whether assistant access is enabled, its review-only mutation
boundary, the affected deployment, and the caller's active tokens. Enable/disable,
issue and revoke are explicit actions with visible errors; tokens appear once and
never enter query cache or browser storage. A connection snippet uses the current
customer origin and a token placeholder. No public host or user is hardcoded.

The shown-once dialog confirms issuance; the active list confirms revocation.
Token success notifications do not cover token metadata. An uncertain issuance
blocks creation until the caller refreshes and revokes any new, unused token
with the submitted name, then confirms that check. Its plaintext is not replayed.

## Verification

Tests must cover anonymous and permission denial, filtered device results,
read-only token refusal of proposals, pending approval creation without dispatch,
and durable audit rows. A security reviewer must examine transport, principal and
token binding, proposal restrictions, audit failure behavior and the Settings
controls before landing. Console review covers light/dark and desktop/mobile;
automated green is not owner design approval.
