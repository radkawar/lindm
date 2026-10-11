// Package core is the device identity and enrollment domain and the
// foundation every other device package builds on.
//
// It owns enrollment (online grants, provisioning tokens with pending
// approval, offline and recovery enrollment), certificate issuance and
// renewal, device sessions and authority fences, device revocation, execution
// trust delivery, agent update records and release compatibility. As the
// shared layer it holds the resolved dependencies (Service), the RPC plumbing
// (admission slots, deadlines, validation, rpcreason errors, no-store
// responses, cursors and page budgets), device-scope authorization, audit
// records, approval gating, the dispatch clock and the device-action
// specification rules shared by dispatch, secrets and inventory.
//
// Boundaries: storage goes through devicedb (sqlc); errors leave as Connect
// codes with an rpcreason. Core never imports another device package; work it
// must hand off, such as seeding a provisioned device's resource assignment,
// is injected at construction. Non-goals: no resource or action dispatch, no
// inventory ingestion, no secret custody and no assistance.
package core
