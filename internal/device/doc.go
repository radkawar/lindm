// Package device is, for now, most of the lindm server's device-facing and
// admin-facing RPC surface on one shared Service. It covers:
//   - device identity, enrollment (online, offline, grants, recovery) and
//     certificate renewal;
//   - inventory and observation snapshots, fleet summary, metadata, groups and
//     search;
//   - resource assignment, targeting, dispatch, signed start and result;
//   - signed device actions, including wipe, recovery boot, readiness and
//     escrow;
//   - local-admin passwords (LAPS), encryption keys and the secret store;
//   - assistance administration and sync, approvals, advisory reads, agent
//     updates and release rollout.
//
// This breadth is a known defect (audit 2026-10-11 #3). The package is
// scheduled to split into device core and enrollment, dispatch for resources
// and actions, secrets and LAPS, assistance and inventory. Each new package
// will carry its own boundary doc. Until then, do not add new domains here.
//
// Boundaries that already hold: storage goes through devicedb (sqlc) and
// errors leave as Connect codes with an rpcreason. Policy compilation,
// targeting expressions, reports, integrations and execution authority live in
// their own packages. Non-goals: device performs no native work and trusts no
// agent claim it has not verified against a signed intent or a stored record.
package device
