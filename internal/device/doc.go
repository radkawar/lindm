// SPDX-License-Identifier: Apache-2.0

// Package device composes the lindm server's device-facing and admin-facing
// RPC surfaces from the device domain packages:
//   - core: device identity, enrollment, sessions, renewal, execution trust and
//     the shared RPC foundation;
//   - dispatch: profiles, targeting, resource assignment and dispatch, and
//     device actions over one signed-action authority path;
//   - secrets: secret store and delivery, encryption keys, escrow and LAPS;
//   - inventory: observations, package snapshots, storage targets, readiness
//     and advisory reads;
//   - directory: approvals, groups, metadata, search and fleet summary;
//   - assistance: consented remote assistance.
//
// Boundaries: this package only constructs the domain services, embeds them so
// their RPC methods form the Connect handlers, and mounts those handlers. Its
// tests exercise the composed surfaces end to end. Non-goals: no domain logic
// lives here; add it to the owning domain package.
package device
