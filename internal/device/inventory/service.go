// SPDX-License-Identifier: Apache-2.0

// Package inventory owns what devices report about themselves: host
// observations, package snapshots and their quotas and receipts, storage
// targets, recovery readiness, advisory findings, and the admin reads over
// them, plus expiry cleanup.
//
// Boundaries: every report is admitted only under the device's current
// session and authority fences from internal/device/core; refresh-inventory
// device actions are admitted here by their exact signed sequence. Advisory
// matching lives in internal/advisory. Non-goals: no execution authority, no
// device actions and no secret custody; facts are evidence for policy, never
// an instruction.
package inventory

import "lindm/internal/device/core"

// Service implements the inventory RPCs over the shared device core.
type Service struct {
	*core.Service
}

// New returns the inventory service.
func New(c *core.Service) *Service { return &Service{Service: c} }
