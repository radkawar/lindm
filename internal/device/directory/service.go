// Package directory implements the administrative directory over enrolled
// devices: approvals, device groups, metadata and attribute definitions,
// search and the fleet summary.
//
// Boundaries: reads are scoped by the caller's device scope; approval
// decisions are recorded through internal/identity with each domain's approval
// scope. Non-goals: no device-facing RPCs, no execution and no secret reveal.
package directory

import (
	"lindm/internal/device/core"
	"lindm/internal/device/inventory"
)

// Service implements the directory RPCs over the shared device core.
type Service struct {
	*core.Service
	inventory *inventory.Service
}

// New returns the directory service.
func New(c *core.Service, inventory *inventory.Service) *Service {
	return &Service{Service: c, inventory: inventory}
}
