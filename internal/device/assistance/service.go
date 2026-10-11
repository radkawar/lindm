// Package assistance implements consented remote assistance: administrator
// session creation, join, answer and stop, and the device-side assistance sync
// that relays the signalling of an accepted session.
//
// Boundaries: sessions are authorized and audited here; media never transits
// the server, which only relays session descriptions through
// internal/assistrelay. Device identity, sessions and RPC plumbing come from
// internal/device/core. Non-goals: no device actions, no inventory reads and no
// assistance without the device user's consent recorded by the agent.
package assistance

import "lindm/internal/device/core"

// Service implements the assistance RPCs over the shared device core.
type Service struct {
	*core.Service
}

// New returns the assistance service.
func New(c *core.Service) *Service { return &Service{Service: c} }
