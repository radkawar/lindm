// SPDX-License-Identifier: Apache-2.0

// Package assistance implements consented remote assistance: administrator
// sessions, request readiness, capability commands, file-transfer
// authorization, reconnect workflows and encrypted recording archives, and
// device sync that relays the signalling and work directives of an accepted
// session and the device's reported assistance policy.
//
// Boundaries: sessions, file metadata, workflows and recordings are authorized
// and audited here. Live media and file content never transit the server;
// recordings arrive already sealed by the session helper and are decrypted
// only in memory for an authorized retrieval. Session descriptions pass through
// internal/assistrelay. Device identity, sessions and RPC plumbing come from
// internal/device/core. Inventory is read only as readiness evidence (local
// desktop sessions). Non-goals: no device actions and no assistance without the
// device user's consent recorded by the agent.
package assistance

import (
	"errors"

	"github.com/google/uuid"

	"lindm/internal/device/core"
)

// Service implements the assistance RPCs using its own SQL core and shared runtime.
type Service struct {
	*core.Service
	runtime *Runtime
}

// New returns an assistance service. Services handling admission and device sync
// for the same process must receive the same runtime, but retain their own cores.
func New(c *core.Service, runtime *Runtime) (*Service, error) {
	if c == nil {
		return nil, errors.New("assistance: device core is required")
	}
	if runtime == nil {
		return nil, errors.New("assistance: runtime is required")
	}
	if runtime.assistanceInstance == uuid.Nil {
		return nil, errors.New("assistance: initialized runtime is required")
	}
	c.AssistanceCeiling = assistancePolicy(c.AssistanceCeiling)
	return &Service{Service: c, runtime: runtime}, nil
}
