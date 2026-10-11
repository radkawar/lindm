// Package dispatch delivers root-authorized work to devices: profiles,
// targeting and resource assignments, resource execution dispatch, and device
// actions including wipe, recovery boot and inventory refresh. Both kinds share
// one signed-action authority path (signed_action.go): device-signed
// challenges, fresh actor authority, start grants of at most 30 seconds and
// nonce-bound attested results.
//
// Boundaries: intents are signed with the delegated execution keys and
// verified against internal/executionauthority; secret custody and escrow
// receipts come from internal/device/secrets, readiness and storage facts from
// internal/device/inventory. Non-goals: no native execution and no trust in
// unsigned device claims; a device result is only evidence bound to an issued
// intent.
package dispatch

import (
	"lindm/internal/device/core"
	"lindm/internal/device/inventory"
	"lindm/internal/device/secrets"
)

// Service implements the dispatch RPCs over the shared device core.
type Service struct {
	*core.Service
	secrets   *secrets.Service
	inventory *inventory.Service
}

// New returns the dispatch service.
func New(c *core.Service, secrets *secrets.Service, inventory *inventory.Service) *Service {
	return &Service{Service: c, secrets: secrets, inventory: inventory}
}
