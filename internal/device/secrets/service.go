// Package secrets owns server-side secret custody: the managed secret store
// and its sealed delivery to resources, device encryption keys, recovery-key
// escrow with signed receipts, and local-admin passwords (LAPS).
//
// Boundaries: plaintext exists only while sealing to an authenticated device
// key or inside internal/escrow; reveal requires fresh authorization and, when
// configured, an approval. Rotation actions are created and dispatched by
// internal/device/dispatch, which calls the escrow ingestion and receipts here.
// Non-goals: no native execution and no dispatch scheduling.
package secrets

import "lindm/internal/device/core"

// Service implements the secret custody RPCs over the shared device core.
type Service struct {
	*core.Service
}

// New returns the secrets service.
func New(c *core.Service) *Service { return &Service{Service: c} }
