// SPDX-License-Identifier: Apache-2.0

//go:build integration

package device

import (
	"testing"
	"time"
)

// Each integration case owns its schema and identities. Four active cases keep
// PostgreSQL, Keycloak and memory-hard credential work bounded even when the
// host's CPU-derived testing parallel limit is much larger. Nested subtests keep
// their existing ordering because many deliberately share a mutable fixture.
var deviceIntegrationSlots = make(chan struct{}, 4)

func parallelDeviceIntegration(t *testing.T) {
	t.Helper()
	t.Parallel()
	queued := time.Now()
	select {
	case deviceIntegrationSlots <- struct{}{}:
		started := time.Now()
		t.Cleanup(func() {
			t.Logf("device integration: active=%s queue=%s", time.Since(started), started.Sub(queued))
			<-deviceIntegrationSlots
		})
	case <-t.Context().Done():
		t.Fatal(t.Context().Err())
	}
}
