// SPDX-License-Identifier: Apache-2.0

package identity

import (
	"context"
	"time"
)

// DirectorySource supplies authoritative identity observations without owning
// authorization policy, persistence or the observation's database timestamp.
// Implementations must not substitute cached authority when their source fails.
type DirectorySource interface {
	Observe(context.Context, string) (directoryObservation, error)
}

type directoryObservation struct {
	Found       bool
	UserID      string
	DisplayName string
	Enabled     bool
	Direct      bool
	Groups      []string
	Lineage     *brokerLineage
	// AcquiredAt is the database clock sampled by Service before the source read.
	// Commit time must not replace it; a later sample wins across processes.
	AcquiredAt time.Time
}
