package inventory

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	inventoryv1 "lindm/gen/lindm/inventory/v1"
	"lindm/internal/device/core"
	"lindm/internal/device/devicedb"
)

// releaseCapabilityHolds dispatches rows the executor refused for a capability
// that was not enabled again when a newer host observation reports a different
// executor capability status (accepted policy version, state or per-capability
// status, including local executor.json changes). It must run before the new
// observation replaces the generation's previous one.
func releaseCapabilityHolds(ctx context.Context, q *devicedb.Queries, generation uuid.UUID, reported *agentv1.CapabilityPolicyObservation) error {
	previous, err := q.GetHostObservation(ctx, generation)
	var before *agentv1.CapabilityPolicyObservation
	switch {
	case err == nil:
		details := new(inventoryv1.NativeDetails)
		if err := proto.Unmarshal(previous.Details, details); err != nil {
			return core.ErrInternalState
		}
		before = details.GetCapabilityPolicy()
	case !errors.Is(err, pgx.ErrNoRows):
		return err
	}
	if proto.Equal(before, reported) {
		return nil
	}
	_, err = q.ReleaseCapabilityHolds(ctx, generation)
	return err
}
