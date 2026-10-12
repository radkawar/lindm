package targeting

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	policyv1 "lindm/gen/lindm/policy/v1"
	"lindm/internal/targeting/targetingdb"
)

// maxMembershipGroups bounds one DynamicGroupsContaining evaluation.
const maxMembershipGroups = 128

// DynamicGroupsContaining returns, in input order, the saved dynamic groups
// whose expression definitely includes the device now, with the same semantics
// as target previews: stale or failed inventory evaluates as unknown, and only
// a definite inclusion is reported. Missing groups are not members. It neither
// locks nor fences anything; it reads inside the caller's transaction snapshot.
func (s *Store) DynamicGroupsContaining(ctx context.Context, tx pgx.Tx, deviceID uuid.UUID, groups []uuid.UUID) ([]uuid.UUID, error) {
	if len(groups) == 0 {
		return nil, nil
	}
	if len(groups) > maxMembershipGroups {
		return nil, ErrCapacity
	}
	q := targetingdb.New(tx)
	row, err := q.TargetingDeviceSnapshot(ctx, deviceID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	now, err := q.TargetingClock(ctx)
	if err != nil {
		return nil, err
	}
	e, err := evaluationFromDevice(q, targetingdb.TargetingDeviceRow(row), now.Time)
	if err != nil {
		return nil, err
	}
	var members []uuid.UUID
	for _, id := range groups {
		match, err := e.target(ctx, &policyv1.TargetRef{Target: &policyv1.TargetRef_DynamicGroupId{DynamicGroupId: id.String()}})
		if err != nil {
			return nil, err
		}
		if match == included {
			members = append(members, id)
		}
	}
	return members, nil
}
