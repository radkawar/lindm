// SPDX-License-Identifier: Apache-2.0

package journal

import (
	"context"
	"database/sql"
	"errors"

	agentv1 "lindm/gen/lindm/agent/v1"
)

// DeviceActionsBlockUpdate includes consumed recovery BOOT grants even after
// startup has classified their original-device outcome as unknown. A root-side
// record cannot manufacture proof that the separate recovery environment finished.
func (s *Store) DeviceActionsBlockUpdate(ctx context.Context) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return false, ErrClosed
	}
	cursor := ""
	for count := 0; count <= maximumDeviceActions; count++ {
		row, err := s.queries.NextUpdateInterlockDeviceAction(ctx, cursor)
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		if err != nil {
			return false, stateReadError(ctx)
		}
		if count == maximumDeviceActions {
			return false, ErrRecoveryHold
		}
		record, err := s.decodeDeviceAction(row)
		if err != nil {
			return false, err
		}
		if record.GetState() != agentv1.DeviceActionState_DEVICE_ACTION_STATE_OUTCOME_UNKNOWN || len(record.GetRecoveryBootGrantEnvelope()) != 0 {
			return true, nil
		}
		cursor = row.ActionID
	}
	return false, ErrRecoveryHold
}
