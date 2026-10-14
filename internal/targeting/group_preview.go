// SPDX-License-Identifier: Apache-2.0

package targeting

import (
	"context"
	"slices"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "lindm/gen/lindm/admin/v1"
	"lindm/internal/identity"
	"lindm/internal/targeting/targetingdb"
)

// defaultGroupPreviewSample is the number of members named when the request
// leaves sample_size unset; protobuf bounds the explicit size.
const defaultGroupPreviewSample = 5

// PreviewDynamicGroup evaluates an unsaved expression with the saved-group
// matcher against at most maxImpactDevices devices at one pinned clock. It reads
// without row locks and writes nothing; it is advisory while editing, not the
// reviewed membership an assignment preview records.
func (s *Store) PreviewDynamicGroup(ctx context.Context, tx pgx.Tx, p identity.Principal, perm identity.Permission, r *adminv1.PreviewDynamicGroupRequest) (*adminv1.PreviewDynamicGroupResponse, error) {
	if err := s.validate(r); err != nil {
		return nil, err
	}
	if err := validateExpression(r.Expression); err != nil {
		return nil, err
	}
	q, err := beginRead(tx, p, perm, true)
	if err != nil {
		return nil, err
	}
	if _, valid, err := expressionDefinitions(ctx, q, r.Expression); err != nil {
		return nil, err
	} else if !valid {
		return nil, ErrRejected
	}
	now, err := q.TargetingClock(ctx)
	if err != nil {
		return nil, err
	}
	out := &adminv1.PreviewDynamicGroupResponse{EvaluatedAt: timestamppb.New(now.Time), Complete: true}
	size := int(r.SampleSize)
	if size == 0 {
		size = defaultGroupPreviewSample
	}
	after := uuid.Nil
	for {
		rows, err := q.ListTargetingDevicePage(ctx, after)
		if err != nil {
			return nil, err
		}
		for _, row := range rows {
			after = row.ID
			if out.EvaluatedDeviceCount == maxImpactDevices {
				out.Complete = false
				return out, nil
			}
			e, err := evaluationFromDevice(q, targetingdb.TargetingDeviceRow(row), now.Time)
			if err != nil {
				return nil, err
			}
			out.EvaluatedDeviceCount++
			switch evaluate(r.Expression, e.input.Device, e.metadata, now.Time) {
			case included:
				out.MatchedCount++
				out.MatchedDevices = sampleMember(out.MatchedDevices, size, &adminv1.DynamicGroupPreviewDevice{DeviceId: row.ID.String(), Hostname: row.Hostname, OsId: row.OsID, OsVersion: row.OsVersion})
			case unknown:
				out.UnknownCount++
			}
		}
		if len(rows) < 200 {
			return out, nil
		}
	}
}

// sampleMember keeps the first size members by hostname, then device ID, so the
// sample is stable across evaluations of the same fleet.
func sampleMember(sample []*adminv1.DynamicGroupPreviewDevice, size int, d *adminv1.DynamicGroupPreviewDevice) []*adminv1.DynamicGroupPreviewDevice {
	compare := func(a, b *adminv1.DynamicGroupPreviewDevice) int {
		if c := strings.Compare(a.Hostname, b.Hostname); c != 0 {
			return c
		}
		return strings.Compare(a.DeviceId, b.DeviceId)
	}
	i, _ := slices.BinarySearchFunc(sample, d, compare)
	if i >= size {
		return sample
	}
	sample = slices.Insert(sample, i, d)
	if len(sample) > size {
		sample = sample[:size]
	}
	return sample
}
