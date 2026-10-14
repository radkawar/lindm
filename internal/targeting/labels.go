// SPDX-License-Identifier: Apache-2.0

package targeting

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"

	adminv1 "lindm/gen/lindm/admin/v1"
	policyv1 "lindm/gen/lindm/policy/v1"
	"lindm/internal/targeting/targetingdb"
)

// Display labels only: names are read live and never bound into a review digest.

func revisionLabels(ctx context.Context, q *targetingdb.Queries, ids []uuid.UUID) ([]*adminv1.ProfileVersionLabel, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	rows, err := q.RevisionLabels(ctx, ids)
	if err != nil {
		return nil, err
	}
	out := make([]*adminv1.ProfileVersionLabel, 0, len(rows))
	for _, row := range rows {
		out = append(out, &adminv1.ProfileVersionLabel{RevisionId: row.ID.String(), ProfileName: row.Name, RevisionNumber: uint64(row.RevisionNumber)})
	}
	return out, nil
}

func targetName(ctx context.Context, q *targetingdb.Queries, target *policyv1.TargetRef) (string, error) {
	var name string
	var err error
	switch {
	case target.GetStaticGroupId() != "":
		name, err = q.StaticGroupName(ctx, uuid.MustParse(target.GetStaticGroupId()))
	case target.GetDynamicGroupId() != "":
		var row targetingdb.DynamicTargetGroup
		row, err = q.GetDynamicGroup(ctx, uuid.MustParse(target.GetDynamicGroupId()))
		if err == nil {
			group := new(adminv1.DynamicTargetGroup)
			if err = proto.Unmarshal(row.Definition, group); err == nil {
				name = group.GetName()
			}
		}
	case target.GetDeviceId() != "":
		name, err = q.TargetDeviceHostname(ctx, uuid.MustParse(target.GetDeviceId()))
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	return name, err
}

// impactLabels names every profile version a page's device rows refer to.
func impactLabels(ctx context.Context, q *targetingdb.Queries, report *adminv1.PreviewTargetAssignmentImpactResponse) error {
	seen := make(map[uuid.UUID]bool)
	var ids []uuid.UUID
	add := func(id string) {
		parsed, err := uuid.Parse(id)
		if err == nil && !seen[parsed] {
			seen[parsed] = true
			ids = append(ids, parsed)
		}
	}
	add(report.GetAssignment().GetProfileRevisionId())
	for _, device := range report.Devices {
		for _, resolution := range []*policyv1.TargetResolution{device.CurrentResolution, device.ProposedResolution} {
			for _, item := range resolution.GetResources() {
				for _, id := range item.ContributingRevisionIds {
					add(id)
				}
				for _, id := range item.OverriddenRevisionIds {
					add(id)
				}
			}
		}
	}
	labels, err := revisionLabels(ctx, q, ids)
	if err != nil {
		return err
	}
	report.RevisionLabels = labels
	return nil
}
