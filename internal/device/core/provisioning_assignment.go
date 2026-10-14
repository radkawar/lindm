// SPDX-License-Identifier: Apache-2.0

package core

import (
	"context"

	"github.com/google/uuid"
	"google.golang.org/protobuf/encoding/protojson"

	adminv1 "lindm/gen/lindm/admin/v1"
	"lindm/internal/device/devicedb"
)

func (s *Service) applyProvisioningMetadata(ctx context.Context, q *devicedb.Queries, deviceID uuid.UUID, assignment *adminv1.CreateProvisioningTokenRequest) error {
	metadata := assignment.GetMetadata()
	if metadata != nil {
		encoded, err := protojson.Marshal(metadata)
		if err != nil {
			return err
		}
		var owner *uuid.UUID
		if metadata.GetOwnerPrincipalId() != "" {
			id, _ := uuid.Parse(metadata.GetOwnerPrincipalId())
			owner = &id
		}
		if err := q.SetDeviceMetadata(ctx, devicedb.SetDeviceMetadataParams{ID: deviceID, Metadata: encoded, OwnerPrincipalID: owner}); err != nil {
			return err
		}
		if err := q.InsertDeviceLabels(ctx, devicedb.InsertDeviceLabelsParams{DeviceID: deviceID, Labels: metadata.GetLabels()}); err != nil {
			return err
		}
	}
	for _, value := range assignment.GetGroupIds() {
		group, _ := uuid.Parse(value)
		if err := q.AddProvisioningGroupMembership(ctx, devicedb.AddProvisioningGroupMembershipParams{GroupID: group, DeviceID: deviceID}); err != nil {
			return err
		}
	}
	return nil
}
