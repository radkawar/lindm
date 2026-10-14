// SPDX-License-Identifier: Apache-2.0

package core

import (
	"context"
	"math"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "lindm/gen/lindm/admin/v1"
	"lindm/internal/device/devicedb"
	"lindm/internal/identity"
)

func (s *Service) ListEnrollmentGrants(ctx context.Context, req *connect.Request[adminv1.ListEnrollmentGrantsRequest]) (*connect.Response[adminv1.ListEnrollmentGrantsResponse], error) {
	ctx, cancel := Bound(ctx)
	defer cancel()
	actor, err := s.RequireUnrestricted(ctx, identity.PermissionManageEnrollment)
	if err != nil {
		return nil, err
	}
	if req == nil || req.Msg == nil || s.Rules.Validate(req.Msg) != nil {
		return nil, Invalid("invalid_argument")
	}
	if err := s.Acquire(ctx); err != nil {
		return nil, MapErr(err)
	}
	defer s.Release()
	after, err := provisioningPage(req.Msg.GetPageToken())
	if err != nil {
		return nil, err
	}
	limit := PageLimit(req.Msg.GetPageSize())
	now := s.Now()
	var rows []devicedb.ListEnrollmentGrantsRow
	var counts devicedb.CountEnrollmentGrantsRow
	err = s.WithinUnrestrictedAuthorization(ctx, actor, identity.PermissionManageEnrollment, func(ctx context.Context, q *devicedb.Queries) error {
		var err error
		rows, err = q.ListEnrollmentGrants(ctx, devicedb.ListEnrollmentGrantsParams{AfterID: after, View: int32(req.Msg.GetView()), Now: Timestamptz(now), RowLimit: limit + 1})
		if err != nil {
			return err
		}
		counts, err = q.CountEnrollmentGrants(ctx, Timestamptz(now))
		return err
	})
	if err != nil {
		return nil, MapErr(err)
	}
	response := &adminv1.ListEnrollmentGrantsResponse{ActiveCount: grantCount(counts.Active), InactiveCount: grantCount(counts.Inactive)}
	var budget ResponsePageBudget
	for _, row := range rows {
		item := &adminv1.EnrollmentGrant{
			GrantId: row.ID.String(), Status: adminv1.EnrollmentGrantStatus_ENROLLMENT_GRANT_STATUS_ACTIVE,
			MaxUses: 1, ExpiresAt: timestamppb.New(row.ExpiresAt.Time), CreatedAt: timestamppb.New(row.CreatedAt.Time),
			CreatedBy: row.CreatedBy.String(), CreatorDisplayName: row.CreatorDisplayName,
			ConsumedDeviceHostname: row.ConsumedDeviceHostname, Labels: row.Labels,
			Name: row.Name,
		}
		if row.RevokedAt.Valid {
			item.RevokedAt = timestamppb.New(row.RevokedAt.Time)
		}
		switch {
		case row.ConsumedAt.Valid:
			item.Status = adminv1.EnrollmentGrantStatus_ENROLLMENT_GRANT_STATUS_CONSUMED
			item.UsedCount = 1
			if row.DeviceID != nil {
				item.ConsumedDeviceId = row.DeviceID.String()
			}
		case row.RevokedAt.Valid:
			item.Status = adminv1.EnrollmentGrantStatus_ENROLLMENT_GRANT_STATUS_REVOKED
		case !now.Before(row.ExpiresAt.Time):
			item.Status = adminv1.EnrollmentGrantStatus_ENROLLMENT_GRANT_STATUS_EXPIRED
		}
		fits, err := budget.Take(item)
		if err != nil {
			return nil, MapErr(err)
		}
		if len(response.Grants) == int(limit) || !fits {
			if len(response.Grants) == 0 {
				return nil, MapErr(ErrInternalState)
			}
			id, _ := uuid.Parse(response.Grants[len(response.Grants)-1].GrantId)
			response.NextPageToken = provisioningCursor(id)
			break
		}
		response.Grants = append(response.Grants, item)
	}
	return NoStore(response), nil
}

func grantCount(n int64) uint32 {
	return uint32(min(max(n, 0), math.MaxUint32))
}
