package device

import (
	"context"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "lindm/gen/lindm/admin/v1"
	"lindm/internal/device/devicedb"
	"lindm/internal/identity"
)

func (s *Service) ListEnrollmentGrants(ctx context.Context, req *connect.Request[adminv1.ListEnrollmentGrantsRequest]) (*connect.Response[adminv1.ListEnrollmentGrantsResponse], error) {
	ctx, cancel := bound(ctx)
	defer cancel()
	actor, err := s.requireUnrestricted(ctx, identity.PermissionManageEnrollment)
	if err != nil {
		return nil, err
	}
	if req == nil || req.Msg == nil || s.rules.Validate(req.Msg) != nil {
		return nil, invalid("invalid_argument")
	}
	if err := s.acquire(ctx); err != nil {
		return nil, mapErr(err)
	}
	defer s.release()
	after, err := provisioningPage(req.Msg.GetPageToken())
	if err != nil {
		return nil, err
	}
	limit := pageLimit(req.Msg.GetPageSize())
	var rows []devicedb.ListEnrollmentGrantsRow
	err = s.withinUnrestrictedAuthorization(ctx, actor, identity.PermissionManageEnrollment, func(ctx context.Context, q *devicedb.Queries) error {
		var err error
		rows, err = q.ListEnrollmentGrants(ctx, devicedb.ListEnrollmentGrantsParams{AfterID: after, RowLimit: limit + 1})
		return err
	})
	if err != nil {
		return nil, mapErr(err)
	}
	response := new(adminv1.ListEnrollmentGrantsResponse)
	var budget responsePageBudget
	now := s.now()
	for _, row := range rows {
		item := &adminv1.EnrollmentGrant{
			GrantId: row.ID.String(), Status: adminv1.EnrollmentGrantStatus_ENROLLMENT_GRANT_STATUS_ACTIVE,
			MaxUses: 1, ExpiresAt: timestamppb.New(row.ExpiresAt.Time), CreatedAt: timestamppb.New(row.CreatedAt.Time),
			CreatedBy: row.CreatedBy.String(), CreatorDisplayName: row.CreatorDisplayName,
			ConsumedDeviceHostname: row.ConsumedDeviceHostname, Labels: row.Labels,
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
		fits, err := budget.take(item)
		if err != nil {
			return nil, mapErr(err)
		}
		if len(response.Grants) == int(limit) || !fits {
			if len(response.Grants) == 0 {
				return nil, mapErr(errInternalState)
			}
			id, _ := uuid.Parse(response.Grants[len(response.Grants)-1].GrantId)
			response.NextPageToken = provisioningCursor(id)
			break
		}
		response.Grants = append(response.Grants, item)
	}
	return noStore(response), nil
}
