package device

import (
	"bytes"
	"context"
	"slices"
	"strings"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"

	adminv1 "lindm/gen/lindm/admin/v1"
	"lindm/internal/device/devicedb"
	"lindm/internal/identity"
)

func (s *Service) ListDeviceGroups(ctx context.Context, req *connect.Request[adminv1.ListDeviceGroupsRequest]) (*connect.Response[adminv1.ListDeviceGroupsResponse], error) {
	ctx, cancel := bound(ctx)
	defer cancel()
	if _, err := s.requireUnrestricted(ctx, identity.PermissionManageAccounts); err != nil {
		return nil, err
	}
	if err := s.acquire(ctx); err != nil {
		return nil, mapErr(err)
	}
	defer s.release()
	if req == nil || req.Msg == nil || s.rules.Validate(req.Msg) != nil {
		return nil, invalid("invalid_group_request")
	}
	after, err := decodeProfileCursor(req.Msg.GetPageToken())
	if err != nil {
		return nil, err
	}
	limit := pageLimit(req.Msg.GetPageSize())
	rows, err := devicedb.New(s.pool).ListDeviceGroups(ctx, devicedb.ListDeviceGroupsParams{AfterID: after, RowLimit: limit + 1})
	if err != nil {
		return nil, mapErr(err)
	}
	response := &adminv1.ListDeviceGroupsResponse{}
	var budget responsePageBudget
	for _, row := range rows {
		if len(response.Groups) == int(limit) {
			break
		}
		group := &adminv1.DeviceGroup{Id: row.ID.String(), Name: row.Name, DeviceIds: row.DeviceIds}
		fits, err := budget.take(group)
		if err != nil {
			return nil, mapErr(err)
		}
		if !fits {
			if len(response.Groups) == 0 {
				return nil, mapErr(errInternalState)
			}
			break
		}
		response.Groups = append(response.Groups, group)
	}
	if len(response.Groups) < len(rows) {
		response.NextPageToken = encodeProfileCursor(rows[len(response.Groups)-1].ID)
	}
	return noStore(response), nil
}

func (s *Service) SetDeviceGroup(ctx context.Context, req *connect.Request[adminv1.SetDeviceGroupRequest]) (*connect.Response[adminv1.SetDeviceGroupResponse], error) {
	ctx, cancel := bound(ctx)
	defer cancel()
	actor, err := s.requireUnrestricted(ctx, identity.PermissionManageAccounts)
	if err != nil {
		return nil, err
	}
	if err := s.acquire(ctx); err != nil {
		return nil, mapErr(err)
	}
	defer s.release()
	if req == nil || req.Msg == nil || s.rules.Validate(req.Msg) != nil {
		return nil, invalid("invalid_group_request")
	}
	groupID, err := parseUUID(req.Msg.GetGroupId())
	if err != nil {
		return nil, invalid("invalid_id")
	}
	requestID, err := parseUUID(req.Msg.GetRequestId())
	if err != nil {
		return nil, invalid("invalid_id")
	}
	members := make([]uuid.UUID, len(req.Msg.GetDeviceIds()))
	for i, value := range req.Msg.GetDeviceIds() {
		members[i], err = parseUUID(value)
		if err != nil {
			return nil, invalid("invalid_id")
		}
	}
	slices.SortFunc(members, func(a, b uuid.UUID) int { return bytes.Compare(a[:], b[:]) })
	memberIDs := make([]string, len(members))
	for i, member := range members {
		memberIDs[i] = member.String()
	}
	const method = "SetDeviceGroup"
	digest := mutationDigest(method, groupID.String(), req.Msg.GetName(), strings.Join(memberIDs, ","), req.Msg.GetReason())
	err = s.withinUnrestrictedAuthorization(ctx, actor, identity.PermissionManageAccounts, func(ctx context.Context, q *devicedb.Queries) error {
		_, owned, err := s.beginAdminRequest(ctx, q, actor.ID, method, requestID, digest)
		if err != nil || !owned {
			return err
		}
		// The group row serializes replacements. All affected devices are then
		// locked in UUID order before changing any authorization membership.
		if err := q.UpsertDeviceGroup(ctx, devicedb.UpsertDeviceGroupParams{ID: groupID, Name: req.Msg.GetName()}); err != nil {
			return err
		}
		locked, err := q.LockDeviceGroupMembers(ctx, devicedb.LockDeviceGroupMembersParams{GroupID: groupID, DeviceIds: members})
		if err != nil {
			return err
		}
		for _, id := range members {
			if _, found := slices.BinarySearchFunc(locked, id, func(a, b uuid.UUID) int { return bytes.Compare(a[:], b[:]) }); !found {
				return errNotFound
			}
		}
		if err := q.ClearDeviceGroupMembers(ctx, groupID); err != nil {
			return err
		}
		if err := q.InsertDeviceGroupMembers(ctx, devicedb.InsertDeviceGroupMembersParams{GroupID: groupID, DeviceIds: members}); err != nil {
			return err
		}
		if err := insertAudit(ctx, q, &actor.ID, "device.group_set", groupID.String(), req.Msg.GetReason()); err != nil {
			return err
		}
		return completeAdmin(ctx, q, actor.ID, method, requestID, uuid.Nil, uuid.Nil, time.Unix(0, 0).UTC())
	})
	if err != nil {
		return nil, mapErr(err)
	}
	return noStore(&adminv1.SetDeviceGroupResponse{Group: &adminv1.DeviceGroup{Id: groupID.String(), Name: req.Msg.GetName(), DeviceIds: memberIDs}}), nil
}

func (s *Service) DeleteDeviceGroup(ctx context.Context, req *connect.Request[adminv1.DeleteDeviceGroupRequest]) (*connect.Response[adminv1.DeleteDeviceGroupResponse], error) {
	ctx, cancel := bound(ctx)
	defer cancel()
	actor, err := s.requireUnrestricted(ctx, identity.PermissionManageAccounts)
	if err != nil {
		return nil, err
	}
	if err := s.acquire(ctx); err != nil {
		return nil, mapErr(err)
	}
	defer s.release()
	if req == nil || req.Msg == nil || s.rules.Validate(req.Msg) != nil {
		return nil, invalid("invalid_group_request")
	}
	groupID, err := parseUUID(req.Msg.GetGroupId())
	if err != nil {
		return nil, invalid("invalid_id")
	}
	requestID, err := parseUUID(req.Msg.GetRequestId())
	if err != nil {
		return nil, invalid("invalid_id")
	}
	const method = "DeleteDeviceGroup"
	digest := mutationDigest(method, groupID.String(), req.Msg.GetReason())
	err = s.withinUnrestrictedAuthorization(ctx, actor, identity.PermissionManageAccounts, func(ctx context.Context, q *devicedb.Queries) error {
		_, owned, err := s.beginAdminRequest(ctx, q, actor.ID, method, requestID, digest)
		if err != nil || !owned {
			return err
		}
		if _, err := q.LockDeviceGroup(ctx, groupID); err != nil {
			return notFoundIfMissing(err)
		}
		if _, err := q.LockDeviceGroupMembers(ctx, devicedb.LockDeviceGroupMembersParams{GroupID: groupID, DeviceIds: []uuid.UUID{}}); err != nil {
			return err
		}
		if err := q.DeleteDeviceGroup(ctx, groupID); err != nil {
			return err
		}
		if err := insertAudit(ctx, q, &actor.ID, "device.group_delete", groupID.String(), req.Msg.GetReason()); err != nil {
			return err
		}
		return completeAdmin(ctx, q, actor.ID, method, requestID, uuid.Nil, uuid.Nil, time.Unix(0, 0).UTC())
	})
	if err != nil {
		return nil, mapErr(err)
	}
	return noStore(&adminv1.DeleteDeviceGroupResponse{}), nil
}
