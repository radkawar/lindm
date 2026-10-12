package directory

import (
	"bytes"
	"context"
	"slices"
	"strings"
	"time"

	"lindm/internal/auditkind"
	"lindm/internal/device/core"

	"connectrpc.com/connect"
	"github.com/google/uuid"

	adminv1 "lindm/gen/lindm/admin/v1"
	"lindm/internal/device/devicedb"
	"lindm/internal/identity"
	"lindm/internal/rpcreason"
)

func (s *Service) ListDeviceGroups(ctx context.Context, req *connect.Request[adminv1.ListDeviceGroupsRequest]) (*connect.Response[adminv1.ListDeviceGroupsResponse], error) {
	ctx, cancel := core.Bound(ctx)
	defer cancel()
	if _, err := s.RequireUnrestricted(ctx, identity.PermissionManageAccounts); err != nil {
		return nil, err
	}
	if err := s.Acquire(ctx); err != nil {
		return nil, core.MapErr(err)
	}
	defer s.Release()
	if req == nil || req.Msg == nil || s.Rules.Validate(req.Msg) != nil {
		return nil, core.Invalid("invalid_group_request")
	}
	after, err := core.DecodeProfileCursor(req.Msg.GetPageToken())
	if err != nil {
		return nil, err
	}
	limit := core.PageLimit(req.Msg.GetPageSize())
	rows, err := devicedb.New(s.Pool).ListDeviceGroups(ctx, devicedb.ListDeviceGroupsParams{AfterID: after, RowLimit: limit + 1})
	if err != nil {
		return nil, core.MapErr(err)
	}
	response := &adminv1.ListDeviceGroupsResponse{}
	var budget core.ResponsePageBudget
	for _, row := range rows {
		if len(response.Groups) == int(limit) {
			break
		}
		group := &adminv1.DeviceGroup{Id: row.ID.String(), Name: row.Name, DeviceIds: row.DeviceIds}
		fits, err := budget.Take(group)
		if err != nil {
			return nil, core.MapErr(err)
		}
		if !fits {
			if len(response.Groups) == 0 {
				return nil, core.MapErr(core.ErrInternalState)
			}
			break
		}
		response.Groups = append(response.Groups, group)
	}
	if len(response.Groups) < len(rows) {
		response.NextPageToken = core.EncodeProfileCursor(rows[len(response.Groups)-1].ID)
	}
	return core.NoStore(response), nil
}

func (s *Service) SetDeviceGroup(ctx context.Context, req *connect.Request[adminv1.SetDeviceGroupRequest]) (*connect.Response[adminv1.SetDeviceGroupResponse], error) {
	ctx, cancel := core.Bound(ctx)
	defer cancel()
	actor, err := s.RequireUnrestricted(ctx, identity.PermissionManageAccounts)
	if err != nil {
		return nil, err
	}
	if err := s.Acquire(ctx); err != nil {
		return nil, core.MapErr(err)
	}
	defer s.Release()
	if req == nil || req.Msg == nil || s.Rules.Validate(req.Msg) != nil {
		return nil, core.Invalid("invalid_group_request")
	}
	groupID, err := core.ParseUUID(req.Msg.GetGroupId())
	if err != nil {
		return nil, core.Invalid("invalid_id")
	}
	requestID, err := core.ParseUUID(req.Msg.GetRequestId())
	if err != nil {
		return nil, core.Invalid("invalid_id")
	}
	members := make([]uuid.UUID, len(req.Msg.GetDeviceIds()))
	for i, value := range req.Msg.GetDeviceIds() {
		members[i], err = core.ParseUUID(value)
		if err != nil {
			return nil, core.Invalid("invalid_id")
		}
	}
	slices.SortFunc(members, func(a, b uuid.UUID) int { return bytes.Compare(a[:], b[:]) })
	memberIDs := make([]string, len(members))
	for i, member := range members {
		memberIDs[i] = member.String()
	}
	const method = "SetDeviceGroup"
	digest := core.MutationDigest(method, groupID.String(), req.Msg.GetName(), strings.Join(memberIDs, ","), req.Msg.GetReason())
	if req.Msg.GetCreateOnly() {
		digest = core.MutationDigest(method, groupID.String(), req.Msg.GetName(), strings.Join(memberIDs, ","), req.Msg.GetReason(), "create_only")
	}
	err = s.WithinUnrestrictedAuthorization(ctx, actor, identity.PermissionManageAccounts, func(ctx context.Context, q *devicedb.Queries) error {
		_, owned, err := s.BeginAdminRequest(ctx, q, actor.ID, method, requestID, digest)
		if err != nil || !owned {
			return err
		}
		// The group row serializes replacements. All affected devices are then
		// locked in UUID order before changing any authorization membership.
		changed, err := q.UpsertDeviceGroup(ctx, devicedb.UpsertDeviceGroupParams{ID: groupID, Name: req.Msg.GetName(), CreateOnly: req.Msg.GetCreateOnly()})
		if err != nil {
			return err
		}
		if changed == 0 {
			return rpcreason.Error(connect.CodeAborted, "group_already_exists")
		}
		locked, err := q.LockDeviceGroupMembers(ctx, devicedb.LockDeviceGroupMembersParams{GroupID: groupID, DeviceIds: members})
		if err != nil {
			return err
		}
		for _, id := range members {
			if _, found := slices.BinarySearchFunc(locked, id, func(a, b uuid.UUID) int { return bytes.Compare(a[:], b[:]) }); !found {
				return core.ErrNotFound
			}
		}
		if err := q.ClearDeviceGroupMembers(ctx, groupID); err != nil {
			return err
		}
		if err := q.InsertDeviceGroupMembers(ctx, devicedb.InsertDeviceGroupMembersParams{GroupID: groupID, DeviceIds: members}); err != nil {
			return err
		}
		if err := core.InsertAudit(ctx, q, &actor.ID, auditkind.DeviceGroupSet, groupID.String(), req.Msg.GetReason()); err != nil {
			return err
		}
		return core.CompleteAdmin(ctx, q, actor.ID, method, requestID, uuid.Nil, uuid.Nil, time.Unix(0, 0).UTC())
	})
	if err != nil {
		return nil, core.MapErr(err)
	}
	return core.NoStore(&adminv1.SetDeviceGroupResponse{Group: &adminv1.DeviceGroup{Id: groupID.String(), Name: req.Msg.GetName(), DeviceIds: memberIDs}}), nil
}

func (s *Service) DeleteDeviceGroup(ctx context.Context, req *connect.Request[adminv1.DeleteDeviceGroupRequest]) (*connect.Response[adminv1.DeleteDeviceGroupResponse], error) {
	ctx, cancel := core.Bound(ctx)
	defer cancel()
	actor, err := s.RequireUnrestricted(ctx, identity.PermissionManageAccounts)
	if err != nil {
		return nil, err
	}
	if err := s.Acquire(ctx); err != nil {
		return nil, core.MapErr(err)
	}
	defer s.Release()
	if req == nil || req.Msg == nil || s.Rules.Validate(req.Msg) != nil {
		return nil, core.Invalid("invalid_group_request")
	}
	groupID, err := core.ParseUUID(req.Msg.GetGroupId())
	if err != nil {
		return nil, core.Invalid("invalid_id")
	}
	requestID, err := core.ParseUUID(req.Msg.GetRequestId())
	if err != nil {
		return nil, core.Invalid("invalid_id")
	}
	const method = "DeleteDeviceGroup"
	digest := core.MutationDigest(method, groupID.String(), req.Msg.GetReason())
	err = s.WithinUnrestrictedAuthorization(ctx, actor, identity.PermissionManageAccounts, func(ctx context.Context, q *devicedb.Queries) error {
		_, owned, err := s.BeginAdminRequest(ctx, q, actor.ID, method, requestID, digest)
		if err != nil || !owned {
			return err
		}
		if _, err := q.LockDeviceGroup(ctx, groupID); err != nil {
			return core.NotFoundIfMissing(err)
		}
		if _, err := q.LockDeviceGroupMembers(ctx, devicedb.LockDeviceGroupMembersParams{GroupID: groupID, DeviceIds: []uuid.UUID{}}); err != nil {
			return err
		}
		if err := q.DeleteDeviceGroup(ctx, groupID); err != nil {
			return err
		}
		if err := core.InsertAudit(ctx, q, &actor.ID, auditkind.DeviceGroupDelete, groupID.String(), req.Msg.GetReason()); err != nil {
			return err
		}
		return core.CompleteAdmin(ctx, q, actor.ID, method, requestID, uuid.Nil, uuid.Nil, time.Unix(0, 0).UTC())
	})
	if err != nil {
		return nil, core.MapErr(err)
	}
	return core.NoStore(&adminv1.DeleteDeviceGroupResponse{}), nil
}
