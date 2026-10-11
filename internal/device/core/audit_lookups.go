package core

import (
	"context"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	adminv1 "lindm/gen/lindm/admin/v1"
	"lindm/internal/device/devicedb"
	"lindm/internal/identity"
)

func auditLookupArguments(after string, id *string, size uint32) (uuid.UUID, *uuid.UUID, int32, error) {
	afterID := uuid.Nil
	var err error
	if after != "" {
		afterID, err = uuid.Parse(after)
		if err != nil {
			return uuid.Nil, nil, 0, Invalid("invalid_id")
		}
	}
	var exact *uuid.UUID
	if id != nil {
		parsed, err := uuid.Parse(*id)
		if err != nil {
			return uuid.Nil, nil, 0, Invalid("invalid_id")
		}
		exact = &parsed
	}
	if size == 0 {
		size = 50
	}
	return afterID, exact, int32(size), nil
}

type auditLookupRequest interface {
	proto.Message
	GetAfterId() string
	GetId() string
	GetNamePrefix() string
	GetPageSize() uint32
}

// Both pickers share exactly the audit-only authorization and pagination boundary.
func auditLookupRPC[Request auditLookupRequest, Response any](ctx context.Context, s *Service, request Request, query func(context.Context, *devicedb.Queries, uuid.UUID, *uuid.UUID, int32) (*Response, error)) (*connect.Response[Response], error) {
	ctx, cancel := Bound(ctx)
	defer cancel()
	if _, err := s.RequireUnrestricted(ctx, identity.PermissionReadAudit); err != nil {
		return nil, err
	}
	if !request.ProtoReflect().IsValid() || s.Rules.Validate(request) != nil {
		return nil, Invalid("invalid_argument")
	}
	if err := s.Acquire(ctx); err != nil {
		return nil, MapErr(err)
	}
	defer s.Release()
	var exactID *string
	if id := request.GetId(); id != "" {
		exactID = &id
	}
	after, id, limit, err := auditLookupArguments(request.GetAfterId(), exactID, request.GetPageSize())
	if err != nil {
		return nil, err
	}
	response, err := query(ctx, devicedb.New(s.Pool), after, id, limit)
	if err != nil {
		return nil, MapErr(err)
	}
	return connect.NewResponse(response), nil
}

func (s *Service) ListAuditActors(ctx context.Context, req *connect.Request[adminv1.ListAuditActorsRequest]) (*connect.Response[adminv1.ListAuditActorsResponse], error) {
	return auditLookupRPC(ctx, s, req.Msg, func(ctx context.Context, q *devicedb.Queries, after uuid.UUID, id *uuid.UUID, limit int32) (*adminv1.ListAuditActorsResponse, error) {
		rows, err := q.ListAuditActors(ctx, devicedb.ListAuditActorsParams{AfterID: after, ID: id, NamePrefix: req.Msg.GetNamePrefix(), RowLimit: limit + 1})
		if err != nil {
			return nil, err
		}
		return auditActorPage(rows, limit), nil
	})
}

func auditActorPage(rows []devicedb.ListAuditActorsRow, limit int32) *adminv1.ListAuditActorsResponse {
	response := &adminv1.ListAuditActorsResponse{}
	if len(rows) > int(limit) {
		rows = rows[:limit]
		response.NextAfterId = rows[len(rows)-1].ID.String()
	}
	for _, row := range rows {
		response.Actors = append(response.Actors, &adminv1.AuditActor{Id: row.ID.String(), DisplayName: row.DisplayName})
	}
	return response
}

func (s *Service) ListAuditDevices(ctx context.Context, req *connect.Request[adminv1.ListAuditDevicesRequest]) (*connect.Response[adminv1.ListAuditDevicesResponse], error) {
	return auditLookupRPC(ctx, s, req.Msg, func(ctx context.Context, q *devicedb.Queries, after uuid.UUID, id *uuid.UUID, limit int32) (*adminv1.ListAuditDevicesResponse, error) {
		rows, err := q.ListAuditDevices(ctx, devicedb.ListAuditDevicesParams{AfterID: after, ID: id, NamePrefix: req.Msg.GetNamePrefix(), RowLimit: limit + 1})
		if err != nil {
			return nil, err
		}
		return auditDevicePage(rows, limit), nil
	})
}

func auditDevicePage(rows []devicedb.ListAuditDevicesRow, limit int32) *adminv1.ListAuditDevicesResponse {
	response := &adminv1.ListAuditDevicesResponse{}
	if len(rows) > int(limit) {
		rows = rows[:limit]
		response.NextAfterId = rows[len(rows)-1].ID.String()
	}
	for _, row := range rows {
		response.Devices = append(response.Devices, &adminv1.AuditDevice{Id: row.ID.String(), Hostname: row.Hostname})
	}
	return response
}
