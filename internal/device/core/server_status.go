// SPDX-License-Identifier: Apache-2.0

package core

import (
	"context"

	"connectrpc.com/connect"

	adminv1 "lindm/gen/lindm/admin/v1"
	"lindm/internal/device/devicedb"
	"lindm/internal/identity"
	"lindm/internal/rpcreason"
)

// GetServerStatus exposes redacted deployment evidence only to administrators
// with an unrestricted integrations grant, including a fresh transaction fence.
func (s *Service) GetServerStatus(ctx context.Context, req *connect.Request[adminv1.GetServerStatusRequest]) (*connect.Response[adminv1.GetServerStatusResponse], error) {
	ctx, cancel := Bound(ctx)
	defer cancel()
	actor, err := s.RequireUnrestricted(ctx, identity.PermissionManageIntegrations)
	if err != nil {
		return nil, err
	}
	if req == nil || req.Msg == nil || s.Rules.Validate(req.Msg) != nil {
		return nil, Invalid("invalid_request")
	}
	if err := s.Acquire(ctx); err != nil {
		return nil, MapErr(err)
	}
	defer s.Release()
	var response *adminv1.GetServerStatusResponse
	err = s.WithinUnrestrictedAuthorization(ctx, actor, identity.PermissionManageIntegrations, func(ctx context.Context, q *devicedb.Queries) error {
		if s.ServerStatus == nil {
			return rpcreason.Error(connect.CodeUnavailable, "server_status_unavailable")
		}
		response = s.ServerStatus()
		custody, err := s.recoveryCustodyStatus(ctx, q, actor)
		if err != nil {
			return err
		}
		response.RecoveryKeyCustody = custody
		return nil
	})
	if err != nil {
		return nil, MapErr(err)
	}
	return NoStore(response), nil
}
