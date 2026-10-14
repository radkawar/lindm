// SPDX-License-Identifier: Apache-2.0

package core

import (
	"context"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	adminv1 "lindm/gen/lindm/admin/v1"
	"lindm/internal/device/devicedb"
	"lindm/internal/identity"
	"lindm/internal/rpcreason"
)

// GetEnrollmentInstructions returns deployment-owned installation metadata, not
// caller-supplied Host headers or credentials. Optional setup stays absent.
func (s *Service) GetEnrollmentInstructions(ctx context.Context, req *connect.Request[adminv1.GetEnrollmentInstructionsRequest]) (*connect.Response[adminv1.GetEnrollmentInstructionsResponse], error) {
	ctx, cancel := Bound(ctx)
	defer cancel()
	actor, err := s.RequireUnrestricted(ctx, identity.PermissionManageEnrollment)
	if err != nil {
		return nil, err
	}
	if req == nil || req.Msg == nil || s.Rules.Validate(req.Msg) != nil {
		return nil, Invalid("invalid_enrollment_instructions_request")
	}
	if err := s.Acquire(ctx); err != nil {
		return nil, MapErr(err)
	}
	defer s.Release()
	var response *adminv1.GetEnrollmentInstructionsResponse
	err = s.WithinUnrestrictedAuthorization(ctx, actor, identity.PermissionManageEnrollment, func(context.Context, *devicedb.Queries) error {
		if s.EnrollmentInstructions == nil {
			return rpcreason.Error(connect.CodeFailedPrecondition, "enrollment_instructions_unavailable")
		}
		response = proto.CloneOf(s.EnrollmentInstructions)
		return nil
	})
	if err != nil {
		return nil, MapErr(err)
	}
	return NoStore(response), nil
}
