package device

import (
	"context"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	adminv1 "lindm/gen/lindm/admin/v1"
	"lindm/internal/device/devicedb"
	"lindm/internal/identity"
)

// GetEnrollmentInstructions returns deployment-owned installation metadata, not
// caller-supplied Host headers or credentials. Optional setup stays absent.
func (s *Service) GetEnrollmentInstructions(ctx context.Context, req *connect.Request[adminv1.GetEnrollmentInstructionsRequest]) (*connect.Response[adminv1.GetEnrollmentInstructionsResponse], error) {
	ctx, cancel := bound(ctx)
	defer cancel()
	actor, err := s.requireUnrestricted(ctx, identity.PermissionManageEnrollment)
	if err != nil {
		return nil, err
	}
	if req == nil || req.Msg == nil || s.rules.Validate(req.Msg) != nil {
		return nil, invalid("invalid_enrollment_instructions_request")
	}
	if err := s.acquire(ctx); err != nil {
		return nil, mapErr(err)
	}
	defer s.release()
	var response *adminv1.GetEnrollmentInstructionsResponse
	err = s.withinUnrestrictedAuthorization(ctx, actor, identity.PermissionManageEnrollment, func(context.Context, *devicedb.Queries) error {
		if s.enrollmentInstructions == nil {
			return rpcError(connect.CodeFailedPrecondition, "enrollment_instructions_unavailable")
		}
		response = proto.CloneOf(s.enrollmentInstructions)
		return nil
	})
	if err != nil {
		return nil, mapErr(err)
	}
	return noStore(response), nil
}
