package devlab

import (
	"context"
	"errors"
	"slices"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	adminv1 "lindm/gen/lindm/admin/v1"
	authv1 "lindm/gen/lindm/auth/v1"
	"lindm/internal/identity"
)

// RequireAdvisoryApproval adds the gate to the observed runtime policy through
// the ordinary owner API. It cannot change a connected demo server.
func (f *AuthorityFixture) RequireAdvisoryApproval(ctx context.Context) (result error) {
	if f.connected != nil || f.local == nil || f.closed {
		return errors.New("advisory approval qualification requires an open isolated local authority")
	}
	owner, err := f.OpenOwnerSession(ctx)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, owner.Close(context.WithoutCancel(ctx))) }()
	current, err := owner.Admin.GetAuthorization(ctx, connect.NewRequest(&adminv1.GetAuthorizationRequest{}))
	if err != nil {
		return err
	}
	state := current.Msg.GetAuthorization()
	policy := proto.CloneOf(state.GetPolicy())
	if policy == nil {
		policy = &authv1.AuthorizationPolicy{}
	}
	permission := string(identity.PermissionManageAdvisoryExceptions)
	if slices.Contains(policy.ApprovalRequiredPermissions, permission) {
		return nil
	}
	policy.ApprovalRequiredPermissions = append(policy.ApprovalRequiredPermissions, permission)
	_, err = owner.Admin.UpdateAuthorization(ctx, connect.NewRequest(&adminv1.UpdateAuthorizationRequest{
		RequestId: uuid.NewString(), ExpectedRevision: state.GetRevision(), Policy: policy,
		Reason: "Require independent advisory risk approval in the disposable qualification authority",
	}))
	return err
}
