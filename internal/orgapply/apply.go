package orgapply

import (
	"context"
	"errors"
	"fmt"
	"maps"

	"buf.build/go/protovalidate"
	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	adminv1 "lindm/gen/lindm/admin/v1"
	adminv1connect "lindm/gen/lindm/admin/v1/adminv1connect"
	authv1 "lindm/gen/lindm/auth/v1"
)

// Apply performs each planned mutation once using deterministic request identities
// and observed revisions. It returns partial outcomes and secrets on error. The
// caller must preserve that result, not discard secrets when a later RPC fails.
func Apply(ctx context.Context, client adminv1connect.AdminServiceClient, plan *ChangePlan, opts Options) (*Result, error) {
	if client == nil || plan == nil || plan.spec == nil {
		return nil, errors.New("orgapply: client and engine-created plan are required")
	}
	result := &Result{}
	revisions := maps.Clone(plan.revisions)
	var accounts map[string]*authv1.LocalAccount
	if opts.AccountClient != nil && len(plan.spec.GetAccounts()) > 0 {
		list, err := opts.AccountClient.ListAccounts(ctx)
		if err != nil {
			return result, fmt.Errorf("list accounts: %w", err)
		}
		accounts = make(map[string]*authv1.LocalAccount, len(list.GetAccounts()))
		for _, a := range list.GetAccounts() {
			accounts[a.GetUsername()] = a
		}
	}
	for _, op := range plan.operations {
		outcome := op.outcome
		if op.request == nil {
			result.Outcomes = append(result.Outcomes, outcome)
			continue
		}
		if opts.AccountClient != nil {
			if err := opts.AccountClient.CheckSession(ctx); err != nil {
				return result, fmt.Errorf("browser session no longer authorizes import: %w", err)
			}
		}
		request := proto.Clone(op.request)
		if a, ok := request.(*authv1.CreateAccountRequest); ok {
			if opts.AccountClient != nil {
				if err := applyAccount(ctx, opts.AccountClient, accounts, a, &outcome, result); err != nil {
					return result, fmt.Errorf("apply account %s: %w", outcome.Name, err)
				}
			}
			result.Outcomes = append(result.Outcomes, outcome)
			continue
		}
		if a, ok := request.(*adminv1.PutTargetAssignmentRequest); ok {
			a.Assignment.ProfileRevisionId = revisions[op.profileID]
		}
		if err := completeRequest(plan.spec.GetName(), outcome.Kind, outcome.Name+"\x00"+op.predecessorID, request); err != nil {
			return result, err
		}
		if err := applyRequest(ctx, client, request, &outcome, result, revisions); err != nil {
			return result, fmt.Errorf("apply %s %s: %w", outcome.Kind, outcome.Name, err)
		}
		result.Outcomes = append(result.Outcomes, outcome)
	}
	if len(plan.spec.GetAssignments()) > 0 {
		if opts.AccountClient != nil {
			if err := opts.AccountClient.CheckSession(ctx); err != nil {
				return result, fmt.Errorf("browser session no longer authorizes activation: %w", err)
			}
		}
		if err := activate(ctx, client, plan, result); err != nil {
			return result, err
		}
	}
	return result, nil
}

func completeRequest(org, kind, id string, request proto.Message) error {
	if approval, ok := request.(*adminv1.CreateApprovalRequest); ok {
		if err := completeRequest(org, kind, id, approval.GetAcceptAdvisoryFinding()); err != nil {
			return err
		}
		return protovalidate.Validate(approval)
	}
	field := request.ProtoReflect().Descriptor().Fields().ByName("request_id")
	if field == nil {
		return errors.New("orgapply: mutation missing request identity")
	}
	request.ProtoReflect().Clear(field)
	key, err := requestID(org, kind, id, request)
	if err != nil {
		return err
	}
	request.ProtoReflect().Set(field, protoreflect.ValueOfString(key))
	if err := protovalidate.Validate(request); err != nil {
		return fmt.Errorf("validate completed %s request: %w", kind, err)
	}
	return nil
}

func applyRequest(ctx context.Context, client adminv1connect.AdminServiceClient, request proto.Message, outcome *Outcome, result *Result, revisions map[string]string) error {
	switch r := request.(type) {
	case *adminv1.UpdateAuthorizationRequest:
		_, err := client.UpdateAuthorization(ctx, connect.NewRequest(r))
		return err
	case *adminv1.CreateApprovalRequest:
		response, err := client.CreateApproval(ctx, connect.NewRequest(r))
		if err != nil {
			return err
		}
		outcome.ID = response.Msg.GetApproval().GetId()
		return nil
	case *adminv1.SetDeviceGroupRequest:
		_, err := client.SetDeviceGroup(ctx, connect.NewRequest(r))
		if err != nil {
			return err
		}
		groups, err := pages(func(token string) ([]*adminv1.DeviceGroup, string, error) {
			response, err := client.ListDeviceGroups(ctx, connect.NewRequest(&adminv1.ListDeviceGroupsRequest{PageSize: 100, PageToken: token}))
			if err != nil {
				return nil, "", err
			}
			return response.Msg.GetGroups(), response.Msg.GetNextPageToken(), nil
		})
		if err != nil {
			return err
		}
		for _, group := range groups {
			if group.GetId() == r.GetGroupId() && group.GetName() == r.GetName() {
				return nil
			}
		}
		return connect.NewError(connect.CodeAborted, errors.New("group creation receipt no longer matches live state; choose a new stable group ID"))
	case *adminv1.PutDynamicGroupRequest:
		_, err := client.PutDynamicGroup(ctx, connect.NewRequest(r))
		return err
	case *adminv1.SetCapabilityPolicyRequest:
		_, err := client.SetCapabilityPolicy(ctx, connect.NewRequest(r))
		return err
	case *adminv1.PublishProfileRevisionRequest:
		response, err := client.PublishProfileRevision(ctx, connect.NewRequest(r))
		if err != nil {
			return err
		}
		revisions[r.GetProfileId()] = response.Msg.GetRevision().GetRevisionId()
		return nil
	case *adminv1.PutRolloutRequest:
		_, err := client.PutRollout(ctx, connect.NewRequest(r))
		return err
	case *adminv1.PutTargetAssignmentRequest:
		_, err := client.PutTargetAssignment(ctx, connect.NewRequest(r))
		return err
	case *adminv1.CreateProvisioningTokenRequest:
		response, err := client.CreateProvisioningToken(ctx, connect.NewRequest(r))
		if err != nil {
			return err
		}
		outcome.ID = response.Msg.GetTokenId()
		if response.Msg.GetSecretDeliveryUnknown() {
			outcome.Status = "pending"
			outcome.Detail = "secret delivery unknown; revoke and issue under a new name"
		} else if response.Msg.GetSecret() != "" {
			result.Secrets = append(result.Secrets, Secret{Kind: outcome.Kind, Name: outcome.Name, ID: outcome.ID, Value: response.Msg.GetSecret(), ExpiresAt: response.Msg.GetExpiresAt()})
		}
		return nil
	case *adminv1.CreateEnrollmentGrantRequest:
		response, err := client.CreateEnrollmentGrant(ctx, connect.NewRequest(r))
		if err != nil {
			return err
		}
		outcome.ID = response.Msg.GetGrantId()
		if response.Msg.GetSecretDeliveryUnknown() {
			outcome.Status = "pending"
			outcome.Detail = "secret delivery unknown; revoke and issue under a new name"
		} else if response.Msg.GetSecret() != "" {
			result.Secrets = append(result.Secrets, Secret{Kind: outcome.Kind, Name: outcome.Name, ID: outcome.ID, Value: response.Msg.GetSecret(), ExpiresAt: response.Msg.GetExpiresAt()})
		}
		return nil
	case *adminv1.AcceptAdvisoryFindingRequest:
		_, err := client.AcceptAdvisoryFinding(ctx, connect.NewRequest(r))
		return err
	default:
		return errors.New("orgapply: unsupported planned mutation")
	}
}

func applyAccount(ctx context.Context, client AccountClient, accounts map[string]*authv1.LocalAccount, desired *authv1.CreateAccountRequest, outcome *Outcome, result *Result) error {
	existing := accounts[desired.GetUsername()]
	if existing == nil {
		enrollment, err := client.CreateAccount(ctx, desired)
		if err != nil {
			return err
		}
		outcome.Status = "created"
		outcome.Detail = "enrollment required"
		outcome.ID = enrollment.GetAccountId()
		if enrollment.GetSecret() != "" {
			result.Secrets = append(result.Secrets, Secret{Kind: "account", Name: desired.GetUsername(), ID: enrollment.GetAccountId(), Value: enrollment.GetSecret(), ExpiresAt: enrollment.GetExpiresAt()})
		}
		return nil
	}
	current := &authv1.CreateAccountRequest{Username: existing.GetUsername(), Role: existing.GetRole(), BreakGlass: existing.GetBreakGlass(), Scopes: existing.GetScopes()}
	outcome.ID = existing.GetId()
	outcome.Detail = ""
	if proto.Equal(current, desired) && existing.GetEnabled() {
		outcome.Status = "unchanged"
		return nil
	}
	request := &authv1.UpdateAccountRequest{AccountId: existing.GetId(), Enabled: true, Role: desired.GetRole(), BreakGlass: desired.GetBreakGlass(), Scopes: desired.GetScopes()}
	if err := client.UpdateAccount(ctx, request); err != nil {
		return err
	}
	outcome.Status = "updated"
	return nil
}
