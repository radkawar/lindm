package identity

import (
	"context"

	"github.com/google/uuid"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	authv1 "lindm/gen/lindm/auth/v1"
	"lindm/internal/auditkind"
	"lindm/internal/identity/identitydb"
)

// BrowserAccounts is an in-process adapter for organization apply. It accepts
// only a live browser session created by RequireSession, never CLI credentials.
type BrowserAccounts struct{ service *Service }

func (s *Service) BrowserAccounts() *BrowserAccounts { return &BrowserAccounts{service: s} }

func (c *BrowserAccounts) CheckSession(ctx context.Context) error {
	return c.transaction(ctx, func(*identitydb.Queries, Principal) error { return nil })
}

func (c *BrowserAccounts) transaction(ctx context.Context, fn func(*identitydb.Queries, Principal) error) error {
	return c.service.accountTransaction(ctx, func(q *identitydb.Queries, actor Principal) error {
		if err := c.service.checkAuthenticatedSession(ctx, q, actor.ID, true); err != nil {
			return err
		}
		return fn(q, actor)
	})
}

func (c *BrowserAccounts) ListAccounts(ctx context.Context) (*authv1.ListAccountsResponse, error) {
	response := new(authv1.ListAccountsResponse)
	err := c.transaction(ctx, func(q *identitydb.Queries, _ Principal) error {
		policy, err := c.service.currentPolicy(ctx, q)
		if err != nil {
			return err
		}
		response.Roles = append([]string(nil), policy.names...)
		rows, err := q.ListLocalAccounts(ctx)
		if err != nil {
			return c.service.dbErr(err)
		}
		for _, row := range rows {
			binding := new(authv1.RoleBinding)
			if err := protojson.Unmarshal(row.ScopeBinding, binding); err != nil {
				return errStore
			}
			response.Accounts = append(response.Accounts, &authv1.LocalAccount{Id: row.ID.String(), Username: row.Username, Role: row.Role, Enabled: row.Enabled, BreakGlass: row.BreakGlass, Enrolled: row.Enrolled, Scopes: binding.GetScopes()})
		}
		return nil
	})
	return response, err
}

func (c *BrowserAccounts) CreateAccount(ctx context.Context, request *authv1.CreateAccountRequest) (*authv1.AccountEnrollment, error) {
	var enrollment Enrollment
	err := c.transaction(ctx, func(q *identitydb.Queries, actor Principal) error {
		var err error
		enrollment, err = c.service.createLocalAccount(ctx, q, request)
		if err != nil {
			return err
		}
		return c.service.insertAudit(ctx, q, &actor.ID, auditkind.IdentityLocalAccountCreated, principalResource(enrollment.AccountID), "")
	})
	if err != nil {
		return nil, err
	}
	return enrollmentProto(enrollment), nil
}

func (c *BrowserAccounts) UpdateAccount(ctx context.Context, request *authv1.UpdateAccountRequest) error {
	if request == nil || c.service.rules.Validate(request) != nil {
		return ErrPolicyInvalid
	}
	id, _ := uuid.Parse(request.GetAccountId())
	return c.transaction(ctx, func(q *identitydb.Queries, actor Principal) error {
		policy, err := c.service.currentPolicy(ctx, q)
		if err != nil {
			return err
		}
		if policy.role(request.GetRole()) == nil {
			return ErrAuthorizationDenied
		}
		if _, err := q.GetPrincipalForUpdate(ctx, id); err != nil {
			return c.service.dbErr(err)
		}
		account, err := q.GetLocalAccount(ctx, id)
		if err != nil {
			return c.service.dbErr(err)
		}
		previous := new(authv1.RoleBinding)
		if err := protojson.Unmarshal(account.ScopeBinding, previous); err != nil {
			return errStore
		}
		binding := &authv1.RoleBinding{Scopes: request.GetScopes()}
		encoded, err := protojson.Marshal(binding)
		if err != nil {
			return err
		}
		if account.Enabled == request.GetEnabled() && account.Role == request.GetRole() && account.BreakGlass == request.GetBreakGlass() && proto.Equal(previous, binding) {
			return nil
		}
		if err := q.UpdateLocalAccount(ctx, identitydb.UpdateLocalAccountParams{ID: id, Enabled: request.GetEnabled(), Role: request.GetRole(), BreakGlass: request.GetBreakGlass(), ScopeBinding: encoded}); err != nil {
			return c.service.dbErr(err)
		}
		role := request.GetRole()
		if !request.GetEnabled() {
			role = ""
		}
		if err := c.service.invalidateLocalAccount(ctx, q, id, role); err != nil {
			return err
		}
		return c.service.insertSystemAudit(ctx, q, &actor.ID, auditkind.IdentityLocalAccountUpdated, principalResource(id), "sessions and pending authority revoked")
	})
}
