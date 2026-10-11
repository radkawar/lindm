package orgapply

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	authv1 "lindm/gen/lindm/auth/v1"
	orgv1 "lindm/gen/lindm/org/v1"
)

type browserAccountsFixture struct {
	admin           *fakeAdmin
	accounts        []*authv1.LocalAccount
	creates         int
	stopAfterPolicy bool
}

func (f *browserAccountsFixture) CheckSession(context.Context) error {
	if f.stopAfterPolicy && f.admin.authorization.GetRuntime() {
		return errors.New("browser session revoked by runtime authorization update")
	}
	return nil
}

func (f *browserAccountsFixture) ListAccounts(context.Context) (*authv1.ListAccountsResponse, error) {
	return &authv1.ListAccountsResponse{Accounts: f.accounts}, nil
}
func (f *browserAccountsFixture) CreateAccount(_ context.Context, request *authv1.CreateAccountRequest) (*authv1.AccountEnrollment, error) {
	known := false
	for _, role := range f.admin.authorization.GetPolicy().GetRoles() {
		known = known || role.GetName() == request.GetRole()
	}
	if !known {
		return nil, errors.New("custom role has not been published")
	}
	f.creates++
	id := uuid.NewString()
	f.accounts = append(f.accounts, &authv1.LocalAccount{Id: id, Username: request.GetUsername(), Enabled: true, Role: request.GetRole(), Scopes: request.GetScopes()})
	return &authv1.AccountEnrollment{AccountId: id, Secret: "shown-once-test-secret"}, nil
}
func (f *browserAccountsFixture) UpdateAccount(_ context.Context, request *authv1.UpdateAccountRequest) error {
	for _, account := range f.accounts {
		if account.GetId() == request.GetAccountId() {
			account.Enabled, account.Role, account.Scopes, account.BreakGlass = request.GetEnabled(), request.GetRole(), request.GetScopes(), request.GetBreakGlass()
			return nil
		}
	}
	return errors.New("account absent")
}

func TestBrowserOrganizationPublishesRolesBeforeAccountIssuance(t *testing.T) {
	client := newFakeAdmin()
	accounts := &browserAccountsFixture{admin: client}
	spec := &orgv1.Organization{Name: "browser", Authorization: &authv1.AuthorizationPolicy{Roles: []*authv1.RoleDefinition{{Name: "support", Permissions: []string{"fleet.read"}}}}, Accounts: []*authv1.CreateAccountRequest{{Username: "support", Role: "support"}}}
	plan, err := Plan(t.Context(), client, spec)
	if err != nil {
		t.Fatal(err)
	}
	if err := plan.PreviewAccounts(t.Context(), accounts); err != nil {
		t.Fatal(err)
	}
	if accounts.creates != 0 || len(client.requests) != 0 {
		t.Fatal("preview mutated authority")
	}
	first, err := Apply(t.Context(), client, plan, Options{AccountClient: accounts})
	if err != nil || accounts.creates != 1 || len(first.Secrets) != 1 {
		t.Fatalf("role/account apply failed: %v %+v", err, first)
	}
	second, err := Plan(t.Context(), client, proto.CloneOf(spec))
	if err != nil {
		t.Fatal(err)
	}
	result, err := Apply(t.Context(), client, second, Options{AccountClient: accounts})
	if err != nil || len(result.Secrets) != 0 || accounts.creates != 1 {
		t.Fatalf("repeat issued another secret: %v %+v", err, result)
	}
	for _, outcome := range result.Outcomes {
		if outcome.Status != "unchanged" {
			t.Fatalf("repeat drift: %+v", outcome)
		}
	}
}

func TestBrowserOrganizationStopsAfterRuntimeRevokesSession(t *testing.T) {
	client := newFakeAdmin()
	accounts := &browserAccountsFixture{admin: client, stopAfterPolicy: true}
	spec := &orgv1.Organization{Name: "browser", Authorization: &authv1.AuthorizationPolicy{}, Accounts: []*authv1.CreateAccountRequest{{Username: "must-not-create", Role: "auditor"}}}
	plan, err := Plan(t.Context(), client, spec)
	if err != nil {
		t.Fatal(err)
	}
	result, err := Apply(t.Context(), client, plan, Options{AccountClient: accounts})
	if err == nil || accounts.creates != 0 || len(result.Secrets) != 0 {
		t.Fatalf("revoked browser capability continued import: %v %+v", err, result)
	}
	if !client.authorization.GetRuntime() || len(result.Outcomes) != 1 || result.Outcomes[0].Kind != "authorization" {
		t.Fatalf("committed policy outcome not retained: %+v", result)
	}
}

func TestBrowserReviewDigestBindsExistingAccountAuthority(t *testing.T) {
	client := newFakeAdmin()
	accounts := &browserAccountsFixture{admin: client, accounts: []*authv1.LocalAccount{{Id: uuid.NewString(), Username: "support", Enabled: true, Role: "helpdesk"}}}
	spec := &orgv1.Organization{Name: "browser", Accounts: []*authv1.CreateAccountRequest{{Username: "support", Role: "auditor"}}}
	plan, err := Plan(t.Context(), client, spec)
	if err != nil {
		t.Fatal(err)
	}
	if err := plan.PreviewAccounts(t.Context(), accounts); err != nil {
		t.Fatal(err)
	}
	before, err := plan.Digest()
	if err != nil {
		t.Fatal(err)
	}
	accounts.accounts[0].Role = "owner"
	if err := plan.PreviewAccounts(t.Context(), accounts); err != nil {
		t.Fatal(err)
	}
	after, err := plan.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(before, after) {
		t.Fatal("review accepted changed account authority")
	}
}
