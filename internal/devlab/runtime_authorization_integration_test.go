//go:build integration

package devlab

import (
	"bytes"
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	adminv1 "lindm/gen/lindm/admin/v1"
	authv1 "lindm/gen/lindm/auth/v1"
	orgv1 "lindm/gen/lindm/org/v1"
)

func TestRuntimeAuthorizationRealServer(t *testing.T) {
	binary, repository := nativeServer(t)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Minute)
	defer cancel()
	fixture, err := OpenLocalConsoleAuthorityFixture(ctx, repository, binary)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := fixture.Close(); err != nil {
			t.Error(err)
		}
	}()
	evidence, err := ExerciseRuntimeAuthorization(ctx, fixture, "")
	if err != nil {
		t.Fatal(err)
	}
	if evidence.InitialRuntime {
		t.Fatal("fresh fixture did not start with bootstrap-only authorization")
	}
	if evidence.FinalRevision <= evidence.InitialRevision || len(evidence.AuditEvents) == 0 || evidence.OwnerID == evidence.SecondHumanID {
		t.Fatal("missing observed runtime authority evidence")
	}
}

func TestOrganizationAccountCapabilityRechecksRealSession(t *testing.T) {
	binary, repository := nativeServer(t)
	ctx, cancel := context.WithTimeout(t.Context(), 4*time.Minute)
	defer cancel()
	fixture, err := OpenLocalConsoleAuthorityFixture(ctx, repository, binary)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := fixture.Close(); err != nil {
			t.Error(err)
		}
	}()
	owner, err := fixture.OpenOwnerSession(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := owner.Close(context.WithoutCancel(ctx)); err != nil {
			t.Error(err)
		}
	}()
	if err := owner.CheckSession(ctx); err != nil {
		t.Fatalf("live browser owner refused: %v", err)
	}
	other, err := fixture.OpenApproverSession(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := other.Close(context.WithoutCancel(ctx)); err != nil {
			t.Error(err)
		}
	}()
	if err := other.CheckSession(ctx); err != nil {
		t.Fatalf("independent browser owner refused: %v", err)
	}
	if err := owner.UpdateAccount(ctx, &authv1.UpdateAccountRequest{AccountId: other.AccountID, Enabled: false, Role: "owner"}); err != nil {
		t.Fatal(err)
	}
	if err := other.CheckSession(ctx); err == nil || !strings.Contains(err.Error(), "HTTP 401") {
		t.Fatalf("revoked browser capability was not refused: %v", err)
	}
	if err := owner.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if err := owner.CheckSession(ctx); err == nil || !strings.Contains(err.Error(), "HTTP 401") {
		t.Fatalf("closed browser capability was not refused: %v", err)
	}
}

// A local-primary policy deliberately cannot carry directory bindings. This
// separate test changes actual group-to-role resolution using real Keycloak
// code/PKCE sessions, not a dormant local mapping or seeded database authority.
func TestRuntimeAuthorizationDirectoryRealServer(t *testing.T) {
	binary, repository := nativeServer(t)
	ctx, cancel := context.WithTimeout(t.Context(), 4*time.Minute)
	defer cancel()
	fixture, err := OpenAuthorityFixture(ctx, repository, binary)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := fixture.Close(); err != nil {
			t.Error(err)
		}
	}()
	owner, err := fixture.OpenOwnerSession(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := owner.Close(context.WithoutCancel(ctx)); err != nil {
			t.Error(err)
		}
	}()
	second, err := OpenApprovalSession(ctx, repository, fixture)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := second.Close(context.WithoutCancel(ctx)); err != nil {
			t.Error(err)
		}
	}()
	if owner.AccountID == second.session.AccountID {
		t.Fatal("directory test did not authenticate two humans")
	}
	if _, err := second.session.Admin.ListAuditEvents(ctx, connect.NewRequest(&adminv1.ListAuditEventsRequest{})); err != nil {
		t.Fatal(err)
	}
	initial, err := owner.Admin.GetAuthorization(ctx, connect.NewRequest(&adminv1.GetAuthorizationRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	policy := &authv1.AuthorizationPolicy{Roles: []*authv1.RoleDefinition{{Name: "directory-reader", Permissions: []string{"fleet.read"}}}, GroupBindings: []*authv1.GroupBinding{{Group: "/mdm-admins", Role: "directory-reader"}}}
	request := &adminv1.UpdateAuthorizationRequest{RequestId: uuid.NewString(), ExpectedRevision: initial.Msg.GetAuthorization().GetRevision(), Policy: policy, Reason: "qualify actual Keycloak group to runtime role mapping"}
	updated, err := owner.Admin.UpdateAuthorization(ctx, connect.NewRequest(request))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := second.session.Admin.ListDevices(ctx, connect.NewRequest(&adminv1.ListDevicesRequest{})); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("old group authority survived mutation: %v", err)
	}
	if err := second.session.Close(ctx); err != nil {
		t.Fatal(err)
	}
	second.account.role = "directory-reader"
	second.session, err = openFixtureSession(ctx, repository, fixture.AdminAddress, second.account)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := second.session.Admin.ListDevices(ctx, connect.NewRequest(&adminv1.ListDevicesRequest{})); err != nil {
		t.Fatal(err)
	}
	if _, err := second.session.Admin.ListAuditEvents(ctx, connect.NewRequest(&adminv1.ListAuditEventsRequest{})); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("runtime reader retained admin audit permission: %v", err)
	}
	if _, err := second.session.Admin.UpdateAuthorization(ctx, connect.NewRequest(&adminv1.UpdateAuthorizationRequest{RequestId: uuid.NewString(), ExpectedRevision: updated.Msg.GetAuthorization().GetRevision(), Policy: policy, Reason: "directory non-owner policy mutation denial"})); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("directory non-owner updated authority: %v", err)
	}
	if err := fixture.Restart(ctx); err != nil {
		t.Fatal(err)
	}
	observed, err := owner.Admin.GetAuthorization(ctx, connect.NewRequest(&adminv1.GetAuthorizationRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(observed.Msg.GetAuthorization(), updated.Msg.GetAuthorization()) {
		t.Fatal("directory policy reverted to bootstrap on restart")
	}
	replay, err := owner.Admin.UpdateAuthorization(ctx, connect.NewRequest(request))
	if err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(replay.Msg, updated.Msg) {
		t.Fatal("directory mutation replay changed historical result")
	}
}

func TestOrganizationBrowserAuthorityBoundaryRealServer(t *testing.T) {
	binary, repository := nativeServer(t)
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	fixture, err := OpenLocalConsoleAuthorityFixture(ctx, repository, binary)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := fixture.Close(); err != nil {
			t.Error(err)
		}
	}()
	owner, err := fixture.OpenOwnerSession(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := owner.Close(context.WithoutCancel(ctx)); err != nil {
			t.Error(err)
		}
	}()
	organization := &orgv1.Organization{Name: "browser-boundary", Accounts: []*authv1.CreateAccountRequest{{Username: "reviewed-account", Role: "auditor"}}}
	body, err := protojson.Marshal(&orgv1.ApplyOrganizationRequest{Organization: organization})
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name, origin, csrf string
		body               []byte
	}{
		{name: "missing origin", csrf: owner.csrf, body: body},
		{name: "foreign origin", origin: "https://foreign.invalid", csrf: owner.csrf, body: body},
		{name: "missing csrf", origin: owner.origin, body: body},
		{name: "unknown field", origin: owner.origin, csrf: owner.csrf, body: []byte(`{"organization":{"name":"boundary"},"unknown":true}`)},
		{name: "apply without review", origin: owner.origin, csrf: owner.csrf, body: []byte(`{"organization":{"name":"boundary"},"apply":true}`)},
	} {
		t.Run(test.name, func(t *testing.T) {
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, owner.origin+"/auth/organization/apply", bytes.NewReader(test.body))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Origin", test.origin)
			req.Header.Set("X-CSRF-Token", test.csrf)
			response, err := owner.client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			if err := response.Body.Close(); err != nil {
				t.Fatal(err)
			}
			if response.StatusCode < 400 || response.StatusCode >= 500 {
				t.Fatalf("boundary request returned HTTP %d", response.StatusCode)
			}
		})
	}
	preview, err := owner.ApplyOrganization(ctx, &orgv1.ApplyOrganizationRequest{Organization: organization})
	if err != nil {
		t.Fatal(err)
	}
	organization.Accounts[0].Role = "operator"
	changed, err := owner.ApplyOrganization(ctx, &orgv1.ApplyOrganizationRequest{Organization: organization, Apply: true, ExpectedPlanSha256: preview.GetPlanSha256()})
	defer clearOrganizationSecrets(changed)
	if err == nil && changed.GetFailureCode() == "" {
		t.Fatal("changed organization applied using stale reviewed plan")
	}
	accounts, err := owner.ListAccounts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, account := range accounts.GetAccounts() {
		if account.GetUsername() == "reviewed-account" {
			t.Fatal("rejected organization review created account")
		}
	}
}
