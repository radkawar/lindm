// SPDX-License-Identifier: Apache-2.0

//go:build integration

package identity

import (
	"errors"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	authv1 "lindm/gen/lindm/auth/v1"
	"lindm/internal/identity/identitydb"
)

func TestDirectoryBindingScopeChangesAdvanceVersion(t *testing.T) {
	svc, ctx, conn := integrationService(t)
	definition := &authv1.AuthorizationPolicy{GroupBindings: []*authv1.GroupBinding{
		{Group: "/west", Role: RoleAdmin, Scopes: []*authv1.DeviceScope{{Labels: []string{"west"}}}},
		{Group: "/east", Role: RoleAdmin, Scopes: []*authv1.DeviceScope{{Labels: []string{"east"}}}},
	}}
	svc.policy = testPolicy(t, Config{Issuer: svc.issuer, Policy: definition})
	if err := svc.activatePolicy(ctx); err != nil {
		t.Fatal(err)
	}
	subject := uuid.New()
	row := insertObservedPrincipal(t, ctx, svc, subject)
	observation := directoryObs(subject, authorizationDatabaseTime(t, ctx, svc), true)
	observation.Groups = []string{"/west"}
	if err := applyAuthorizationObservation(ctx, svc, row.ID, observation); err != nil {
		t.Fatal(err)
	}
	grant := authorizationFromSnapshot(t, ctx, svc, row.ID)
	createAuthorizationEffects(t, ctx, conn)
	assertAuthorizationEffect(t, ctx, conn, svc, grant, nil)
	before := readAuthorizationState(t, ctx, conn, row.ID)
	observation.AcquiredAt = authorizationDatabaseTime(t, ctx, svc)
	observation.Groups = []string{"/east"}
	if err := applyAuthorizationObservation(ctx, svc, row.ID, observation); err != nil {
		t.Fatal(err)
	}
	after := readAuthorizationState(t, ctx, conn, row.ID)
	if after.Role != before.Role || after.Version != before.Version+1 {
		t.Fatalf("same-role scope transition did not invalidate: %v -> %v", before, after)
	}
	assertAuthorizationEffect(t, ctx, conn, svc, grant, ErrAuthorizationChanged)
	fresh := authorizationFromSnapshot(t, ctx, svc, row.ID)
	unrestricted, scopes := DeviceScopes(fresh.Principal(), PermissionRevokeDevice)
	if unrestricted || len(scopes) != 1 || scopes[0].Labels[0] != "east" {
		t.Fatal("new group inherited old target authority")
	}
}

func TestPolicyStartupInvalidatesVersionsAndStaleReplicas(t *testing.T) {
	for _, change := range []string{"role permissions", "mapping", "scope", "approval policy"} {
		t.Run(change, func(t *testing.T) {
			svc, ctx, conn := integrationService(t)
			definition := &authv1.AuthorizationPolicy{Roles: []*authv1.RoleDefinition{{Name: "custom", Permissions: []string{string(PermissionRevokeDevice), string(PermissionReadFleet)}}}, GroupBindings: []*authv1.GroupBinding{{Group: "/admins", Role: "custom", Scopes: []*authv1.DeviceScope{{Labels: []string{"west"}}}}}}
			svc.policy = testPolicy(t, Config{Issuer: svc.issuer, Policy: definition})
			if err := svc.activatePolicy(ctx); err != nil {
				t.Fatal(err)
			}
			_, grant := observedAuthorization(t, ctx, svc)
			before := readAuthorizationState(t, ctx, conn, grant.ActorID())
			peer := &Service{pool: svc.pool, issuer: svc.issuer, localIssuer: svc.localIssuer, now: svc.now}
			peer.policy = testPolicy(t, Config{Issuer: svc.issuer, Policy: definition})
			if err := peer.activatePolicy(ctx); err != nil {
				t.Fatal(err)
			}
			if got := readAuthorizationState(t, ctx, conn, grant.ActorID()); got.Version != before.Version {
				t.Fatal("identical replica invalidated authority")
			}
			next := proto.CloneOf(definition)
			switch change {
			case "role permissions":
				next.Roles[0].Permissions = append(next.Roles[0].Permissions, string(PermissionReadAudit))
			case "mapping":
				next.GroupBindings[0].Group = "/other"
			case "scope":
				next.GroupBindings[0].Scopes[0].Labels = []string{"east"}
			case "approval policy":
				next.ApprovalRequiredPermissions = []string{string(PermissionAssignResources)}
			}
			peer.policy = testPolicy(t, Config{Issuer: svc.issuer, Policy: next})
			if err := peer.activatePolicy(ctx); err != nil {
				t.Fatal(err)
			}
			after := readAuthorizationState(t, ctx, conn, grant.ActorID())
			if after.Version != before.Version+1 {
				t.Fatal("startup policy change did not durably invalidate actors")
			}
			if _, err := svc.loadSnapshot(ctx, grant.ActorID()); !errors.Is(err, ErrAuthorizationChanged) {
				t.Fatalf("old replica served authority: %v", err)
			}
			tx, err := svc.pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if err = svc.LockAuthorization(ctx, tx, grant, PermissionRevokeDevice); !errors.Is(err, ErrAuthorizationChanged) {
				t.Fatalf("old replica fenced grant=%v", err)
			}
			if err = tx.Rollback(ctx); err != nil {
				t.Fatal(err)
			}
			// Returning to the original policy must not resurrect an old version.
			if err = svc.activatePolicy(ctx); err != nil {
				t.Fatal(err)
			}
			if got := readAuthorizationState(t, ctx, conn, grant.ActorID()); got.Version != after.Version+1 {
				t.Fatal("policy rollback resurrected old authorization version")
			}
		})
	}
}

func TestLocalCustomRoleScopesPersistAndFence(t *testing.T) {
	_, ctx, pool := localIntegrationService(t)
	definition := &authv1.AuthorizationPolicy{Roles: []*authv1.RoleDefinition{{Name: "custom", Permissions: []string{string(PermissionReadFleet), string(PermissionAssignResources), string(PermissionManageAccounts)}}}}
	custom, err := New(ctx, pool, Config{Local: true, PublicURL: localTestOrigin, Policy: definition})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := custom.Close(); err != nil {
			t.Error(err)
		}
	})
	s := custom
	owner, err := s.BootstrapLocalOwner(ctx, "owner")
	if err != nil {
		t.Fatal(err)
	}
	auth := localAuthenticator(t)
	enrollLocal(t, s, ctx, owner, auth)
	cookie := loginLocal(t, s, ctx, "owner", "", auth)
	scopes := []*authv1.DeviceScope{{Labels: []string{"west"}}}
	response := authAccountRequest(t, s, http.MethodPost, "/auth/accounts/create", cookie, &authv1.CreateAccountRequest{Username: "scoped", Role: "custom", Scopes: scopes})
	if response.Code != http.StatusOK {
		t.Fatalf("create custom account: %d %s", response.Code, response.Body.String())
	}
	created := &authv1.AccountEnrollment{}
	if err := protojson.Unmarshal(response.Body.Bytes(), created); err != nil {
		t.Fatal(err)
	}
	actor, err := uuid.Parse(created.AccountId)
	if err != nil {
		t.Fatal(err)
	}
	scopedAuth := localAuthenticator(t)
	enrollLocal(t, s, ctx, Enrollment{AccountID: actor, Secret: created.Secret}, scopedAuth)
	scopedCookie := loginLocal(t, s, ctx, "scoped", "", scopedAuth)
	for _, test := range []struct {
		method, path string
		request      proto.Message
	}{
		{http.MethodGet, "/auth/accounts", nil},
		{http.MethodPost, "/auth/accounts/create", &authv1.CreateAccountRequest{Username: "forbidden", Role: RoleAdmin}},
		{http.MethodPost, "/auth/accounts/update", &authv1.UpdateAccountRequest{AccountId: owner.AccountID.String(), Enabled: true, Role: RoleHelpdesk}},
		{http.MethodPost, "/auth/accounts/reset", &authv1.ResetAccountRequest{AccountId: owner.AccountID.String()}},
	} {
		if denied := authAccountRequest(t, s, test.method, test.path, scopedCookie, test.request); denied.Code != http.StatusForbidden {
			t.Fatalf("scoped accounts.manage reached %s: %d", test.path, denied.Code)
		}
	}
	called := false
	forged := WithPrincipal(ctx, Principal{ID: actor, Role: RoleOwner})
	if err := s.accountTransaction(forged, func(*identitydb.Queries, Principal) error { called = true; return nil }); !errors.Is(err, ErrAuthorizationDenied) || called {
		t.Fatalf("fresh scoped fence trusted unrestricted context: %v", err)
	}
	grant, err := s.AuthorizeFresh(ctx, actor, PermissionAssignResources)
	if err != nil {
		t.Fatal(err)
	}
	if unrestricted, got := DeviceScopes(grant.Principal(), PermissionAssignResources); unrestricted || len(got) != 1 || !proto.Equal(got[0], scopes[0]) {
		t.Fatal("local scopes not captured")
	}
	if Authorize(grant.Principal(), PermissionReadRecoveryKeys) {
		t.Fatal("custom role inherited privileged builtin permission")
	}
	response = authAccountRequest(t, s, http.MethodGet, "/auth/accounts", cookie, nil)
	listed := &authv1.ListAccountsResponse{}
	if response.Code != http.StatusOK {
		t.Fatalf("list=%d", response.Code)
	}
	if err := protojson.Unmarshal(response.Body.Bytes(), listed); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, account := range listed.Accounts {
		if account.Id == actor.String() {
			found = len(account.Scopes) == 1 && proto.Equal(account.Scopes[0], scopes[0])
		}
	}
	if !found {
		t.Fatal("account API dropped persisted scopes")
	}
	response = authAccountRequest(t, s, http.MethodPost, "/auth/accounts/update", cookie, &authv1.UpdateAccountRequest{AccountId: actor.String(), Enabled: true, Role: "custom", Scopes: []*authv1.DeviceScope{{Labels: []string{"east"}}}})
	if response.Code != http.StatusNoContent {
		t.Fatalf("update=%d %s", response.Code, response.Body.String())
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.LockAuthorization(ctx, tx, grant, PermissionAssignResources); !errors.Is(err, ErrAuthorizationChanged) {
		t.Fatalf("scope edit retained pending authority: %v", err)
	}
	if err = tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	fresh, err := s.AuthorizeFresh(ctx, actor, PermissionAssignResources)
	if err != nil {
		t.Fatal(err)
	}
	if fresh.Version() <= grant.Version() || fresh.Principal().Bindings[0].Scopes[0].Labels[0] != "east" {
		t.Fatal("new local scope not durable")
	}
	if err := s.withTx(ctx, func(q *identitydb.Queries) error {
		_, err := s.createLocalAccount(ctx, q, &authv1.CreateAccountRequest{Username: "invalid", Role: "absent"})
		return err
	}); !errors.Is(err, ErrAuthorizationDenied) {
		t.Fatalf("unknown account role allowed: %v", err)
	}
}
