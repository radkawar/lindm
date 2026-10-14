// SPDX-License-Identifier: Apache-2.0

//go:build integration

package identity

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"testing"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	adminv1 "lindm/gen/lindm/admin/v1"
	authv1 "lindm/gen/lindm/auth/v1"
	"lindm/internal/identity/identitydb"
)

func runtimeOwner(t *testing.T) (*Service, context.Context, string) {
	t.Helper()
	s, ctx, _ := localIntegrationService(t)
	enrollment, err := bootstrapLocalOwner(t, s, ctx, "owner")
	if err != nil {
		t.Fatal(err)
	}
	authenticator := localAuthenticator(t)
	enrollLocal(t, s, ctx, enrollment, authenticator)
	cookie := loginLocal(t, s, ctx, "owner", "", authenticator)
	principal, decision, err := s.resolve(ctx, cookie)
	if err != nil || decision.Kind != accessOK {
		t.Fatalf("owner login: %v %+v", err, decision)
	}
	return s, s.withAuthenticatedSession(ctx, cookie, principal), cookie
}

func updateRuntime(t *testing.T, ctx context.Context, s *Service, revision uint64, policy *authv1.AuthorizationPolicy) (*adminv1.UpdateAuthorizationRequest, *adminv1.AuthorizationState) {
	t.Helper()
	request := &adminv1.UpdateAuthorizationRequest{RequestId: uuid.NewString(), ExpectedRevision: revision, Policy: policy, Reason: "change organization access"}
	state, err := s.UpdateAuthorization(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	return request, state
}

func TestRuntimeAuthorizationDurabilityReplayAndRevocation(t *testing.T) {
	s, ctx, ownerCookie := runtimeOwner(t)
	bootstrap, err := s.GetAuthorization(ctx)
	if err != nil || bootstrap.GetRuntime() || bootstrap.GetRevision() != 0 {
		t.Fatalf("bootstrap state=%v err=%v", bootstrap, err)
	}
	invalid := &adminv1.UpdateAuthorizationRequest{RequestId: uuid.NewString(), Policy: &authv1.AuthorizationPolicy{GroupBindings: []*authv1.GroupBinding{{Group: "/directory-admins", Role: "owner"}}}, Reason: "reject directory grant in local mode"}
	if _, err := s.UpdateAuthorization(ctx, invalid); !errors.Is(err, ErrPolicyInvalid) {
		t.Fatalf("local source accepted directory bindings: %v", err)
	}
	policy := &authv1.AuthorizationPolicy{Roles: []*authv1.RoleDefinition{{Name: "support", Permissions: []string{"fleet.read", "profiles.manage"}}}}
	_, first := updateRuntime(t, ctx, s, 0, policy)
	enrollment, err := s.BrowserAccounts().CreateAccount(ctx, &authv1.CreateAccountRequest{Username: "support", Role: "support"})
	if err != nil {
		t.Fatal(err)
	}
	id, _ := uuid.Parse(enrollment.GetAccountId())
	authenticator := localAuthenticator(t)
	enrollLocal(t, s, ctx, Enrollment{AccountID: id, Secret: enrollment.GetSecret()}, authenticator)
	cookie := loginLocal(t, s, ctx, "support", "", authenticator)
	grant, err := s.AuthorizeFresh(ctx, id, PermissionManageProfiles)
	if err != nil {
		t.Fatal(err)
	}
	peer, err := New(ctx, s.pool, Config{Local: true, PublicURL: localTestOrigin})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := peer.Close(); err != nil {
			t.Error(err)
		}
	})
	actor, _ := PrincipalFromContext(ctx)
	peerCtx := peer.withAuthenticatedSession(ctx, ownerCookie, actor)
	observed, err := peer.GetAuthorization(peerCtx)
	if err != nil || !proto.Equal(first, observed) {
		t.Fatalf("replica policy=%v err=%v", observed, err)
	}
	next := proto.CloneOf(policy)
	next.Roles[0].Permissions = []string{"fleet.read"}
	next.ApprovalRequiredPermissions = []string{"resources.assign"}
	request, changed := updateRuntime(t, peerCtx, peer, first.GetRevision(), next)
	if changed.GetRevision() != 2 {
		t.Fatal("runtime revision did not advance")
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.LockAuthorization(ctx, tx, grant, PermissionManageProfiles); !errors.Is(err, ErrAuthorizationChanged) {
		t.Fatalf("stale replica grant=%v", err)
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AuthorizeFresh(ctx, id, PermissionManageProfiles); !errors.Is(err, ErrAuthorizationDenied) {
		t.Fatalf("removed permission=%v", err)
	}
	if response := authAccountRequest(t, s, http.MethodGet, "/auth/session", cookie, nil); response.Code != http.StatusUnauthorized {
		t.Fatalf("old session remained usable: %d", response.Code)
	}
	if response := authAccountRequest(t, s, http.MethodGet, "/auth/session", ownerCookie, nil); response.Code != http.StatusOK {
		t.Fatalf("immutable owner recovery lost: %d", response.Code)
	}
	replayed, err := s.UpdateAuthorization(ctx, request)
	if err != nil || !proto.Equal(changed, replayed) {
		t.Fatalf("exact replay=%v err=%v", replayed, err)
	}
	mutated := proto.CloneOf(request)
	mutated.Reason = "changed request payload"
	if _, err := s.UpdateAuthorization(ctx, mutated); !errors.Is(err, ErrPolicyReplay) {
		t.Fatalf("changed replay=%v", err)
	}
	stale := proto.CloneOf(request)
	stale.RequestId = uuid.NewString()
	if _, err := s.UpdateAuthorization(ctx, stale); !errors.Is(err, ErrPolicyConflict) {
		t.Fatalf("stale CAS=%v", err)
	}
	fresh, err := s.AuthorizeFresh(ctx, actor.ID, PermissionAssignResources)
	if err != nil || !fresh.ApprovalRequired(PermissionAssignResources) {
		t.Fatalf("runtime approval policy not captured: %v", err)
	}
	var count int
	if err := s.pool.QueryRow(ctx, "SELECT count(*) FROM audit_events WHERE action = 'identity.authorization_updated'").Scan(&count); err != nil || count != 2 {
		t.Fatalf("audit count=%d err=%v", count, err)
	}
	_, empty := updateRuntime(t, ctx, s, 2, &authv1.AuthorizationPolicy{})
	restarted, err := New(ctx, s.pool, Config{Local: true, PublicURL: localTestOrigin, Policy: policy})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := restarted.Close(); err != nil {
			t.Error(err)
		}
	})
	afterRestart, err := restarted.GetAuthorization(restarted.withAuthenticatedSession(ctx, ownerCookie, actor))
	if err != nil || !proto.Equal(empty, afterRestart) || !afterRestart.GetRuntime() {
		t.Fatalf("bootstrap overwrote empty runtime policy: %v %v", afterRestart, err)
	}
	// Restoring a grant never restores an earlier browser credential.
	updateRuntime(t, ctx, s, 3, policy)
	if response := authAccountRequest(t, s, http.MethodGet, "/auth/session", cookie, nil); response.Code != http.StatusUnauthorized {
		t.Fatal("restore resurrected revoked session")
	}
}

func TestRuntimeAuthorizationSerializesConcurrentWriters(t *testing.T) {
	s, ctx, _ := runtimeOwner(t)
	var group sync.WaitGroup
	results := make(chan error, 2)
	for _, name := range []string{"one", "two"} {
		group.Go(func() {
			_, err := s.UpdateAuthorization(ctx, &adminv1.UpdateAuthorizationRequest{RequestId: uuid.NewString(), Policy: &authv1.AuthorizationPolicy{Roles: []*authv1.RoleDefinition{{Name: name, Permissions: []string{"fleet.read"}}}}, Reason: "concurrent policy replacement"})
			results <- err
		})
	}
	group.Wait()
	close(results)
	accepted := 0
	for err := range results {
		if err == nil {
			accepted++
			continue
		}
		if !errors.Is(err, ErrPolicyConflict) && !errors.Is(err, ErrAuthorizationChanged) {
			t.Fatal(err)
		}
	}
	if accepted != 1 {
		t.Fatalf("accepted %d writers", accepted)
	}
	state, err := s.GetAuthorization(ctx)
	if err != nil || state.GetRevision() != 1 {
		t.Fatalf("state=%v err=%v", state, err)
	}
}

func TestBrowserAccountCapabilityRejectsMissingAndCLIProof(t *testing.T) {
	s, ctx, cookie := runtimeOwner(t)
	actor, _ := PrincipalFromContext(ctx)
	if _, err := s.BrowserAccounts().ListAccounts(WithPrincipal(t.Context(), actor)); !errors.Is(err, ErrAuthorizationDenied) {
		t.Fatalf("forged principal acquired browser capability: %v", err)
	}
	if _, err := s.pool.Exec(ctx, "UPDATE sessions SET kind = 'cli' WHERE token_hash = $1", sessionHash(cookie)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.BrowserAccounts().CreateAccount(ctx, &authv1.CreateAccountRequest{Username: "forbidden", Role: RoleAdmin}); !errors.Is(err, ErrAuthorizationDenied) {
		t.Fatalf("CLI acquired browser capability: %v", err)
	}
	if rows, err := identitydb.New(s.pool).ListLocalAccounts(ctx); err != nil || len(rows) != 1 {
		t.Fatalf("denied capability mutated accounts: %v %v", rows, err)
	}
}

func TestRuntimePolicyRequiresLiveSessionEvenOnReplay(t *testing.T) {
	s, ctx, cookie := runtimeOwner(t)
	request, _ := updateRuntime(t, ctx, s, 0, &authv1.AuthorizationPolicy{})
	actor, _ := PrincipalFromContext(ctx)
	if err := s.logout(ctx, cookie, actor.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetAuthorization(ctx); !errors.Is(err, ErrAuthorizationDenied) {
		t.Fatalf("revoked session read policy: %v", err)
	}
	if _, err := s.UpdateAuthorization(ctx, request); !errors.Is(err, ErrAuthorizationDenied) {
		t.Fatalf("revoked session replayed policy: %v", err)
	}
	if _, err := s.UpdateAuthorization(WithPrincipal(t.Context(), actor), request); !errors.Is(err, ErrAuthorizationDenied) {
		t.Fatalf("forged context replayed policy: %v", err)
	}
}

func TestRuntimeDeletedRoleFailsClosedForAssignedLocalAccount(t *testing.T) {
	s, ctx, _ := runtimeOwner(t)
	_, first := updateRuntime(t, ctx, s, 0, &authv1.AuthorizationPolicy{Roles: []*authv1.RoleDefinition{{Name: "assigned-reader", Permissions: []string{"fleet.read"}}}})
	enrollment, err := s.BrowserAccounts().CreateAccount(ctx, &authv1.CreateAccountRequest{Username: "assigned-reader", Role: "assigned-reader"})
	if err != nil {
		t.Fatal(err)
	}
	id, err := uuid.Parse(enrollment.GetAccountId())
	if err != nil {
		t.Fatal(err)
	}
	authenticator := localAuthenticator(t)
	enrollLocal(t, s, ctx, Enrollment{AccountID: id, Secret: enrollment.GetSecret()}, authenticator)
	cookie := loginLocal(t, s, ctx, "assigned-reader", "", authenticator)
	grant, err := s.AuthorizeFresh(ctx, id, PermissionReadFleet)
	if err != nil {
		t.Fatal(err)
	}
	updateRuntime(t, ctx, s, first.GetRevision(), &authv1.AuthorizationPolicy{})
	if _, err := s.AuthorizeFresh(ctx, id, PermissionReadFleet); !errors.Is(err, ErrAuthorizationDenied) {
		t.Fatalf("deleted role retained fresh authority: %v", err)
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.LockAuthorization(ctx, tx, grant, PermissionReadFleet); !errors.Is(err, ErrAuthorizationChanged) {
		t.Fatalf("deleted role retained captured authority: %v", err)
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	list, err := s.BrowserAccounts().ListAccounts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var assigned bool
	for _, account := range list.GetAccounts() {
		if account.GetId() == id.String() {
			assigned = account.GetRole() == "assigned-reader"
		}
	}
	if !assigned {
		t.Fatal("role deletion silently reassigned or deleted the account")
	}
	if response := authAccountRequest(t, s, http.MethodGet, "/auth/session", cookie, nil); response.Code != http.StatusUnauthorized {
		t.Fatalf("deleted-role browser session survived: %d", response.Code)
	}
}

func TestRuntimeScopedLocalOwnerDoesNotKeepRecoverySession(t *testing.T) {
	s, ctx, recoveryCookie := runtimeOwner(t)
	enrollment, err := s.BrowserAccounts().CreateAccount(ctx, &authv1.CreateAccountRequest{Username: "scoped-owner", Role: RoleOwner, Scopes: []*authv1.DeviceScope{{DeviceIds: []string{uuid.NewString()}}}})
	if err != nil {
		t.Fatal(err)
	}
	id, err := uuid.Parse(enrollment.GetAccountId())
	if err != nil {
		t.Fatal(err)
	}
	authenticator := localAuthenticator(t)
	enrollLocal(t, s, ctx, Enrollment{AccountID: id, Secret: enrollment.GetSecret()}, authenticator)
	cookie := loginLocal(t, s, ctx, "scoped-owner", "", authenticator)
	grant, err := s.AuthorizeFresh(ctx, id, PermissionManageAccounts)
	if err != nil {
		t.Fatal(err)
	}
	if unrestricted, _ := DeviceScopes(grant.Principal(), PermissionManageAccounts); unrestricted {
		t.Fatal("scoped owner fixture accidentally received unrestricted recovery authority")
	}
	if response := authAccountRequest(t, s, http.MethodGet, "/auth/session", cookie, nil); response.Code != http.StatusOK {
		t.Fatalf("scoped owner did not start with a live browser session: %d", response.Code)
	}
	updateRuntime(t, ctx, s, 0, &authv1.AuthorizationPolicy{})
	var revoked bool
	if err := s.pool.QueryRow(ctx, "SELECT revoked_at IS NOT NULL FROM sessions WHERE token_hash=$1", sessionHash(cookie)).Scan(&revoked); err != nil {
		t.Fatal(err)
	}
	if !revoked {
		t.Fatal("scoped local owner was mistaken for an unrestricted recovery owner")
	}
	if response := authAccountRequest(t, s, http.MethodGet, "/auth/session", cookie, nil); response.Code != http.StatusUnauthorized {
		t.Fatalf("scoped owner session remained usable: %d", response.Code)
	}
	if response := authAccountRequest(t, s, http.MethodGet, "/auth/session", recoveryCookie, nil); response.Code != http.StatusOK {
		t.Fatalf("unrestricted recovery owner was revoked: %d", response.Code)
	}
}
