//go:build integration

package devlab

import (
	"context"
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/hex"
	"io"
	"net/http"
	"os"
	"slices"
	"testing"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
	authv1 "lindm/gen/lindm/auth/v1"
)

type assistanceTransitionBinary struct {
	SHA256      string `json:"sha256"`
	VCSRevision string `json:"vcs_revision,omitempty"`
	VCSModified string `json:"vcs_modified,omitempty"`
}

type assistanceTransitionActor struct {
	Stage             string                `json:"stage"`
	ID                string                `json:"id"`
	Role              string                `json:"role"`
	Permissions       []string              `json:"permissions"`
	Bindings          []*authv1.RoleBinding `json:"bindings"`
	ModeDenial        string                `json:"mode_denial,omitempty"`
	SessionHTTPStatus int                   `json:"session_http_status"`
}

func assistanceTransitionBinaryProof(t *testing.T, path string) assistanceTransitionBinary {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			t.Error(err)
		}
	}()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		t.Fatal(err)
	}
	proof := assistanceTransitionBinary{SHA256: hex.EncodeToString(hash.Sum(nil))}
	info, err := buildinfo.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, setting := range info.Settings {
		switch setting.Key {
		case "vcs.revision":
			proof.VCSRevision = setting.Value
		case "vcs.modified":
			proof.VCSModified = setting.Value
		}
	}
	return proof
}

func assistanceTransitionOwner(t *testing.T, ctx context.Context, fixture *AuthorityFixture) *OwnerSession {
	t.Helper()
	owner, err := fixture.OpenOwnerSession(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(owner.transport.CloseIdleConnections)
	return owner
}

func assistanceTransitionState(t *testing.T, ctx context.Context, owner *OwnerSession) *adminv1.AuthorizationState {
	t.Helper()
	response, err := owner.Admin.GetAuthorization(ctx, connect.NewRequest(&adminv1.GetAuthorizationRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	return response.Msg.GetAuthorization()
}

func assistanceTransitionUpdate(t *testing.T, ctx context.Context, owner *OwnerSession, request *adminv1.UpdateAuthorizationRequest) *adminv1.AuthorizationState {
	t.Helper()
	response, err := owner.Admin.UpdateAuthorization(ctx, connect.NewRequest(request))
	if err != nil {
		t.Fatal(err)
	}
	assistanceTransitionAssertState(t, response.Msg.GetAuthorization(), request.GetPolicy(), request.GetExpectedRevision()+1)
	return response.Msg.GetAuthorization()
}

func assistanceTransitionAssertState(t *testing.T, state *adminv1.AuthorizationState, policy *authv1.AuthorizationPolicy, revision uint64) {
	t.Helper()
	// Source/built-in fingerprint activation can fence authority without changing
	// the definition revision. Its updated_at is not a policy restore precondition.
	if !state.GetRuntime() || state.GetRevision() != revision || !proto.Equal(state.GetPolicy(), policy) {
		t.Fatal("runtime definition or its exact revision changed unexpectedly")
	}
}

func assistanceTransitionAudit(t *testing.T, ctx context.Context, owner *OwnerSession, reason string) *adminv1.AuditEvent {
	t.Helper()
	var result *adminv1.AuditEvent
	for page := ""; ; {
		response, err := owner.Admin.ListAuditEvents(ctx, connect.NewRequest(&adminv1.ListAuditEventsRequest{PageSize: 200, PageToken: page}))
		if err != nil {
			t.Fatal(err)
		}
		for _, event := range response.Msg.GetEvents() {
			if event.GetAction() != "identity.authorization_updated" || event.GetReason() != reason {
				continue
			}
			if result != nil || event.GetActorId() != owner.AccountID || event.GetResourceId() != "authorization" {
				t.Fatal("authorization write did not retain one correctly attributed audit event")
			}
			result = proto.CloneOf(event)
		}
		page = response.Msg.GetNextPageToken()
		if page == "" {
			break
		}
	}
	if result == nil {
		t.Fatal("authorization write has no audit event")
	}
	return result
}

func assistanceTransitionScopes() []*authv1.DeviceScope {
	return []*authv1.DeviceScope{{Labels: []string{"department/support"}}, {Labels: []string{"department/field"}}}
}

func assistanceTransitionEnrollActors(t *testing.T, ctx context.Context, fixture *AuthorityFixture, owner *OwnerSession, receipt *assistanceTransitionReceipt) []*OwnerSession {
	t.Helper()
	var actors []*OwnerSession
	for _, role := range receipt.Original.GetPolicy().GetRoles()[:2] {
		enrollment, err := owner.CreateAccount(ctx, &authv1.CreateAccountRequest{Username: role.GetName(), Role: role.GetName(), Scopes: assistanceTransitionScopes()})
		if err != nil {
			t.Fatal(err)
		}
		account, err := newLocalAccount(fixture.relyingPartyID(), role.GetName(), enrollment.GetAccountId())
		if err != nil {
			enrollment.Secret = ""
			t.Fatal(err)
		}
		t.Cleanup(func() {
			account.mu.Lock()
			clear(account.password)
			account.password, account.authenticator = nil, nil
			account.mu.Unlock()
		})
		actor, err := fixture.newLocalSession(account)
		if err != nil {
			enrollment.Secret = ""
			t.Fatal(err)
		}
		t.Cleanup(actor.transport.CloseIdleConnections)
		err = actor.localCeremonyRole(ctx, enrollment.GetSecret(), role.GetName())
		enrollment.Secret = ""
		if err != nil {
			t.Fatal(err)
		}
		assistanceTransitionLogin(t, ctx, actor, role.GetName())
		receipt.Actors = append(receipt.Actors, assistanceTransitionObserveActor(t, ctx, actor, "original", role.GetPermissions()))
		actors = append(actors, actor)
	}
	return actors
}

func assistanceTransitionLogin(t *testing.T, ctx context.Context, actor *OwnerSession, role string) {
	t.Helper()
	if err := actor.localCeremonyRole(ctx, "", role); err != nil {
		t.Fatal(err)
	}
}

func assistanceTransitionPrincipal(t *testing.T, ctx context.Context, actor *OwnerSession) (*authv1.SessionPrincipal, int) {
	t.Helper()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, actor.origin+"/auth/session", nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := actor.client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	body, readErr := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	closeErr := response.Body.Close()
	defer clear(body)
	if readErr != nil || closeErr != nil {
		t.Fatal("cannot read actual transition actor session")
	}
	if response.StatusCode == http.StatusUnauthorized {
		return nil, response.StatusCode
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("unexpected transition session HTTP status %d", response.StatusCode)
	}
	principal := new(authv1.SessionPrincipal)
	if err := protojson.Unmarshal(body, principal); err != nil {
		t.Fatal("cannot decode actual transition actor session")
	}
	principal.CsrfToken = ""
	return principal, response.StatusCode
}

func assistanceTransitionObserveActor(t *testing.T, ctx context.Context, actor *OwnerSession, stage string, permissions []string) assistanceTransitionActor {
	t.Helper()
	principal, status := assistanceTransitionPrincipal(t, ctx, actor)
	if status != http.StatusOK || principal.GetId() != actor.AccountID || principal.GetRole() != actor.local.username || principal.GetBreakGlass() || principal.GetServiceAccount() {
		t.Fatal("actual transition actor identity changed")
	}
	actual, expected := slices.Clone(principal.GetPermissions()), slices.Clone(permissions)
	slices.Sort(actual)
	slices.Sort(expected)
	if !slices.Equal(actual, expected) || len(principal.GetBindings()) != 1 {
		t.Fatal("actual transition actor permissions changed outside the explicit replacement")
	}
	binding := principal.GetBindings()[0]
	if binding.GetRole() != actor.local.username || !equalAssistanceTransitionScopes(binding.GetScopes(), assistanceTransitionScopes()) {
		t.Fatal("permission replacement changed the actual local actor device scopes")
	}
	return assistanceTransitionActor{Stage: stage, ID: principal.GetId(), Role: principal.GetRole(), Permissions: principal.GetPermissions(), Bindings: principal.GetBindings(), SessionHTTPStatus: status}
}

func equalAssistanceTransitionScopes(actual, expected []*authv1.DeviceScope) bool {
	return slices.EqualFunc(actual, expected, func(a, b *authv1.DeviceScope) bool { return proto.Equal(a, b) })
}

func assistanceTransitionAssertWithdrawn(t *testing.T, ctx context.Context, actors []*OwnerSession, receipt *assistanceTransitionReceipt, stage string) {
	t.Helper()
	for index, actor := range actors {
		var observed assistanceTransitionActor
		if index == 0 {
			// A removed role may deny login or authenticate with zero grants; neither
			// may fall back to the display role or bootstrap role definition.
			loginErr := actor.localCeremonyRole(ctx, "", actor.local.username)
			principal, status := assistanceTransitionPrincipal(t, ctx, actor)
			if status == http.StatusOK && (loginErr != nil || principal.GetId() != actor.AccountID || principal.GetRole() != actor.local.username || len(principal.GetPermissions()) != 0) {
				t.Fatal("removed custom role retained or broadened authority")
			}
			observed = assistanceTransitionActor{Stage: stage, ID: actor.AccountID, Role: actor.local.username, Permissions: principal.GetPermissions(), Bindings: principal.GetBindings(), SessionHTTPStatus: status}
		} else {
			assistanceTransitionLogin(t, ctx, actor, actor.local.username)
			observed = assistanceTransitionObserveActor(t, ctx, actor, stage, receipt.Interim.GetPolicy().GetRoles()[0].GetPermissions())
		}
		expectedCode := connect.CodePermissionDenied
		if observed.SessionHTTPStatus == http.StatusUnauthorized {
			expectedCode = connect.CodeUnauthenticated
		}
		_, err := actor.Admin.CreateAssistanceSession(ctx, connect.NewRequest(&adminv1.CreateAssistanceSessionRequest{RequestId: uuid.NewString(), DeviceId: uuid.NewString(), Mode: agentv1.AssistanceMode_ASSISTANCE_MODE_VIEW, Reason: "prove explicit permission deny window", MaxDurationSeconds: 60}))
		if connect.CodeOf(err) != expectedCode {
			t.Fatalf("deny-window actor reached device/session admission: %v", err)
		}
		observed.ModeDenial = connect.CodeOf(err).String()
		receipt.Actors = append(receipt.Actors, observed)
	}
}

func assistanceTransitionAssertAccounts(t *testing.T, ctx context.Context, owner *OwnerSession, actors []*OwnerSession) {
	t.Helper()
	response, err := owner.ListAccounts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, actor := range actors {
		var actual *authv1.LocalAccount
		for _, account := range response.GetAccounts() {
			if account.GetId() == actor.AccountID {
				actual = account
			}
		}
		if actual == nil || !actual.GetEnabled() || !actual.GetEnrolled() || actual.GetRole() != actor.local.username || !equalAssistanceTransitionScopes(actual.GetScopes(), assistanceTransitionScopes()) {
			t.Fatal("policy-only transition changed the recorded account role, identity or scopes")
		}
	}
}
