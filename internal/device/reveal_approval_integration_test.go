//go:build integration

package device

import (
	"testing"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/encoding/protojson"

	adminv1 "lindm/gen/lindm/admin/v1"
	authv1 "lindm/gen/lindm/auth/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/identity"
)

// enrolledAdmin inserts a local human account in the state account creation
// plus enrollment leaves it: enabled, holding a registered sign-in credential.
// Scopes, when given, restrict every grant of its role to them.
func enrolledAdmin(t *testing.T, svc *Service, role string, scopes ...*authv1.DeviceScope) identity.Principal {
	t.Helper()
	ctx := t.Context()
	conn, err := svc.Pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Release()
	principal := insertPrincipal(t, ctx, conn.Conn(), role)
	if len(scopes) != 0 {
		binding, err := protojson.Marshal(&authv1.RoleBinding{Scopes: scopes})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := conn.Exec(ctx, "UPDATE local_accounts SET scope_binding=$2 WHERE id=$1", principal.ID, binding); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := conn.Exec(ctx, "INSERT INTO local_credentials (credential_id, account_id, credential_json) VALUES ($1, $2, '{}')", principal.ID[:], principal.ID); err != nil {
		t.Fatal(err)
	}
	return principal
}

func execSQL(t *testing.T, svc *Service, query string, args ...any) {
	t.Helper()
	if _, err := svc.Pool.Exec(t.Context(), query, args...); err != nil {
		t.Fatal(err)
	}
}

func (f *secretFixture) demoSecret(t *testing.T) *adminv1.SecretSummary {
	t.Helper()
	return f.create(t, &adminv1.CreateSecretRequest{RequestId: uuid.NewString(), Purpose: resourcev1.SecretPurpose_SECRET_PURPOSE_DIRECTORY_JOIN, DisplayName: "domain join", Material: opaqueMaterial("domain-join-credential"), Reason: "provision join account"})
}

// secretRule is the decision the console shows the step-up owner next to Reveal.
func (f *secretFixture) secretRule(t *testing.T, secretID string) *adminv1.RevealApproval {
	t.Helper()
	response, err := f.svc.GetSecret(f.stepUp, connect.NewRequest(&adminv1.GetSecretRequest{SecretId: secretID}))
	if err != nil {
		t.Fatal(err)
	}
	return response.Msg.GetRevealApproval()
}

func (f *secretFixture) assertRule(t *testing.T, secretID string, want adminv1.RevealApprovalRule) {
	t.Helper()
	got := f.secretRule(t, secretID)
	required := want != adminv1.RevealApprovalRule_REVEAL_APPROVAL_RULE_ONLY_APPROVER
	if got.GetRule() != want || got.GetRequired() != required {
		t.Fatalf("reveal rule = %v required=%t, want %v required=%t", got.GetRule(), got.GetRequired(), want, required)
	}
}

func (f *secretFixture) revealRequest(secretID string) *adminv1.RevealSecretRequest {
	return &adminv1.RevealSecretRequest{RequestId: uuid.NewString(), SecretId: secretID, Version: 1, Reason: "join a replacement domain controller"}
}

// revealAlone reveals without an approval and requires the server to agree.
func (f *secretFixture) revealAlone(t *testing.T, secretID string) {
	t.Helper()
	revealed, err := f.svc.RevealSecret(f.stepUp, connect.NewRequest(f.revealRequest(secretID)))
	if err != nil || string(revealed.Msg.GetMaterial().GetOpaque()) != "domain-join-credential" {
		t.Fatalf("sole administrator reveal: %v", err)
	}
}

func (f *secretFixture) refusedAlone(t *testing.T, secretID string) {
	t.Helper()
	if _, err := f.svc.RevealSecret(f.stepUp, connect.NewRequest(f.revealRequest(secretID))); rpcReason(err) != "approval_required" {
		t.Fatalf("reveal without approval while another administrator can approve: %v", err)
	}
}

func (f *secretFixture) requestApproval(t *testing.T, request *adminv1.RevealSecretRequest) string {
	t.Helper()
	created, err := f.svc.CreateApproval(f.stepUp, connect.NewRequest(&adminv1.CreateApprovalRequest{LifetimeSeconds: 600, Payload: &adminv1.CreateApprovalRequest_RevealSecret{RevealSecret: request}}))
	if err != nil {
		t.Fatal(err)
	}
	return created.Msg.GetApproval().GetId()
}

func approve(t *testing.T, svc *Service, approver identity.Principal, id string) error {
	t.Helper()
	_, err := svc.ApproveApproval(identity.WithPrincipal(t.Context(), approver), connect.NewRequest(&adminv1.ApproveApprovalRequest{ApprovalId: id, Reason: "independently reviewed reveal"}))
	return err
}

func TestRevealApprovalSoleAdminRevealsAlone(t *testing.T) {
	f := newSecretFixture(t)
	summary := f.demoSecret(t)
	// Neither an account that never enrolled a credential nor a demoted one can
	// approve, so neither makes the owner wait for an approval.
	unenrolled := enrolledAdmin(t, f.svc, identity.RoleAdmin)
	execSQL(t, f.svc, "DELETE FROM local_credentials WHERE account_id=$1", unenrolled.ID)
	enrolledAdmin(t, f.svc, identity.RoleOperator)
	f.assertRule(t, summary.GetSecretId(), adminv1.RevealApprovalRule_REVEAL_APPROVAL_RULE_ONLY_APPROVER)
	f.revealAlone(t, summary.GetSecretId())
}

func TestRevealApprovalAnotherAdminRequiresApproval(t *testing.T) {
	f := newSecretFixture(t)
	summary := f.demoSecret(t)
	second := enrolledAdmin(t, f.svc, identity.RoleAdmin)
	f.assertRule(t, summary.GetSecretId(), adminv1.RevealApprovalRule_REVEAL_APPROVAL_RULE_ANOTHER_APPROVER)
	f.refusedAlone(t, summary.GetSecretId())
	request := f.revealRequest(summary.GetSecretId())
	id := f.requestApproval(t, request)
	// The requester never approves their own reveal, whatever the rule.
	if err := approve(t, f.svc, f.owner, id); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("requester approved own reveal: %v", err)
	}
	if err := approve(t, f.svc, second, id); err != nil {
		t.Fatal(err)
	}
	request.ApprovalId = id
	revealed, err := f.svc.RevealSecret(f.stepUp, connect.NewRequest(request))
	if err != nil || string(revealed.Msg.GetMaterial().GetOpaque()) != "domain-join-credential" {
		t.Fatalf("approved reveal: %v", err)
	}
}

func TestRevealApprovalApproverDisabledOrRemovedBeforeRequest(t *testing.T) {
	for _, change := range []struct{ name, query string }{
		{"disabled", "UPDATE local_accounts SET enabled=false WHERE id=$1"},
		{"removed from admin role", "UPDATE local_accounts SET role='operator' WHERE id=$1"},
		{"credentials reset", "DELETE FROM local_credentials WHERE account_id=$1"},
	} {
		t.Run(change.name, func(t *testing.T) {
			f := newSecretFixture(t)
			summary := f.demoSecret(t)
			second := enrolledAdmin(t, f.svc, identity.RoleAdmin)
			f.assertRule(t, summary.GetSecretId(), adminv1.RevealApprovalRule_REVEAL_APPROVAL_RULE_ANOTHER_APPROVER)
			execSQL(t, f.svc, change.query, second.ID)
			f.assertRule(t, summary.GetSecretId(), adminv1.RevealApprovalRule_REVEAL_APPROVAL_RULE_ONLY_APPROVER)
			f.revealAlone(t, summary.GetSecretId())
		})
	}
}

func TestRevealApprovalApproverDisabledAtDecideTime(t *testing.T) {
	f := newSecretFixture(t)
	summary := f.demoSecret(t)
	second := enrolledAdmin(t, f.svc, identity.RoleAdmin)
	request := f.revealRequest(summary.GetSecretId())
	id := f.requestApproval(t, request)
	execSQL(t, f.svc, "UPDATE local_accounts SET enabled=false WHERE id=$1", second.ID)
	if err := approve(t, f.svc, second, id); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("disabled administrator approved: %v", err)
	}
	request.ApprovalId = id
	if _, err := f.svc.RevealSecret(f.stepUp, connect.NewRequest(request)); err == nil {
		t.Fatal("undecided approval released the secret")
	}
	// No one is left who could approve: the owner is the only eligible admin.
	f.assertRule(t, summary.GetSecretId(), adminv1.RevealApprovalRule_REVEAL_APPROVAL_RULE_ONLY_APPROVER)
	f.revealAlone(t, summary.GetSecretId())
}

func TestRevealApprovalApproverDisabledAfterApproving(t *testing.T) {
	f := newSecretFixture(t)
	summary := f.demoSecret(t)
	second := enrolledAdmin(t, f.svc, identity.RoleAdmin)
	request := f.revealRequest(summary.GetSecretId())
	id := f.requestApproval(t, request)
	if err := approve(t, f.svc, second, id); err != nil {
		t.Fatal(err)
	}
	execSQL(t, f.svc, "UPDATE local_accounts SET enabled=false WHERE id=$1", second.ID)
	request.ApprovalId = id
	if _, err := f.svc.RevealSecret(f.stepUp, connect.NewRequest(request)); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("approval from a since-disabled administrator released the secret: %v", err)
	}
	f.assertRule(t, summary.GetSecretId(), adminv1.RevealApprovalRule_REVEAL_APPROVAL_RULE_ONLY_APPROVER)
	f.revealAlone(t, summary.GetSecretId())
}

func TestRevealApprovalScopeRestrictedApproverDoesNotCount(t *testing.T) {
	t.Run("global secret", func(t *testing.T) {
		f := newSecretFixture(t)
		summary := f.demoSecret(t)
		// A device-scoped admin cannot reveal deployment-global secrets.
		enrolledAdmin(t, f.svc, identity.RoleAdmin, &authv1.DeviceScope{DeviceIds: []string{uuid.NewString()}})
		f.assertRule(t, summary.GetSecretId(), adminv1.RevealApprovalRule_REVEAL_APPROVAL_RULE_ONLY_APPROVER)
		f.revealAlone(t, summary.GetSecretId())
	})
	t.Run("device custody", func(t *testing.T) {
		f := newLAPSFixture(t, false)
		elsewhere := enrolledAdmin(t, f.svc, identity.RoleAdmin, &authv1.DeviceScope{DeviceIds: []string{uuid.NewString()}})
		f.assertDeviceRules(t, adminv1.RevealApprovalRule_REVEAL_APPROVAL_RULE_ONLY_APPROVER)
		f.refusedDeviceRevealsAlone(t, false)
		execSQL(t, f.svc, "DELETE FROM local_credentials WHERE account_id=$1", elsewhere.ID)
		enrolledAdmin(t, f.svc, identity.RoleAdmin, &authv1.DeviceScope{DeviceIds: []string{f.deviceID}})
		f.assertDeviceRules(t, adminv1.RevealApprovalRule_REVEAL_APPROVAL_RULE_ANOTHER_APPROVER)
		f.refusedDeviceRevealsAlone(t, true)
	})
}

func TestRevealApprovalServiceAndCLIPrincipalsDoNotCount(t *testing.T) {
	f := newSecretFixture(t)
	summary := f.demoSecret(t)
	service := enrolledAdmin(t, f.svc, identity.RoleOwner)
	execSQL(t, f.svc, "UPDATE principals SET service_account=true WHERE id=$1", service.ID)
	// A CLI sign-in is a session of the requester, never another principal.
	execSQL(t, f.svc, `INSERT INTO sessions (token_hash, principal_id, created_at, last_seen_at, idle_expires_at, absolute_expires_at, kind)
		VALUES (sha256($1::bytea), $2, now(), now(), now() + interval '10 minutes', now() + interval '1 hour', 'cli')`, []byte(uuid.NewString()), f.owner.ID)
	f.assertRule(t, summary.GetSecretId(), adminv1.RevealApprovalRule_REVEAL_APPROVAL_RULE_ONLY_APPROVER)
	f.revealAlone(t, summary.GetSecretId())
}

func TestRevealApprovalBreakGlassAccountDoesNotCount(t *testing.T) {
	f := newSecretFixture(t)
	summary := f.demoSecret(t)
	emergency := enrolledAdmin(t, f.svc, identity.RoleOwner)
	execSQL(t, f.svc, "UPDATE local_accounts SET break_glass=true WHERE id=$1", emergency.ID)
	f.assertRule(t, summary.GetSecretId(), adminv1.RevealApprovalRule_REVEAL_APPROVAL_RULE_ONLY_APPROVER)
	f.revealAlone(t, summary.GetSecretId())
}

func TestRevealApprovalServerSettingAlwaysRequiresApproval(t *testing.T) {
	f := newSecretFixture(t)
	summary := f.demoSecret(t)
	f.svc.RevealApproval = true
	f.assertRule(t, summary.GetSecretId(), adminv1.RevealApprovalRule_REVEAL_APPROVAL_RULE_SERVER_SETTING)
	f.refusedAlone(t, summary.GetSecretId())
}

// assertDeviceRules checks the decision both device custody views report to
// the step-up owner for the fixture device.
func (f *lapsFixture) assertDeviceRules(t *testing.T, want adminv1.RevealApprovalRule) {
	t.Helper()
	required := want != adminv1.RevealApprovalRule_REVEAL_APPROVAL_RULE_ONLY_APPROVER
	status, err := f.svc.GetLocalAdminPasswordStatus(f.stepUp, connect.NewRequest(&adminv1.GetLocalAdminPasswordStatusRequest{DeviceId: f.deviceID}))
	if err != nil {
		t.Fatal(err)
	}
	encryption, err := f.svc.GetDeviceEncryption(f.stepUp, connect.NewRequest(&adminv1.GetDeviceEncryptionRequest{DeviceId: f.deviceID}))
	if err != nil {
		t.Fatal(err)
	}
	for name, got := range map[string]*adminv1.RevealApproval{"local admin": status.Msg.GetRevealApproval(), "recovery key": encryption.Msg.GetRecoveryKeyRevealApproval()} {
		if got.GetRule() != want || got.GetRequired() != required {
			t.Fatalf("%s reveal rule = %v required=%t, want %v", name, got.GetRule(), got.GetRequired(), want)
		}
	}
}

// refusedDeviceRevealsAlone checks the request-time gate on both device reveal
// RPCs. The gate runs before custody lookup, so an unknown action reports
// not_found only when approval is not required.
func (f *lapsFixture) refusedDeviceRevealsAlone(t *testing.T, required bool) {
	t.Helper()
	want := connect.CodeNotFound
	if required {
		want = connect.CodePermissionDenied
	}
	_, recovery := f.svc.RevealRecoveryKey(f.stepUp, connect.NewRequest(&adminv1.RevealRecoveryKeyRequest{RequestId: uuid.NewString(), DeviceId: f.deviceID, ActionId: uuid.NewString(), Reason: "user locked out of disk"}))
	_, local := f.svc.RevealLocalAdminPassword(f.stepUp, connect.NewRequest(&adminv1.RevealLocalAdminPasswordRequest{RequestId: uuid.NewString(), DeviceId: f.deviceID, ActionId: uuid.NewString(), Reason: "repair local login"}))
	for name, err := range map[string]error{"recovery key": recovery, "local admin": local} {
		if connect.CodeOf(err) != want || required && rpcReason(err) != "approval_required" {
			t.Fatalf("%s reveal alone (approval required=%t): %v", name, required, err)
		}
	}
}
