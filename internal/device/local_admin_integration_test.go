//go:build integration

package device

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"

	"lindm/internal/device/assistance"
	"lindm/internal/device/core"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
	devicev1 "lindm/gen/lindm/device/v1"
	"lindm/internal/escrow"
	"lindm/internal/identity"
)

const lapsAccount = "lapsadmin"

func localAdminActionSpec(f *deviceActionFixture) *agentv1.DeviceActionSpec {
	return &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_LocalAdminPasswordRotate{LocalAdminPasswordRotate: &agentv1.LocalAdminPasswordRotateAction{AccountName: lapsAccount, EscrowKeyId: f.svc.Escrow.KeyID(), EscrowPublicKey: f.svc.Escrow.PublicKey()}}}
}

type lapsFixture struct {
	*deviceActionFixture
	stepUp context.Context // real local password + WebAuthn session principal
}

// newLAPSFixture swaps in an identity service whose origin admits the real
// local login ceremony, so reveal step-up is proven rather than assumed.
func newLAPSFixture(t *testing.T, revealApproval bool) *lapsFixture {
	t.Helper()
	f := &lapsFixture{deviceActionFixture: newDeviceActionFixture(t)}
	authority, err := identity.New(t.Context(), f.svc.Pool, identity.Config{Local: true, PublicURL: secretTestOrigin})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := authority.Close(); err != nil {
			t.Error(err)
		}
	})
	f.stepUp = localStepUp(t, authority)
	f.svc = f.rebuild(t, authority, f.svc.Escrow, revealApproval)
	return f
}

func (f *lapsFixture) rebuild(t *testing.T, authority *identity.Service, custody *escrow.Custody, revealApproval bool) *Service {
	t.Helper()
	s := f.svc
	svc, err := New(s.Pool, core.Config{DeploymentID: s.DeploymentID.String(), CACertificate: s.CA, CAKey: s.CAKey, Identity: authority, ExecutionAuthority: s.Execution, ExecutionSigning: s.Signing, Escrow: custody, EscrowRevealApprovalRequired: revealApproval}, assistance.NewRuntime())
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

func lapsPolicy() *adminv1.LocalAdminPasswordPolicy {
	return &adminv1.LocalAdminPasswordPolicy{AccountName: lapsAccount, RotationInterval: durationpb.New(30 * 24 * time.Hour), PostRevealRotationDelay: durationpb.New(time.Hour)}
}

func (f *lapsFixture) setPolicy(t *testing.T, ctx context.Context) *adminv1.LocalAdminPasswordStatus {
	t.Helper()
	response, err := f.svc.SetLocalAdminPasswordPolicy(ctx, connect.NewRequest(&adminv1.SetLocalAdminPasswordPolicyRequest{RequestId: uuid.NewString(), DeviceId: f.deviceID, Policy: lapsPolicy(), Reason: "manage break-glass admin"}))
	if err != nil {
		t.Fatal(err)
	}
	return response.Msg.GetStatus()
}

func (f *lapsFixture) status(t *testing.T) *adminv1.LocalAdminPasswordStatus {
	t.Helper()
	response, err := f.svc.GetLocalAdminPasswordStatus(f.ownerCtx, connect.NewRequest(&adminv1.GetLocalAdminPasswordStatusRequest{DeviceId: f.deviceID}))
	if err != nil {
		t.Fatal(err)
	}
	return response.Msg.GetStatus()
}

func (f *lapsFixture) pollEmpty(t *testing.T) {
	t.Helper()
	response, err := f.svc.GetDeviceActionWork(f.deviceCtx(), connect.NewRequest(&devicev1.GetDeviceActionWorkRequest{SessionEpoch: 1}))
	if err != nil || response.Msg.GetWork() != nil {
		t.Fatalf("unexpected work: %v %v", response, err)
	}
}

func (f *lapsFixture) count(t *testing.T, query string, args ...any) int {
	t.Helper()
	var count int
	if err := f.svc.Pool.QueryRow(t.Context(), query, args...).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func lapsBinding(t *testing.T, challenge *agentv1.DeviceActionChallenge) (*agentv1.LocalAdminPasswordBinding, []byte) {
	t.Helper()
	binding := challenge.GetNativePlan().GetLocalAdminBinding()
	canonical, err := proto.MarshalOptions{Deterministic: true}.Marshal(binding)
	if err != nil {
		t.Fatal(err)
	}
	return binding, canonical
}

func (f *lapsFixture) escrowResult(t *testing.T, work *devicev1.DeviceActionWork, binding *agentv1.LocalAdminPasswordBinding, ciphertext, password []byte) *agentv1.DeviceActionVerification {
	t.Helper()
	digest := sha256Sum(password)
	return &agentv1.DeviceActionVerification{After: &agentv1.DeviceActionObservation{ObservedAt: timestamppb.Now(), Supported: true}, Escrow: &agentv1.DeviceActionEscrow{EscrowKeyId: f.svc.Escrow.KeyID(), Ciphertext: ciphertext, RecoveryKeySha256: digest, LocalAdmin: proto.CloneOf(binding)}}
}

// rotate drives one minted rotation through escrow, receipt and verified set.
func (f *lapsFixture) rotate(t *testing.T, password []byte) uuid.UUID {
	t.Helper()
	work := f.work(t)
	start, challenge := f.startRequest(t, work)
	if _, err := f.svc.AuthorizeDeviceActionStart(f.deviceCtx(), connect.NewRequest(start)); err != nil {
		t.Fatal(err)
	}
	binding, canonical := lapsBinding(t, challenge)
	sealed, err := escrow.SealLocalAdminPassword(f.svc.Escrow.PublicKey(), canonical, password)
	if err != nil {
		t.Fatal(err)
	}
	verification := f.escrowResult(t, work, binding, sealed, password)
	staged, err := f.svc.ReportDeviceActionResult(f.deviceCtx(), connect.NewRequest(f.result(t, work, 1, agentv1.DeviceActionState_DEVICE_ACTION_STATE_AWAITING_ESCROW, verification)))
	if err != nil {
		t.Fatal(err)
	}
	receipt := new(agentv1.DeviceActionEscrowReceipt)
	if err := f.svc.Authority.Verify(t.Context(), staged.Msg.GetEscrowReceiptEnvelope(), receipt, 1, ed25519.PublicKey(f.svc.Signing.StartKey[ed25519.SeedSize:])); err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(receipt.GetLocalAdmin(), binding) || receipt.GetLuksUuid() != "" {
		t.Fatal("receipt is not bound to the local-admin escrow")
	}
	verification.Verified = true
	if _, err := f.svc.ReportDeviceActionResult(f.deviceCtx(), connect.NewRequest(f.result(t, f.work(t), 2, agentv1.DeviceActionState_DEVICE_ACTION_STATE_SUCCEEDED, verification))); err != nil {
		t.Fatal(err)
	}
	return uuid.MustParse(work.GetActionId())
}

func TestLocalAdminPolicyLifecycleAndAuthorization(t *testing.T) {
	parallelDeviceIntegration(t)
	f := newLAPSFixture(t, false)
	if _, err := f.svc.CreateDeviceAction(f.ownerCtx, connect.NewRequest(f.request(localAdminActionSpec(f.deviceActionFixture)))); connect.CodeOf(err) != connect.CodeFailedPrecondition || rpcReason(err) != "local_admin_policy_required" {
		t.Fatalf("administrator minted a local-admin action: %v", err)
	}
	if _, err := f.svc.RequestLocalAdminPasswordRotation(f.ownerCtx, connect.NewRequest(&adminv1.RequestLocalAdminPasswordRotationRequest{RequestId: uuid.NewString(), DeviceId: f.deviceID, Reason: "rotate without policy"})); rpcReason(err) != "local_admin_policy_required" {
		t.Fatalf("rotation without policy: %v", err)
	}
	helpdesk := identity.WithPrincipal(t.Context(), insertPrincipal(t, t.Context(), f.conn, identity.RoleHelpdesk))
	if _, err := f.svc.SetLocalAdminPasswordPolicy(helpdesk, connect.NewRequest(&adminv1.SetLocalAdminPasswordPolicyRequest{RequestId: uuid.NewString(), DeviceId: f.deviceID, Policy: lapsPolicy(), Reason: "unauthorized policy"})); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("helpdesk set a policy: %v", err)
	}
	set := &adminv1.SetLocalAdminPasswordPolicyRequest{RequestId: uuid.NewString(), DeviceId: f.deviceID, Policy: lapsPolicy(), Reason: "manage break-glass admin"}
	response, err := f.svc.SetLocalAdminPasswordPolicy(f.ownerCtx, connect.NewRequest(set))
	if err != nil {
		t.Fatal(err)
	}
	owner, _ := identity.PrincipalFromContext(f.ownerCtx)
	status := response.Msg.GetStatus()
	if !proto.Equal(status.GetPolicy(), lapsPolicy()) || status.GetPolicyActorId() != owner.ID.String() || status.GetEscrowKeyId() != f.svc.Escrow.KeyID() || status.GetBlockedReason() != "" || time.Since(status.GetRotationDueAt().AsTime()) < 0 {
		t.Fatalf("policy status: %v", status)
	}
	if replay, err := f.svc.SetLocalAdminPasswordPolicy(f.ownerCtx, connect.NewRequest(set)); err != nil || !proto.Equal(replay.Msg.GetStatus().GetPolicy(), status.GetPolicy()) {
		t.Fatalf("exact retry: %v", err)
	}
	reused := proto.CloneOf(set)
	reused.Policy.AccountName = "otheradmin"
	if _, err := f.svc.SetLocalAdminPasswordPolicy(f.ownerCtx, connect.NewRequest(reused)); connect.CodeOf(err) != connect.CodeAlreadyExists {
		t.Fatalf("request reuse: %v", err)
	}
	if read, err := f.svc.GetLocalAdminPasswordStatus(helpdesk, connect.NewRequest(&adminv1.GetLocalAdminPasswordStatusRequest{DeviceId: f.deviceID})); err != nil || read.Msg.GetStatus().GetPolicy() == nil {
		t.Fatalf("fleet reader status: %v", err)
	}
	remove := &adminv1.RemoveLocalAdminPasswordPolicyRequest{RequestId: uuid.NewString(), DeviceId: f.deviceID, Reason: "stop managing account"}
	if _, err := f.svc.RemoveLocalAdminPasswordPolicy(f.ownerCtx, connect.NewRequest(remove)); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.RemoveLocalAdminPasswordPolicy(f.ownerCtx, connect.NewRequest(remove)); err != nil {
		t.Fatalf("exact remove retry: %v", err)
	}
	if _, err := f.svc.RemoveLocalAdminPasswordPolicy(f.ownerCtx, connect.NewRequest(&adminv1.RemoveLocalAdminPasswordPolicyRequest{RequestId: uuid.NewString(), DeviceId: f.deviceID, Reason: "remove twice"})); connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("second remove: %v", err)
	}
	if f.status(t).GetPolicy() != nil {
		t.Fatal("removed policy still projected")
	}
	if got := f.count(t, "SELECT count(*) FROM audit_events WHERE action IN ('local_admin.policy_set','local_admin.policy_removed') AND resource_id=$1", f.deviceID); got != 2 {
		t.Fatalf("policy audit rows = %d", got)
	}
	f.pollEmpty(t)
}

func TestLocalAdminDuePolicyMintsEscrowsAndSettles(t *testing.T) {
	parallelDeviceIntegration(t)
	f := newLAPSFixture(t, false)
	f.setPolicy(t, f.ownerCtx)
	work := f.work(t)
	intent := f.intent(t, work)
	owner, _ := identity.PrincipalFromContext(f.ownerCtx)
	if !proto.Equal(intent.GetSpec(), localAdminActionSpec(f.deviceActionFixture)) || intent.GetActorId() != owner.ID.String() {
		t.Fatalf("minted intent: %v", intent)
	}
	// Polling again serves the same open action with a fresh result nonce.
	again := f.work(t)
	if again.GetActionId() != work.GetActionId() || f.count(t, "SELECT count(*) FROM device_actions WHERE capability='device.local-admin-rotate.v1'") != 1 {
		t.Fatal("open rotation was reminted")
	}
	work = again
	start, challenge := f.startRequest(t, work)
	if _, err := f.svc.AuthorizeDeviceActionStart(f.deviceCtx(), connect.NewRequest(start)); err != nil {
		t.Fatal(err)
	}
	binding, canonical := lapsBinding(t, challenge)
	password := []byte("LAPSPLAINTEXTFIXTURE234567")
	sealed, err := escrow.SealLocalAdminPassword(f.svc.Escrow.PublicKey(), canonical, password)
	if err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*agentv1.DeviceActionEscrow){
		"rebound uid":   func(e *agentv1.DeviceActionEscrow) { e.LocalAdmin.AccountUid = 0 },
		"other account": func(e *agentv1.DeviceActionEscrow) { e.LocalAdmin.AccountName = "root" },
		"other device":  func(e *agentv1.DeviceActionEscrow) { e.LocalAdmin.DeviceId = uuid.NewString() },
		"recovery kind": func(e *agentv1.DeviceActionEscrow) {
			e.LocalAdmin, e.LuksUuid, e.MetadataSha256 = nil, uuid.NewString(), make([]byte, 32)
		},
		"recovery seal": func(e *agentv1.DeviceActionEscrow) {
			e.Ciphertext = mustSealRecovery(t, f.svc.Escrow.PublicKey(), canonical, password)
		},
		"password swap": func(e *agentv1.DeviceActionEscrow) {
			e.RecoveryKeySha256 = sha256Sum([]byte("LAPSOTHERPASSWORD234567AB"))
		},
		"wrong key name": func(e *agentv1.DeviceActionEscrow) { e.EscrowKeyId = hex.EncodeToString(make([]byte, 32)) },
	} {
		t.Run(name, func(t *testing.T) {
			verification := f.escrowResult(t, work, binding, sealed, password)
			change(verification.Escrow)
			if _, err := f.svc.ReportDeviceActionResult(f.deviceCtx(), connect.NewRequest(f.result(t, work, 1, agentv1.DeviceActionState_DEVICE_ACTION_STATE_AWAITING_ESCROW, verification))); err == nil {
				t.Fatal("unbound local-admin escrow admitted")
			}
			if f.count(t, "SELECT count(*) FROM device_action_escrow")+f.count(t, "SELECT count(*) FROM local_admin_passwords") != 0 {
				t.Fatal("rejected escrow committed")
			}
		})
	}
	verification := f.escrowResult(t, work, binding, sealed, password)
	staged, err := f.svc.ReportDeviceActionResult(f.deviceCtx(), connect.NewRequest(f.result(t, work, 1, agentv1.DeviceActionState_DEVICE_ACTION_STATE_AWAITING_ESCROW, verification)))
	if err != nil || len(staged.Msg.GetEscrowReceiptEnvelope()) == 0 {
		t.Fatalf("escrow: %v", err)
	}
	if escrows := f.status(t).GetEscrows(); len(escrows) != 1 || escrows[0].GetState() != adminv1.LocalAdminPasswordState_LOCAL_ADMIN_PASSWORD_STATE_ESCROWED || escrows[0].GetAccountUid() != 1001 {
		t.Fatalf("escrowed projection: %v", escrows)
	}
	// Success before the receipt-bound set is not accepted as settlement.
	verification.Verified = true
	fresh := f.work(t)
	if _, err := f.svc.Pool.Exec(t.Context(), "UPDATE device_actions SET escrow_receipt_envelope='' WHERE id=$1", work.GetActionId()); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.ReportDeviceActionResult(f.deviceCtx(), connect.NewRequest(f.result(t, fresh, 2, agentv1.DeviceActionState_DEVICE_ACTION_STATE_SUCCEEDED, verification))); rpcReason(err) != "device_action_escrow_receipt_required" {
		t.Fatalf("unreceipted success: %v", err)
	}
	if _, err := f.svc.ReportDeviceActionResult(f.deviceCtx(), connect.NewRequest(f.result(t, f.work(t), 2, agentv1.DeviceActionState_DEVICE_ACTION_STATE_SUCCEEDED, verification))); err != nil {
		t.Fatal(err)
	}
	status := f.status(t)
	if len(status.GetEscrows()) != 1 || status.GetEscrows()[0].GetState() != adminv1.LocalAdminPasswordState_LOCAL_ADMIN_PASSWORD_STATE_CURRENT || status.GetRotationDueAt().AsTime().Before(time.Now().Add(29*24*time.Hour)) {
		t.Fatalf("settled status: %v", status)
	}
	f.pollEmpty(t)

	// An explicit request rotates again; the predecessor becomes superseded.
	if _, err := f.svc.RequestLocalAdminPasswordRotation(f.ownerCtx, connect.NewRequest(&adminv1.RequestLocalAdminPasswordRotationRequest{RequestId: uuid.NewString(), DeviceId: f.deviceID, Reason: "suspected disclosure"})); err != nil {
		t.Fatal(err)
	}
	second := []byte("LAPSSECONDPLAINTEXT2345672")
	next := f.rotate(t, second)
	escrows := f.status(t).GetEscrows()
	if len(escrows) != 2 || escrows[0].GetActionId() != next.String() || escrows[0].GetState() != adminv1.LocalAdminPasswordState_LOCAL_ADMIN_PASSWORD_STATE_CURRENT || escrows[1].GetState() != adminv1.LocalAdminPasswordState_LOCAL_ADMIN_PASSWORD_STATE_SUPERSEDED {
		t.Fatalf("supersession: %v", escrows)
	}
	for _, table := range []string{"local_admin_passwords", "local_admin_password_policies", "device_action_escrow", "device_actions", "audit_events", "device_admin_requests"} {
		var text string
		if err := f.svc.Pool.QueryRow(t.Context(), "SELECT coalesce(string_agg(t::text, ''), '') FROM "+table+" t").Scan(&text); err != nil {
			t.Fatal(err)
		}
		for _, secret := range [][]byte{password, second} {
			if bytes.Contains([]byte(text), secret) || bytes.Contains([]byte(text), []byte(hex.EncodeToString(secret))) {
				t.Fatalf("plaintext local-admin password stored in %s", table)
			}
		}
	}
	if f.count(t, "SELECT count(*) FROM audit_events WHERE action='local_admin.escrow_store'") != 2 || f.count(t, "SELECT count(*) FROM audit_events WHERE action='local_admin.rotation_requested'") != 1 {
		t.Fatal("escrow or request audit missing")
	}
}

func TestLocalAdminAuthorityChangeAndMissingEscrowBlock(t *testing.T) {
	parallelDeviceIntegration(t)
	f := newLAPSFixture(t, false)
	adminPrincipal := insertPrincipal(t, t.Context(), f.conn, identity.RoleAdmin)
	f.setPolicy(t, identity.WithPrincipal(t.Context(), adminPrincipal))
	if _, err := f.svc.Pool.Exec(t.Context(), "UPDATE local_accounts SET enabled=false WHERE id=$1", adminPrincipal.ID); err != nil {
		t.Fatal(err)
	}
	f.pollEmpty(t)
	if status := f.status(t); status.GetBlockedReason() != "policy_authority_changed" {
		t.Fatalf("changed authority not visible: %v", status)
	}
	if f.count(t, "SELECT count(*) FROM device_actions") != 0 {
		t.Fatal("blocked policy minted an action")
	}
	// A new policy actor re-authorizes the policy and minting resumes.
	f.setPolicy(t, f.ownerCtx)
	if f.work(t).GetActionId() == "" || f.status(t).GetBlockedReason() != "" {
		t.Fatal("re-authorized policy did not mint")
	}

	g := newLAPSFixture(t, false)
	g.setPolicy(t, g.ownerCtx)
	g.svc = g.rebuild(t, g.svc.Identity, nil, false)
	g.pollEmpty(t)
	if status := g.status(t); status.GetBlockedReason() != "escrow_unconfigured" || status.GetEscrowKeyId() != "" {
		t.Fatalf("missing escrow not visible: %v", status)
	}
}

func TestLocalAdminRevealStepUpAuditApprovalAndRotation(t *testing.T) {
	parallelDeviceIntegration(t)
	f := newLAPSFixture(t, false)
	f.setPolicy(t, f.ownerCtx)
	password := []byte("LAPSREVEALPLAINTEXT2345672")
	id := f.rotate(t, password)
	reveal := &adminv1.RevealLocalAdminPasswordRequest{RequestId: uuid.NewString(), DeviceId: f.deviceID, ActionId: id.String(), Reason: "break-glass login"}
	if _, err := f.svc.RevealLocalAdminPassword(f.ownerCtx, connect.NewRequest(reveal)); rpcReason(err) != "recent_step_up_required" {
		t.Fatalf("reveal without step-up: %v", err)
	}
	if f.count(t, "SELECT count(*) FROM audit_events WHERE action='local_admin.reveal'") != 0 {
		t.Fatal("refused reveal audited as released")
	}
	before := time.Now()
	response, err := f.svc.RevealLocalAdminPassword(f.stepUp, connect.NewRequest(reveal))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(response.Msg.GetPassword(), password) || response.Msg.GetEscrow().GetState() != adminv1.LocalAdminPasswordState_LOCAL_ADMIN_PASSWORD_STATE_CURRENT || response.Header().Get("Cache-Control") == "" {
		t.Fatalf("reveal response: %v", response.Msg.GetEscrow())
	}
	due := response.Msg.GetRotationDueAt().AsTime()
	if due.Before(before.Add(time.Hour-time.Minute)) || due.After(time.Now().Add(time.Hour+time.Minute)) || !f.status(t).GetRotationDueAt().AsTime().Equal(due) {
		t.Fatalf("post-reveal rotation not scheduled: %v", due)
	}
	if f.status(t).GetEscrows()[0].GetLastRevealedAt() == nil {
		t.Fatal("reveal time not recorded")
	}
	// Audit admission precedes release: a custody failure is still audited.
	if _, err := f.svc.Pool.Exec(t.Context(), "UPDATE device_action_escrow SET ciphertext = ciphertext || '\\x00'::bytea WHERE action_id=$1", id); err != nil {
		t.Fatal(err)
	}
	failed := proto.CloneOf(reveal)
	failed.RequestId = uuid.NewString()
	if _, err := f.svc.RevealLocalAdminPassword(f.stepUp, connect.NewRequest(failed)); rpcReason(err) != "escrow_custody_rejected" {
		t.Fatalf("damaged custody: %v", err)
	}
	if f.count(t, "SELECT count(*) FROM audit_events WHERE action='local_admin.reveal' AND resource_id=$1", id.String()) != 2 {
		t.Fatal("reveal attempts were not audited before release")
	}
	if _, err := f.svc.RevealRecoveryKey(f.stepUp, connect.NewRequest(&adminv1.RevealRecoveryKeyRequest{RequestId: uuid.NewString(), DeviceId: f.deviceID, ActionId: id.String(), Reason: "cross-kind reveal"})); connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("recovery reveal of a local-admin record: %v", err)
	}

	a := newLAPSFixture(t, true)
	a.setPolicy(t, a.ownerCtx)
	second := []byte("LAPSAPPROVALPLAINTEXT23456")
	approvedID := a.rotate(t, second)
	request := &adminv1.RevealLocalAdminPasswordRequest{RequestId: uuid.NewString(), DeviceId: a.deviceID, ActionId: approvedID.String(), Reason: "approved break-glass login"}
	if _, err := a.svc.RevealLocalAdminPassword(a.stepUp, connect.NewRequest(request)); rpcReason(err) != "approval_required" {
		t.Fatalf("unapproved reveal under approval policy: %v", err)
	}
	created, err := a.svc.CreateApproval(a.stepUp, connect.NewRequest(&adminv1.CreateApprovalRequest{LifetimeSeconds: 600, Payload: &adminv1.CreateApprovalRequest_RevealLocalAdminPassword{RevealLocalAdminPassword: request}}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.svc.ApproveApproval(approvalReviewer(t, a.svc, t.Context()), connect.NewRequest(&adminv1.ApproveApprovalRequest{ApprovalId: created.Msg.GetApproval().GetId(), Reason: "second administrator reviewed"})); err != nil {
		t.Fatal(err)
	}
	request.ApprovalId = created.Msg.GetApproval().GetId()
	approved, err := a.svc.RevealLocalAdminPassword(a.stepUp, connect.NewRequest(request))
	if err != nil || !bytes.Equal(approved.Msg.GetPassword(), second) {
		t.Fatalf("approved reveal: %v", err)
	}
}

func sha256Sum(data []byte) []byte {
	digest := sha256.Sum256(data)
	return digest[:]
}

func mustSealRecovery(t *testing.T, public, binding, secret []byte) []byte {
	t.Helper()
	padded := append(bytes.Clone(secret), bytes.Repeat([]byte{'0'}, 64-len(secret))...)
	sealed, err := escrow.SealForServer(public, binding, padded)
	if err != nil {
		t.Fatal(err)
	}
	return sealed
}
