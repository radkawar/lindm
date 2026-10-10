//go:build integration

package device

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
	authv1 "lindm/gen/lindm/auth/v1"
	devicev1 "lindm/gen/lindm/device/v1"
	"lindm/internal/device/devicedb"
	"lindm/internal/escrow"
	"lindm/internal/identity"
)

func lockActionSpec() *agentv1.DeviceActionSpec {
	return &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_LockSessions{LockSessions: &agentv1.LockSessionsAction{}}}
}
func wipeActionSpec() *agentv1.DeviceActionSpec {
	return &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_CryptoErase{CryptoErase: &agentv1.CryptoEraseAction{Mode: agentv1.CryptoEraseMode_CRYPTO_ERASE_MODE_OFFLINE, Target: fixtureStorageTarget(uuid.NewString())}}}
}

func TestDeviceActionImmutableDigestGrantReplayAndUnknown(t *testing.T) {
	f := newDeviceActionFixture(t)
	request := f.request(lockActionSpec())
	action := f.create(t, request)
	replay := f.create(t, request)
	if replay.GetActionId() != action.GetActionId() {
		t.Fatal("create replay minted new action")
	}
	changed := proto.CloneOf(request)
	changed.Reason = "different exact operation"
	if _, err := f.svc.CreateDeviceAction(f.ownerCtx, connect.NewRequest(changed)); connect.CodeOf(err) != connect.CodeAlreadyExists {
		t.Fatalf("changed digest replay: %v", err)
	}
	work := f.work(t)
	start, challenge := f.startRequest(t, work)
	bad := proto.CloneOf(challenge)
	bad.SpecSha256[0] ^= 1
	if _, err := f.svc.AuthorizeDeviceActionStart(f.deviceCtx(), connect.NewRequest(&devicev1.AuthorizeDeviceActionStartRequest{SessionEpoch: 1, ActionId: action.GetActionId(), ChallengeProof: f.sign(t, bad)})); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("wrong spec challenge: %v", err)
	}
	response, err := f.svc.AuthorizeDeviceActionStart(f.deviceCtx(), connect.NewRequest(start))
	if err != nil {
		t.Fatal(err)
	}
	grant := new(agentv1.DeviceActionStartGrant)
	if err := f.svc.authority.Verify(t.Context(), response.Msg.GetStartGrantEnvelope(), grant, 1, ed25519.PublicKey(f.svc.signing.StartKey[ed25519.SeedSize:])); err != nil {
		t.Fatal(err)
	}
	if grant.GetExpiresAt().AsTime().Sub(grant.GetNotBefore().AsTime()) > 30*time.Second {
		t.Fatal("long-lived start grant")
	}
	again, err := f.svc.AuthorizeDeviceActionStart(f.deviceCtx(), connect.NewRequest(start))
	if err != nil || !bytes.Equal(again.Msg.GetStartGrantEnvelope(), response.Msg.GetStartGrantEnvelope()) {
		t.Fatalf("exact grant replay: %v", err)
	}
	different, _ := f.startRequest(t, work)
	if _, err := f.svc.AuthorizeDeviceActionStart(f.deviceCtx(), connect.NewRequest(different)); connect.CodeOf(err) != connect.CodeAlreadyExists {
		t.Fatalf("reissued different challenge: %v", err)
	}
	state, err := f.svc.GetDeviceAction(f.ownerCtx, connect.NewRequest(&adminv1.GetDeviceActionRequest{ActionId: action.GetActionId()}))
	if err != nil {
		t.Fatal(err)
	}
	if state.Msg.GetAction().GetStatus().GetState() != agentv1.DeviceActionState_DEVICE_ACTION_STATE_OUTCOME_UNKNOWN {
		t.Fatal("unreported possible effect not unknown")
	}
	if _, err := f.svc.CreateDeviceAction(f.ownerCtx, connect.NewRequest(f.request(lockActionSpec()))); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("new effect admitted while unknown: %v", err)
	}
	result := f.result(t, f.work(t), 1, agentv1.DeviceActionState_DEVICE_ACTION_STATE_OUTCOME_UNKNOWN, nil)
	if _, err := f.svc.ReportDeviceActionResult(f.deviceCtx(), connect.NewRequest(result)); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.ReportDeviceActionResult(f.deviceCtx(), connect.NewRequest(result)); err != nil {
		t.Fatalf("exact attestation replay: %v", err)
	}
	if f.work(t).GetActionId() != action.GetActionId() {
		t.Fatal("unknown action replaced")
	}
	acquireTestSession(t, t.Context(), f.svc, f.principal, f.key, 1)
	if _, err := f.svc.GetDeviceActionWork(f.deviceCtx(), connect.NewRequest(&devicev1.GetDeviceActionWorkRequest{SessionEpoch: 1})); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("stale session work: %v", err)
	}
}

func TestDeviceActionDestructiveApprovalConsumedAtStart(t *testing.T) {
	f := newDeviceActionFixture(t)
	request := f.request(wipeActionSpec())
	f.observeStorageTargets(t, request.GetSpec().GetCryptoErase().GetTarget())
	if _, err := f.svc.CreateDeviceAction(f.ownerCtx, connect.NewRequest(request)); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("destructive create without approval: %v", err)
	}
	f.approval(t, request)
	f.create(t, request)
	var state string
	if err := f.svc.pool.QueryRow(t.Context(), "SELECT state FROM approval_requests WHERE id=$1", request.GetApprovalId()).Scan(&state); err != nil || state != "approved" {
		t.Fatalf("approval consumed before start: %s %v", state, err)
	}
	start, _ := f.startRequest(t, f.work(t))
	response, err := f.svc.AuthorizeDeviceActionStart(f.deviceCtx(), connect.NewRequest(start))
	if err != nil {
		t.Fatal(err)
	}
	if err := f.svc.pool.QueryRow(t.Context(), "SELECT state FROM approval_requests WHERE id=$1", request.GetApprovalId()).Scan(&state); err != nil || state != "consumed" {
		t.Fatalf("approval not consumed atomically: %s %v", state, err)
	}
	grant := new(agentv1.DeviceActionStartGrant)
	if err := f.svc.authority.Verify(t.Context(), response.Msg.GetStartGrantEnvelope(), grant, 1, ed25519.PublicKey(f.svc.signing.StartKey[ed25519.SeedSize:])); err != nil {
		t.Fatal(err)
	}
	if len(grant.GetApprovals()) != 2 || grant.GetApprovals()[0].GetActorId() == grant.GetApprovals()[1].GetActorId() {
		t.Fatal("grant lacks two independent humans")
	}
}

func TestDeviceActionApprovalRevocationExpiryAndDigest(t *testing.T) {
	for _, variant := range []string{"revoked", "expired", "digest"} {
		t.Run(variant, func(t *testing.T) {
			f := newDeviceActionFixture(t)
			request := f.request(wipeActionSpec())
			reviewer := f.approval(t, request)
			if variant == "digest" {
				request.Spec.GetCryptoErase().Target.LuksUuid = uuid.NewString()
			}
			f.observeStorageTargets(t, request.GetSpec().GetCryptoErase().GetTarget())
			f.create(t, request)
			start, _ := f.startRequest(t, f.work(t))
			if variant == "revoked" {
				principal, _ := identity.PrincipalFromContext(reviewer)
				if _, err := f.svc.pool.Exec(t.Context(), "UPDATE local_accounts SET enabled=false WHERE id=$1", principal.ID); err != nil {
					t.Fatal(err)
				}
			}
			if variant == "expired" {
				if _, err := f.svc.pool.Exec(t.Context(), "UPDATE approval_requests SET created_at=clock_timestamp()-interval '20 minutes',expires_at=clock_timestamp()-interval '10 minutes' WHERE id=$1", request.GetApprovalId()); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := f.svc.AuthorizeDeviceActionStart(f.deviceCtx(), connect.NewRequest(start)); err == nil {
				t.Fatal("invalid fresh approval admitted")
			}
			var grant []byte
			if err := f.svc.pool.QueryRow(t.Context(), "SELECT start_grant_envelope FROM device_actions WHERE id=$1", start.GetActionId()).Scan(&grant); err != nil {
				t.Fatal(err)
			}
			if len(grant) != 0 {
				t.Fatal("rejected approval persisted authority")
			}
		})
	}
}

func TestDeviceActionEscrowDurableReceiptSecretExclusion(t *testing.T) {
	f := newDeviceActionFixture(t)
	rotate := &agentv1.EscrowRotateAction{Target: fixtureStorageTarget(uuid.NewString()), EscrowKeyId: f.svc.escrow.KeyID(), EscrowPublicKey: f.svc.escrow.PublicKey()}
	f.observeStorageTargets(t, rotate.GetTarget())
	action := f.create(t, f.request(&agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_EscrowRotate{EscrowRotate: rotate}}))
	work := f.work(t)
	start, challenge := f.startRequest(t, work)
	if _, err := f.svc.AuthorizeDeviceActionStart(f.deviceCtx(), connect.NewRequest(start)); err != nil {
		t.Fatal(err)
	}
	binding, err := proto.MarshalOptions{Deterministic: true}.Marshal(challenge.GetNativePlan().GetRecoveryBinding())
	if err != nil {
		t.Fatal(err)
	}
	secret := []byte("memory-only-high-entropy-fixture-recovery-key-93237a58409841a0")
	defer clear(secret)
	encrypted, err := escrow.SealForServer(f.svc.escrow.PublicKey(), binding, secret)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(secret)
	recovery := &agentv1.DeviceActionEscrow{EscrowKeyId: f.svc.escrow.KeyID(), Ciphertext: encrypted, RecoveryKeySha256: digest[:], NewKeyslot: 1, LuksUuid: rotate.GetTarget().GetLuksUuid(), MetadataSha256: make([]byte, 32)}
	verification := &agentv1.DeviceActionVerification{After: &agentv1.DeviceActionObservation{ObservedAt: timestamppb.Now(), Supported: true, Encrypted: true, Target: rotate.GetTarget()}, Escrow: recovery}
	badVerification := proto.CloneOf(verification)
	badVerification.Escrow.RecoveryKeySha256[0] ^= 1
	if _, err := f.svc.ReportDeviceActionResult(f.deviceCtx(), connect.NewRequest(f.result(t, work, 1, agentv1.DeviceActionState_DEVICE_ACTION_STATE_AWAITING_ESCROW, badVerification))); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("bad secret digest admitted: %v", err)
	}
	var count int
	if err := f.svc.pool.QueryRow(t.Context(), "SELECT count(*) FROM device_action_escrow").Scan(&count); err != nil || count != 0 {
		t.Fatalf("rejected custody committed: %d %v", count, err)
	}
	result := f.result(t, work, 1, agentv1.DeviceActionState_DEVICE_ACTION_STATE_AWAITING_ESCROW, verification)
	response, err := f.svc.ReportDeviceActionResult(f.deviceCtx(), connect.NewRequest(result))
	if err != nil {
		t.Fatal(err)
	}
	if len(response.Msg.GetEscrowReceiptEnvelope()) == 0 {
		t.Fatal("missing committed custody receipt")
	}
	id, _ := uuid.Parse(action.GetActionId())
	stored, err := devicedb.New(f.svc.pool).GetDeviceActionEscrow(t.Context(), id)
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := f.svc.escrow.Reveal(stored.BindingDocument, &escrow.Record{KeyID: stored.KeyID, WrappedKey: stored.WrappedKey, Ciphertext: stored.Ciphertext, SecretSHA256: stored.SecretSha256})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(plaintext, secret) {
		t.Fatal("durable custody differs")
	}
	clear(plaintext)
	receipt := new(agentv1.DeviceActionEscrowReceipt)
	if err := f.svc.authority.Verify(t.Context(), response.Msg.GetEscrowReceiptEnvelope(), receipt, 1, ed25519.PublicKey(f.svc.signing.StartKey[ed25519.SeedSize:])); err != nil {
		t.Fatal(err)
	}
	if receipt.GetActionId() != action.GetActionId() || !bytes.Equal(receipt.GetRecoveryKeySha256(), digest[:]) || receipt.GetNewKeyslot() != 1 || !receipt.GetStoredAt().AsTime().Equal(stored.CommittedAt.Time) {
		t.Fatal("receipt not bound to committed custody")
	}
	replay, err := f.svc.ReportDeviceActionResult(f.deviceCtx(), connect.NewRequest(result))
	if err != nil || !bytes.Equal(replay.Msg.GetEscrowReceiptEnvelope(), response.Msg.GetEscrowReceiptEnvelope()) {
		t.Fatalf("lost receipt response changed: %v", err)
	}
	// Simulate a process loss after custody commit but before receipt persistence.
	if _, err := f.svc.pool.Exec(t.Context(), "UPDATE device_actions SET escrow_receipt_envelope='' WHERE id=$1", id); err != nil {
		t.Fatal(err)
	}
	resumed := f.work(t)
	if len(resumed.GetEscrowReceiptEnvelope()) == 0 {
		t.Fatal("committed escrow not recovered by work polling")
	}
	detail, err := f.svc.GetDeviceAction(f.ownerCtx, connect.NewRequest(&adminv1.GetDeviceActionRequest{ActionId: id.String()}))
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := proto.Marshal(detail.Msg)
	if err != nil {
		t.Fatal(err)
	}
	var audit string
	if err := f.svc.pool.QueryRow(t.Context(), "SELECT string_agg(action || reason,' ') FROM audit_events").Scan(&audit); err != nil {
		t.Fatal(err)
	}
	for _, payload := range [][]byte{encoded, stored.Ciphertext, stored.WrappedKey, result.GetAttestationEnvelope(), resumed.GetEscrowReceiptEnvelope(), []byte(audit)} {
		if bytes.Contains(payload, secret) {
			t.Fatal("recovery plaintext escaped custody")
		}
	}
	if _, err := f.svc.RevealRecoveryKey(f.ownerCtx, connect.NewRequest(&adminv1.RevealRecoveryKeyRequest{RequestId: uuid.NewString(), DeviceId: f.deviceID, ActionId: id.String(), Reason: "attempt without private step-up proof"})); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("WithPrincipal bypassed stepup: %v", err)
	}
	verification.Verified = true
	final := f.result(t, resumed, 2, agentv1.DeviceActionState_DEVICE_ACTION_STATE_SUCCEEDED, verification)
	if _, err := f.svc.ReportDeviceActionResult(f.deviceCtx(), connect.NewRequest(final)); err != nil {
		t.Fatal(err)
	}
	encryption, err := f.svc.GetDeviceEncryption(f.ownerCtx, connect.NewRequest(&adminv1.GetDeviceEncryptionRequest{DeviceId: f.deviceID}))
	if err != nil || !encryption.Msg.GetEscrow().GetRetirementConfirmed() {
		t.Fatalf("final escrow state: %v", err)
	}
	// A later session/network action must not replace a volume observation with
	// its unrelated targetless observation.
	for _, spec := range []*agentv1.DeviceActionSpec{
		lockActionSpec(),
		{Action: &agentv1.DeviceActionSpec_Quarantine{Quarantine: &agentv1.QuarantineAction{ManagementEndpoints: []string{"192.0.2.1"}}}},
	} {
		f.create(t, f.request(spec))
		laterWork := f.work(t)
		laterStart, _ := f.startRequest(t, laterWork)
		if _, err := f.svc.AuthorizeDeviceActionStart(f.deviceCtx(), connect.NewRequest(laterStart)); err != nil {
			t.Fatal(err)
		}
		laterVerification := &agentv1.DeviceActionVerification{Verified: true, After: &agentv1.DeviceActionObservation{ObservedAt: timestamppb.Now(), Supported: true}}
		if _, err := f.svc.ReportDeviceActionResult(f.deviceCtx(), connect.NewRequest(f.result(t, laterWork, 1, agentv1.DeviceActionState_DEVICE_ACTION_STATE_SUCCEEDED, laterVerification))); err != nil {
			t.Fatal(err)
		}
		latest, err := f.svc.GetDeviceEncryption(f.ownerCtx, connect.NewRequest(&adminv1.GetDeviceEncryptionRequest{DeviceId: f.deviceID}))
		if err != nil {
			t.Fatal(err)
		}
		if !proto.Equal(latest.Msg.GetObservation(), encryption.Msg.GetObservation()) || latest.Msg.GetObservation().GetTarget().GetLuksUuid() != rotate.GetTarget().GetLuksUuid() || latest.Msg.GetEscrow().GetLuksUuid() != rotate.GetTarget().GetLuksUuid() {
			t.Fatal("unrelated action replaced the exact recorded encryption volume")
		}
	}
}

func TestDeviceActionScopeOfflineAndQuarantineRestrictions(t *testing.T) {
	f := newDeviceActionFixture(t)
	request := f.request(&agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_Quarantine{Quarantine: &agentv1.QuarantineAction{ManagementEndpoints: []string{"192.0.2.1"}}}})
	if _, err := f.svc.pool.Exec(t.Context(), "UPDATE devices SET last_seen_at=clock_timestamp()-interval '2 minutes' WHERE id=$1", f.principal.DeviceID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.CreateDeviceAction(f.ownerCtx, connect.NewRequest(request)); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("offline destructive queue admitted: %v", err)
	}
	if _, err := f.svc.pool.Exec(t.Context(), "UPDATE devices SET last_seen_at=clock_timestamp() WHERE id=$1", f.principal.DeviceID); err != nil {
		t.Fatal(err)
	}
	action := f.create(t, request)
	principal, _ := identity.PrincipalFromContext(f.ownerCtx)
	principal.Bindings = []*authv1.RoleBinding{{Permissions: []string{string(identity.PermissionReadFleet)}, Scopes: []*authv1.DeviceScope{{DeviceIds: []string{uuid.NewString()}}}}}
	outside := identity.WithPrincipal(t.Context(), principal)
	for _, id := range []string{action.GetActionId(), uuid.NewString()} {
		if _, err := f.svc.GetDeviceAction(outside, connect.NewRequest(&adminv1.GetDeviceActionRequest{ActionId: id})); connect.CodeOf(err) != connect.CodeNotFound {
			t.Fatalf("action existence leak: %v", err)
		}
	}
	if _, err := f.svc.GetDeviceEncryption(outside, connect.NewRequest(&adminv1.GetDeviceEncryptionRequest{DeviceId: f.deviceID})); connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("encryption scope leak: %v", err)
	}
	start, _ := f.startRequest(t, f.work(t))
	if _, err := f.svc.AuthorizeDeviceActionStart(f.deviceCtx(), connect.NewRequest(start)); err != nil {
		t.Fatal(err)
	}
	response, err := f.svc.GetDeviceActions(f.ownerCtx, connect.NewRequest(&adminv1.GetDeviceActionsRequest{DeviceId: f.deviceID}))
	if err != nil || !response.Msg.GetQuarantined() {
		t.Fatalf("missing restriction: %v", err)
	}
	until := response.Msg.GetQuarantineUntil().AsTime()
	if until.After(time.Now().Add(331 * time.Second)) {
		t.Fatal("quarantine restriction unbounded")
	}
	if _, err := f.svc.GetResourceWork(f.deviceCtx(), connect.NewRequest(&devicev1.GetResourceWorkRequest{SessionEpoch: 1})); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("quarantine service authority admitted: %v", err)
	}
	if _, err := f.svc.pool.Exec(t.Context(), "UPDATE device_action_restrictions SET quarantine_until=clock_timestamp()-interval '1 second' WHERE device_id=$1", f.principal.DeviceID); err != nil {
		t.Fatal(err)
	}
	if work, err := f.svc.GetResourceWork(f.deviceCtx(), connect.NewRequest(&devicev1.GetResourceWorkRequest{SessionEpoch: 1})); err != nil || work.Msg.GetWork() != nil {
		t.Fatalf("expired quarantine prevented an empty service poll: %v", err)
	}
	var quarantined bool
	if err := f.svc.pool.QueryRow(t.Context(), "SELECT quarantined FROM device_action_restrictions WHERE device_id=$1", f.principal.DeviceID).Scan(&quarantined); err != nil || quarantined {
		t.Fatalf("service poll did not durably expire quarantine: quarantined=%v err=%v", quarantined, err)
	}
	response, err = f.svc.GetDeviceActions(f.ownerCtx, connect.NewRequest(&adminv1.GetDeviceActionsRequest{DeviceId: f.deviceID}))
	if err != nil || response.Msg.GetQuarantined() {
		t.Fatalf("native expiry left permanent server restriction: %v", err)
	}
}

func TestDeviceActionFreshMutationScopeAndDeviceRevocation(t *testing.T) {
	f := newDeviceActionFixture(t)
	actor := insertPrincipal(t, t.Context(), f.conn, identity.RoleAdmin)
	outside := []byte(`{"scopes":[{"deviceIds":["` + uuid.NewString() + `"]}]}`)
	if _, err := f.svc.pool.Exec(t.Context(), "UPDATE local_accounts SET scope_binding=$2::jsonb WHERE id=$1", actor.ID, outside); err != nil {
		t.Fatal(err)
	}
	actorCtx := identity.WithPrincipal(t.Context(), actor)
	request := f.request(lockActionSpec())
	if _, err := f.svc.CreateDeviceAction(actorCtx, connect.NewRequest(request)); connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("fresh out-of-scope mutation admitted: %v", err)
	}
	inside := []byte(`{"scopes":[{"deviceIds":["` + f.deviceID + `"]}]}`)
	if _, err := f.svc.pool.Exec(t.Context(), "UPDATE local_accounts SET scope_binding=$2::jsonb WHERE id=$1", actor.ID, inside); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.CreateDeviceAction(actorCtx, connect.NewRequest(request)); err != nil {
		t.Fatal(err)
	}
	work := f.work(t)
	start, _ := f.startRequest(t, work)
	if _, err := f.svc.AuthorizeDeviceActionStart(f.deviceCtx(), connect.NewRequest(start)); err != nil {
		t.Fatal(err)
	}
	result := f.result(t, work, 1, agentv1.DeviceActionState_DEVICE_ACTION_STATE_OUTCOME_UNKNOWN, nil)
	if _, err := f.svc.RevokeDevice(f.ownerCtx, approvedRevocation(t, f.svc, f.ownerCtx, &adminv1.RevokeDeviceRequest{RequestId: uuid.NewString(), DeviceId: f.deviceID, Reason: "revoke action identity before accepting result"})); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.ReportDeviceActionResult(f.deviceCtx(), connect.NewRequest(result)); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("revoked device result admitted: %v", err)
	}
}

func TestDeviceActionResultNonceAndIntentFences(t *testing.T) {
	f := newDeviceActionFixture(t)
	f.create(t, f.request(lockActionSpec()))
	work := f.work(t)
	start, _ := f.startRequest(t, work)
	if _, err := f.svc.AuthorizeDeviceActionStart(f.deviceCtx(), connect.NewRequest(start)); err != nil {
		t.Fatal(err)
	}
	stale := f.result(t, work, 1, agentv1.DeviceActionState_DEVICE_ACTION_STATE_OUTCOME_UNKNOWN, nil)
	fresh := f.work(t)
	if _, err := f.svc.ReportDeviceActionResult(f.deviceCtx(), connect.NewRequest(stale)); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("replaced result nonce admitted: %v", err)
	}
	result := f.result(t, fresh, 1, agentv1.DeviceActionState_DEVICE_ACTION_STATE_OUTCOME_UNKNOWN, nil)
	proof := new(agentv1.DeviceActionAttestation)
	if err := f.svc.authority.Verify(t.Context(), result.GetAttestationEnvelope(), proof, 1, ed25519.PublicKey(f.key[ed25519.SeedSize:])); err != nil {
		t.Fatal(err)
	}
	proof.Status.IntentSha256[0] ^= 1
	result.AttestationEnvelope = f.sign(t, proof)
	if _, err := f.svc.ReportDeviceActionResult(f.deviceCtx(), connect.NewRequest(result)); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("wrong intent result admitted: %v", err)
	}
	if _, err := f.svc.ReportDeviceActionResult(f.deviceCtx(), connect.NewRequest(f.result(t, fresh, 1, agentv1.DeviceActionState_DEVICE_ACTION_STATE_OUTCOME_UNKNOWN, nil))); err != nil {
		t.Fatal(err)
	}
}

func TestDeviceActionEncryptionExactVolumeSelection(t *testing.T) {
	f := newDeviceActionFixture(t)
	volumes := []string{uuid.NewString(), uuid.NewString()}
	actions := make([]string, len(volumes))
	targets := []*agentv1.StorageTarget{fixtureStorageTarget(volumes[0]), fixtureStorageTarget(volumes[1])}
	f.observeStorageTargets(t, targets...)
	for i, volume := range volumes {
		rotate := &agentv1.EscrowRotateAction{Target: targets[i], EscrowKeyId: f.svc.escrow.KeyID(), EscrowPublicKey: f.svc.escrow.PublicKey()}
		action := f.create(t, f.request(&agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_EscrowRotate{EscrowRotate: rotate}}))
		actions[i] = action.GetActionId()
		work := f.work(t)
		start, challenge := f.startRequest(t, work)
		if _, err := f.svc.AuthorizeDeviceActionStart(f.deviceCtx(), connect.NewRequest(start)); err != nil {
			t.Fatal(err)
		}
		binding, err := proto.MarshalOptions{Deterministic: true}.Marshal(challenge.GetNativePlan().GetRecoveryBinding())
		if err != nil {
			t.Fatal(err)
		}
		secret := []byte("volume-specific-recovery-" + uuid.NewString())
		digest := sha256.Sum256(secret)
		ciphertext, err := escrow.SealForServer(f.svc.escrow.PublicKey(), binding, secret)
		clear(secret)
		if err != nil {
			t.Fatal(err)
		}
		verification := &agentv1.DeviceActionVerification{
			After:  &agentv1.DeviceActionObservation{ObservedAt: timestamppb.Now(), Supported: true, Encrypted: true, Target: rotate.GetTarget()},
			Escrow: &agentv1.DeviceActionEscrow{EscrowKeyId: f.svc.escrow.KeyID(), Ciphertext: ciphertext, RecoveryKeySha256: digest[:], NewKeyslot: 1, LuksUuid: volume, MetadataSha256: make([]byte, 32)},
		}
		if _, err := f.svc.ReportDeviceActionResult(f.deviceCtx(), connect.NewRequest(f.result(t, work, 1, agentv1.DeviceActionState_DEVICE_ACTION_STATE_AWAITING_ESCROW, verification))); err != nil {
			t.Fatal(err)
		}
		verification.Verified = true
		if _, err := f.svc.ReportDeviceActionResult(f.deviceCtx(), connect.NewRequest(f.result(t, f.work(t), 2, agentv1.DeviceActionState_DEVICE_ACTION_STATE_SUCCEEDED, verification))); err != nil {
			t.Fatal(err)
		}
	}
	for i, volume := range volumes {
		response, err := f.svc.GetDeviceEncryption(f.ownerCtx, connect.NewRequest(&adminv1.GetDeviceEncryptionRequest{DeviceId: f.deviceID, LuksUuid: volume}))
		if err != nil {
			t.Fatal(err)
		}
		if response.Msg.GetObservation().GetTarget().GetLuksUuid() != volume || response.Msg.GetEscrow().GetLuksUuid() != volume || response.Msg.GetEscrow().GetActionId() != actions[i] {
			t.Fatal("selected volume resolved another volume's observation or recovery custody")
		}
	}
	latest, err := f.svc.GetDeviceEncryption(f.ownerCtx, connect.NewRequest(&adminv1.GetDeviceEncryptionRequest{DeviceId: f.deviceID}))
	if err != nil || latest.Msg.GetEscrow().GetActionId() != actions[1] {
		t.Fatalf("unfiltered latest volume: %v", err)
	}
	missing, err := f.svc.GetDeviceEncryption(f.ownerCtx, connect.NewRequest(&adminv1.GetDeviceEncryptionRequest{DeviceId: f.deviceID, LuksUuid: uuid.NewString()}))
	if err != nil || missing.Msg.GetObservation() != nil || missing.Msg.GetEscrow() != nil {
		t.Fatalf("missing volume fell back to another recovery key: %v", err)
	}
	incomplete := f.request(&agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_CryptoErase{CryptoErase: &agentv1.CryptoEraseAction{Mode: agentv1.CryptoEraseMode_CRYPTO_ERASE_MODE_LIVE_ROOT_HEADER, Targets: targets[:1]}}})
	if _, err := f.svc.CreateDeviceAction(f.ownerCtx, connect.NewRequest(incomplete)); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("live root omitted retained escrow volume: %v", err)
	}
}
