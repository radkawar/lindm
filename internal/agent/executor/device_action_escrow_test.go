//go:build linux

package executor

import (
	"bytes"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
)

func escrowActionSpec() *agentv1.DeviceActionSpec {
	old := uint32(1)
	return &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_EscrowRotate{EscrowRotate: &agentv1.EscrowRotateAction{Target: &agentv1.StorageTarget{IdentityBasis: agentv1.StorageIdentityBasis_STORAGE_IDENTITY_BASIS_WWN_SERIAL, LuksUuid: uuid.NewString(), Wwn: "fixture-wwn", Serial: "fixture-serial", SizeBytes: 1 << 30}, EscrowKeyId: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", EscrowPublicKey: bytes.Repeat([]byte{6}, 256), RetireKeyslot: &old}}}
}

func TestDeviceActionEscrowPreservesPlannedNonzeroSlot(t *testing.T) {
	f := newDeviceActionFixture(t)
	f.actionNative.occupiedKeyslots = []uint32{0}
	spec := escrowActionSpec()
	spec.GetEscrowRotate().RetireKeyslot = nil
	intent := f.actionIntent(t, 1, spec)
	f.actionPrepare(t, intent)
	record, _ := deviceActionRow(t, f.svc, intent.GetActionId())
	binding := record.GetNativePlan().GetRecoveryBinding()
	if binding.GetNewKeyslot() != 1 || binding.GetDeviceId() != intent.GetDeviceId() ||
		binding.GetEnrollmentGeneration() != intent.GetEnrollmentGeneration() ||
		binding.GetActionId() != intent.GetActionId() || binding.GetLuksUuid() != spec.GetEscrowRotate().GetTarget().GetLuksUuid() {
		t.Fatal("root identity binding overwrote the provider-selected free slot")
	}
	challenge := new(agentv1.DeviceActionChallenge)
	if err := f.svc.authority.Verify(t.Context(), record.GetChallengeProof(), challenge, 1, publicOf(durable(t, f.svc).GetIdentityPrivateKey())); err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(challenge.GetNativePlan().GetRecoveryBinding(), binding) {
		t.Fatal("signed challenge lost the frozen nonzero recovery slot")
	}
	actionStart(t, f.svc, intent.GetActionId(), f.actionGrant(t, intent))
	status := awaitDeviceAction(t, f.svc, intent.GetActionId(), agentv1.DeviceActionState_DEVICE_ACTION_STATE_AWAITING_ESCROW)
	if status.GetVerification().GetEscrow().GetNewKeyslot() != binding.GetNewKeyslot() {
		t.Fatal("staged recovery did not retain its signed OAEP slot binding")
	}
}

func (f *deviceActionFixture) escrowReceipt(t *testing.T, record *agentv1.DeviceActionRecord, version uint64) []byte {
	t.Helper()
	i, e := record.GetIntent(), record.GetVerification().GetEscrow()
	digest, err := digestMessage(e)
	if err != nil {
		t.Fatal(err)
	}
	return mustSign(t, f.svc.authority, &agentv1.DeviceActionEscrowReceipt{DeploymentId: i.GetDeploymentId(), DeviceId: i.GetDeviceId(), EnrollmentGeneration: i.GetEnrollmentGeneration(), ActionId: i.GetActionId(), IntentSha256: record.GetIntentSha256(), EscrowSha256: digest, RecoveryKeySha256: e.GetRecoveryKeySha256(), NewKeyslot: e.GetNewKeyslot(), LuksUuid: e.GetLuksUuid(), EscrowKeyId: e.GetEscrowKeyId(), StoredAt: protoTimestamp(f.now), RootVersion: 1, DelegationVersion: version}, f.startKey)
}

func TestDeviceActionEscrowReceiptPrecedesRetirement(t *testing.T) {
	f := newDeviceActionFixture(t)
	i := f.actionIntent(t, 1, escrowActionSpec())
	f.actionPrepare(t, i)
	actionStart(t, f.svc, i.GetActionId(), f.actionGrant(t, i))
	awaiting := awaitDeviceAction(t, f.svc, i.GetActionId(), agentv1.DeviceActionState_DEVICE_ACTION_STATE_AWAITING_ESCROW)
	f.svc.operations.Wait()
	if f.actionNative.retirements.Load() != 0 || awaiting.GetVerification().GetEscrow() == nil {
		t.Fatal("old slot retired before durable custody receipt")
	}
	record, _ := deviceActionRow(t, f.svc, i.GetActionId())
	wrong := proto.CloneOf(record)
	wrong.Verification.Escrow.NewKeyslot++
	if _, err := f.svc.ConfirmDeviceActionEscrow(t.Context(), connect.NewRequest(&agentv1.ConfirmDeviceActionEscrowRequest{ActionId: i.GetActionId(), ReceiptEnvelope: f.escrowReceipt(t, wrong, 1)})); err == nil {
		t.Fatal("receipt for a different slot authorized retirement")
	}
	if f.actionNative.retirements.Load() != 0 {
		t.Fatal("rejected receipt retired old slot")
	}
	// A current receipt can use a newer delegation; the journal retains that
	// exact trust snapshot so future reads do not require current authority.
	f.actionDelegation(t, 2)
	receipt := f.escrowReceipt(t, record, 2)
	f.actionNative.checkGate = func() error {
		r, _, err := f.svc.store.LoadDeviceAction(t.Context(), i.GetActionId())
		if err != nil {
			return err
		}
		if r.GetState() != agentv1.DeviceActionState_DEVICE_ACTION_STATE_RETIRING_ESCROW || !bytes.Equal(r.GetEscrowReceiptEnvelope(), receipt) || r.GetReceiptRoot() == nil {
			return errInternal
		}
		return nil
	}
	if _, err := f.svc.ConfirmDeviceActionEscrow(t.Context(), connect.NewRequest(&agentv1.ConfirmDeviceActionEscrowRequest{ActionId: i.GetActionId(), ReceiptEnvelope: receipt})); err != nil {
		t.Fatal(err)
	}
	terminal := awaitDeviceAction(t, f.svc, i.GetActionId(), agentv1.DeviceActionState_DEVICE_ACTION_STATE_SUCCEEDED)
	f.svc.operations.Wait()
	if !proto.Equal(terminal.GetVerification().GetEscrow(), awaiting.GetVerification().GetEscrow()) {
		t.Fatal("retirement rewrote durable encrypted recovery material")
	}
	f.reopenActions(t)
	if _, err := f.svc.ConfirmDeviceActionEscrow(t.Context(), connect.NewRequest(&agentv1.ConfirmDeviceActionEscrowRequest{ActionId: i.GetActionId(), ReceiptEnvelope: receipt})); err != nil {
		t.Fatal(err)
	}
	if f.actionNative.effects.Load() != 1 || f.actionNative.retirements.Load() != 1 {
		t.Fatal("receipt retry repeated a native rotation phase")
	}
}

func TestDeviceActionEscrowRestartKeepsUnknownAndCiphertext(t *testing.T) {
	for _, retiring := range []bool{false, true} {
		t.Run(map[bool]string{false: "awaiting", true: "retiring"}[retiring], func(t *testing.T) {
			f := newDeviceActionFixture(t)
			i := f.actionIntent(t, 1, escrowActionSpec())
			f.actionPrepare(t, i)
			actionStart(t, f.svc, i.GetActionId(), f.actionGrant(t, i))
			awaitDeviceAction(t, f.svc, i.GetActionId(), agentv1.DeviceActionState_DEVICE_ACTION_STATE_AWAITING_ESCROW)
			f.svc.operations.Wait()
			record, _ := deviceActionRow(t, f.svc, i.GetActionId())
			receipt := f.escrowReceipt(t, record, 1)
			if retiring {
				if _, err := f.svc.consumeDeviceAction(t.Context(), record, receipt, true); err != nil {
					t.Fatal(err)
				}
			}
			f.reopenActions(t)
			status := awaitDeviceAction(t, f.svc, i.GetActionId(), agentv1.DeviceActionState_DEVICE_ACTION_STATE_OUTCOME_UNKNOWN)
			if !proto.Equal(status.GetVerification().GetEscrow(), record.GetVerification().GetEscrow()) {
				t.Fatal("restart discarded encrypted recovery material or slot evidence")
			}
			_, err := f.svc.ConfirmDeviceActionEscrow(t.Context(), connect.NewRequest(&agentv1.ConfirmDeviceActionEscrowRequest{ActionId: i.GetActionId(), ReceiptEnvelope: receipt}))
			if !retiring && err == nil {
				t.Fatal("unconsumed receipt revived unknown rotation")
			}
			if retiring && err != nil {
				t.Fatalf("consumed receipt historical lookup failed: %v", err)
			}
			if f.actionNative.retirements.Load() != 0 {
				t.Fatal("restart retired a slot or replayed ambiguous retirement")
			}
		})
	}
}

func TestDeviceActionCredentialIsOneShotBoundedAndNeverJournaled(t *testing.T) {
	f := newDeviceActionFixture(t)
	i := f.actionIntent(t, 1, escrowActionSpec())
	f.actionPrepare(t, i)
	secret := []byte("local-only one-time owner credential")
	request := &agentv1.SupplyDeviceActionCredentialRequest{ActionId: i.GetActionId(), Credential: bytes.Clone(secret)}
	if _, err := f.svc.SupplyDeviceActionCredential(t.Context(), connect.NewRequest(request)); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(request.Credential, make([]byte, len(secret))) {
		t.Fatal("RPC credential buffer was not cleared")
	}
	f.svc.mu.Lock()
	if got := f.svc.takeActionCredential(uuid.NewString()); len(got) != 0 {
		t.Fatal("credential crossed action identity")
	}
	got := f.svc.takeActionCredential(i.GetActionId())
	if !bytes.Equal(got, secret) {
		t.Fatal("credential was not delivered to its exact action")
	}
	releaseActionCredential(got)
	if got := f.svc.takeActionCredential(i.GetActionId()); len(got) != 0 {
		t.Fatal("credential replay succeeded")
	}
	f.svc.mu.Unlock()
	record, _ := deviceActionRow(t, f.svc, i.GetActionId())
	encoded, err := proto.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, secret) {
		t.Fatal("plaintext entered persistent action record")
	}
	if _, err := f.svc.SupplyDeviceActionCredential(t.Context(), connect.NewRequest(&agentv1.SupplyDeviceActionCredentialRequest{ActionId: i.GetActionId(), Credential: bytes.Clone(secret)})); err != nil {
		t.Fatal(err)
	}
	f.wall.Store(f.now.Add(31 * time.Second).UnixNano())
	f.svc.mu.Lock()
	defer f.svc.mu.Unlock()
	if got := f.svc.takeActionCredential(i.GetActionId()); len(got) != 0 || len(f.svc.actionCredential.value) != 0 {
		t.Fatal("expired credential retained authority or plaintext")
	}
}

func TestDeviceActionMissingCredentialDoesNotConsumeOrExtendGrant(t *testing.T) {
	f := newDeviceActionFixture(t)
	f.actionNative.requireCredential = true
	i := f.actionIntent(t, 1, escrowActionSpec())
	f.actionPrepare(t, i)
	grant := f.actionGrant(t, i)
	before, revision := deviceActionRow(t, f.svc, i.GetActionId())
	if _, err := f.svc.StartDeviceAction(t.Context(), connect.NewRequest(&agentv1.StartDeviceActionRequest{ActionId: i.GetActionId(), StartGrantEnvelope: grant})); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("missing credential admission: %v", err)
	}
	f.svc.operations.Wait()
	after, afterRevision := deviceActionRow(t, f.svc, i.GetActionId())
	if revision != afterRevision || !proto.Equal(before, after) || f.actionNative.effects.Load() != 0 {
		t.Fatal("missing local input consumed or renewed authority")
	}
	if _, err := f.svc.SupplyDeviceActionCredential(t.Context(), connect.NewRequest(&agentv1.SupplyDeviceActionCredentialRequest{ActionId: i.GetActionId(), Credential: []byte("one-use local input")})); err != nil {
		t.Fatal(err)
	}
	actionStart(t, f.svc, i.GetActionId(), grant)
	awaitDeviceAction(t, f.svc, i.GetActionId(), agentv1.DeviceActionState_DEVICE_ACTION_STATE_AWAITING_ESCROW)
	f.svc.operations.Wait()
	f.svc.mu.Lock()
	defer f.svc.mu.Unlock()
	if len(f.svc.actionCredential.value) != 0 || f.actionNative.effects.Load() != 1 {
		t.Fatal("credential retained after effect or duplicate execution")
	}
}
