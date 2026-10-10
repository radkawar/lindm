//go:build linux

package executor

import (
	"bytes"
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/agent/actionprovider"
)

// actionBoundary is a deterministic effect gate, not a native storage emulator.
// These tests exercise actual DSSE, current trust, SQLite durability and restart;
// native commands are qualified separately on disposable guests.
type actionBoundary struct {
	applies           atomic.Int32
	effects           atomic.Int32
	retirements       atomic.Int32
	beforeGate        chan struct{}
	releaseGate       chan struct{}
	checkGate         func() error
	failAfterEffect   bool
	requireCredential bool
	occupiedKeyslots  []uint32
}

func (n *actionBoundary) Observe(_ context.Context, spec *agentv1.DeviceActionSpec) (*agentv1.DeviceActionObservation, error) {
	o := &agentv1.DeviceActionObservation{ObservedAt: protoTimestamp(time.Date(2031, 9, 1, 0, 0, 0, 0, time.UTC)), Supported: true, RecoveryEnvironment: true, OffTargetJournal: true}
	if r := spec.GetEscrowRotate(); r != nil {
		o.Target, o.Encrypted, o.LindmKeyslots, o.OccupiedKeyslots = proto.CloneOf(r.GetTarget()), true, []uint32{1}, []uint32{0, 1}
		if n.occupiedKeyslots != nil {
			o.OccupiedKeyslots = append([]uint32(nil), n.occupiedKeyslots...)
		}
	}
	if r := spec.GetCryptoErase(); r != nil {
		o.Target, o.Encrypted = proto.CloneOf(r.GetTarget()), true
	}
	return o, nil
}
func (n *actionBoundary) Plan(_ context.Context, spec *agentv1.DeviceActionSpec, before *agentv1.DeviceActionObservation) (*agentv1.DeviceActionPlan, error) {
	plan := &agentv1.DeviceActionPlan{Spec: proto.CloneOf(spec), Before: proto.CloneOf(before)}
	if rotate := spec.GetEscrowRotate(); rotate != nil {
		var slot uint32
		for ; slot < 32; slot++ {
			occupied := false
			for _, existing := range before.GetOccupiedKeyslots() {
				occupied = occupied || existing == slot
			}
			if !occupied {
				break
			}
		}
		plan.RecoveryBinding = &agentv1.RecoveryKeyBinding{LuksUuid: rotate.GetTarget().GetLuksUuid(), NewKeyslot: slot}
	}
	return plan, nil
}
func (n *actionBoundary) Apply(ctx context.Context, plan *agentv1.DeviceActionPlan, credential []byte, gate func(context.Context) error) (*agentv1.DeviceActionVerification, error) {
	n.applies.Add(1)
	if n.requireCredential && len(credential) == 0 {
		return nil, actionprovider.ErrCredential
	}
	if n.beforeGate != nil {
		close(n.beforeGate)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-n.releaseGate:
		}
	}
	if err := gate(ctx); err != nil {
		return nil, err
	}
	if n.checkGate != nil {
		if err := n.checkGate(); err != nil {
			return nil, err
		}
	}
	n.effects.Add(1)
	if n.failAfterEffect {
		return nil, errors.New("interrupted native effect")
	}
	result := &agentv1.DeviceActionVerification{Verified: true, After: proto.CloneOf(plan.GetBefore()), Evidence: "effect boundary completed"}
	if rotate := plan.GetSpec().GetEscrowRotate(); rotate != nil {
		result.Verified = false
		result.Escrow = &agentv1.DeviceActionEscrow{EscrowKeyId: rotate.GetEscrowKeyId(), Ciphertext: []byte("encrypted custody fixture, never plaintext"), RecoveryKeySha256: bytes.Repeat([]byte{8}, 32), NewKeyslot: plan.GetRecoveryBinding().GetNewKeyslot(), LuksUuid: rotate.GetTarget().GetLuksUuid(), MetadataSha256: bytes.Repeat([]byte{9}, 32), TokenId: 3}
	}
	return result, nil
}
func (n *actionBoundary) Verify(_ context.Context, _ *agentv1.DeviceActionPlan, result *agentv1.DeviceActionVerification) (*agentv1.DeviceActionVerification, error) {
	return proto.CloneOf(result), nil
}
func (n *actionBoundary) ConfirmEscrow(ctx context.Context, _ *agentv1.DeviceActionPlan, result *agentv1.DeviceActionVerification, _ []byte, gate func(context.Context) error) (*agentv1.DeviceActionVerification, error) {
	if err := gate(ctx); err != nil {
		return nil, err
	}
	if n.checkGate != nil {
		if err := n.checkGate(); err != nil {
			return nil, err
		}
	}
	n.retirements.Add(1)
	verified := proto.CloneOf(result)
	verified.Verified = true
	return verified, nil
}

type deviceActionFixture struct {
	*serviceFixture
	actionNative *actionBoundary
}

func newDeviceActionFixture(t *testing.T) *deviceActionFixture {
	t.Helper()
	f := &deviceActionFixture{serviceFixture: newServiceFixture(t, false, true), actionNative: &actionBoundary{}}
	f.svc.actionProvider = f.actionNative
	f.actionDelegation(t, 1)
	return f
}
func (f *deviceActionFixture) actionDelegation(t *testing.T, version uint64) {
	t.Helper()
	plan, start := delegate(t, f.planKey), delegate(t, f.startKey)
	plan.Capabilities = []string{"device.lock-sessions.v1", "device.release-lock.v1", "device.escrow-rotate.v1", "device.crypto-erase.v1", "device.restart.v1", "device.shutdown.v1", "device.refresh-inventory.v1"}
	start.Capabilities = append([]string(nil), plan.Capabilities...)
	start.Role = agentv1.ExecutionSignerRole_EXECUTION_SIGNER_ROLE_START
	callTrust(t, f.svc, &agentv1.UpdateExecutionTrustRequest{DelegationEnvelope: mustSign(t, f.svc.authority, delegationDocument(f.fix.deploy.String(), 1, version, 0, f.now, plan, start), f.fix.rootKey)})
}
func (f *deviceActionFixture) actionIntent(t *testing.T, sequence uint64, spec *agentv1.DeviceActionSpec) *agentv1.DeviceActionIntent {
	t.Helper()
	state := durable(t, f.svc)
	if spec == nil {
		spec = &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_LockSessions{LockSessions: &agentv1.LockSessionsAction{}}}
	}
	digest, err := digestMessage(spec)
	if err != nil {
		t.Fatal(err)
	}
	return &agentv1.DeviceActionIntent{DeploymentId: f.fix.deploy.String(), DeviceId: state.GetDeviceId(), EnrollmentGeneration: state.GetEnrollmentGeneration(), ActionId: uuid.NewString(), ActorId: uuid.NewString(), ActionSequence: sequence, RootVersion: 1, DelegationVersion: 1, AuthorizationVersion: 1, NotBefore: protoTimestamp(f.now.Add(-time.Second)), ExpiresAt: protoTimestamp(f.now.Add(5 * time.Minute)), Spec: spec, SpecSha256: digest}
}
func (f *deviceActionFixture) actionPrepare(t *testing.T, intent *agentv1.DeviceActionIntent) []byte {
	t.Helper()
	envelope := mustSign(t, f.svc.authority, intent, f.planKey)
	if _, err := f.svc.PrepareDeviceAction(t.Context(), connect.NewRequest(&agentv1.PrepareDeviceActionRequest{IntentEnvelope: envelope})); err != nil {
		t.Fatal(err)
	}
	return envelope
}
func deviceActionRow(t *testing.T, svc *Service, id string) (*agentv1.DeviceActionRecord, int64) {
	t.Helper()
	r, revision, err := svc.store.LoadDeviceAction(t.Context(), id)
	if err != nil {
		t.Fatal(err)
	}
	return r, revision
}
func (f *deviceActionFixture) actionGrant(t *testing.T, i *agentv1.DeviceActionIntent, approvals ...*agentv1.DeviceActionHumanApproval) []byte {
	t.Helper()
	r, _ := deviceActionRow(t, f.svc, i.GetActionId())
	return mustSign(t, f.svc.authority, &agentv1.DeviceActionStartGrant{Challenge: r.GetChallenge(), ActorId: i.GetActorId(), AuthorizationVersion: i.GetAuthorizationVersion(), RootVersion: 1, DelegationVersion: 1, NotBefore: r.GetChallenge().GetIssuedAt(), ExpiresAt: r.GetChallenge().GetExpiresAt(), Approvals: approvals}, f.startKey)
}
func actionStart(t *testing.T, svc *Service, id string, grant []byte) *agentv1.DeviceActionStatus {
	t.Helper()
	r, err := svc.StartDeviceAction(t.Context(), connect.NewRequest(&agentv1.StartDeviceActionRequest{ActionId: id, StartGrantEnvelope: grant}))
	if err != nil {
		t.Fatal(err)
	}
	return r.Msg.GetStatus()
}
func awaitDeviceAction(t *testing.T, svc *Service, id string, state agentv1.DeviceActionState) *agentv1.DeviceActionStatus {
	t.Helper()
	timer, tick := time.NewTimer(5*time.Second), time.NewTicker(time.Millisecond)
	defer timer.Stop()
	defer tick.Stop()
	for {
		r, err := svc.GetDeviceAction(t.Context(), connect.NewRequest(&agentv1.GetDeviceActionRequest{ActionId: id}))
		if err != nil {
			t.Fatal(err)
		}
		if r.Msg.GetStatus().GetState() == state {
			return r.Msg.GetStatus()
		}
		if r.Msg.GetStatus().GetCompletedAt() != nil {
			t.Fatalf("unexpected terminal state %s", r.Msg.GetStatus().GetState())
		}
		select {
		case <-timer.C:
			t.Fatal("action did not reach durable state")
		case <-tick.C:
		}
	}
}
func (f *deviceActionFixture) reopenActions(t *testing.T) {
	t.Helper()
	directory := f.svc.directory
	if err := f.svc.Close(); err != nil {
		t.Fatal(err)
	}
	opts := append(f.options(), WithActionProvider(f.actionNative))
	svc, err := New(t.Context(), directory, opts...)
	if err != nil {
		t.Fatal(err)
	}
	f.svc = svc
	t.Cleanup(func() { _ = svc.Close() })
}

func TestDeviceActionDurableGateHistoricalReplayAndAttestation(t *testing.T) {
	f := newDeviceActionFixture(t)
	i := f.actionIntent(t, 1, nil)
	f.actionPrepare(t, i)
	grant := f.actionGrant(t, i)
	f.actionNative.checkGate = func() error {
		r, _, err := f.svc.store.LoadDeviceAction(t.Context(), i.GetActionId())
		if err != nil {
			return err
		}
		if r.GetState() != agentv1.DeviceActionState_DEVICE_ACTION_STATE_RUNNING || !bytes.Equal(r.GetStartGrantEnvelope(), grant) {
			return errors.New("effect preceded durable consumption")
		}
		return nil
	}
	actionStart(t, f.svc, i.GetActionId(), grant)
	terminal := awaitDeviceAction(t, f.svc, i.GetActionId(), agentv1.DeviceActionState_DEVICE_ACTION_STATE_SUCCEEDED)
	_, revision := deviceActionRow(t, f.svc, i.GetActionId())
	f.wall.Store(f.now.Add(6 * time.Minute).UnixNano())
	if got := actionStart(t, f.svc, i.GetActionId(), grant); !proto.Equal(got, terminal) {
		t.Fatal("retry rewrote historical status")
	}
	_, after := deviceActionRow(t, f.svc, i.GetActionId())
	if revision != after || f.actionNative.effects.Load() != 1 || f.actionNative.applies.Load() != 1 {
		t.Fatal("grant caused duplicate effects or writes")
	}
	if _, err := f.svc.StartDeviceAction(t.Context(), connect.NewRequest(&agentv1.StartDeviceActionRequest{ActionId: i.GetActionId(), StartGrantEnvelope: append(bytes.Clone(grant), ' ')})); connect.CodeOf(err) != connect.CodeAlreadyExists {
		t.Fatalf("changed grant accepted: %v", err)
	}
	nonce := bytes.Repeat([]byte{4}, 32)
	response, err := f.svc.AttestDeviceAction(t.Context(), connect.NewRequest(&agentv1.AttestDeviceActionRequest{ActionId: i.GetActionId(), Nonce: nonce}))
	if err != nil {
		t.Fatal(err)
	}
	attestation := new(agentv1.DeviceActionAttestation)
	if err := f.svc.authority.Verify(t.Context(), response.Msg.GetAttestationEnvelope(), attestation, 1, publicOf(durable(t, f.svc).GetIdentityPrivateKey())); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(attestation.GetNonce(), nonce) || !proto.Equal(attestation.GetStatus(), terminal) || attestation.GetActionRevision() != uint64(revision) {
		t.Fatal("attestation lost nonce or protected evidence")
	}
}

func TestDeviceActionEffectGateRejectsChangedAuthorityAndClock(t *testing.T) {
	for _, cause := range []string{"boottime", "wall", "reboot", "delegation"} {
		t.Run(cause, func(t *testing.T) {
			f := newDeviceActionFixture(t)
			f.actionNative.beforeGate, f.actionNative.releaseGate = make(chan struct{}), make(chan struct{})
			i := f.actionIntent(t, 1, nil)
			f.actionPrepare(t, i)
			grant := f.actionGrant(t, i)
			done := make(chan error, 1)
			go func() {
				_, err := f.svc.StartDeviceAction(t.Context(), connect.NewRequest(&agentv1.StartDeviceActionRequest{ActionId: i.GetActionId(), StartGrantEnvelope: grant}))
				done <- err
			}()
			waitBoundary(t, f.actionNative.beforeGate)
			switch cause {
			case "boottime":
				f.bootClock.Add(uint64(31 * time.Second))
			case "wall":
				f.wall.Store(f.now.Add(31 * time.Second).UnixNano())
			case "reboot":
				f.boot = uuid.NewString()
			case "delegation":
				f.actionDelegation(t, 2)
			}
			close(f.actionNative.releaseGate)
			if err := <-done; err == nil {
				t.Fatal("changed admission facts permitted effect")
			}
			if f.actionNative.effects.Load() != 0 {
				t.Fatal("rejected authority mutated native state")
			}
		})
	}
}

func TestDeviceActionRestartNeverReplaysConsumedWork(t *testing.T) {
	for _, consumed := range []bool{false, true} {
		t.Run(map[bool]string{false: "prepared", true: "consumed"}[consumed], func(t *testing.T) {
			f := newDeviceActionFixture(t)
			i := f.actionIntent(t, 1, nil)
			f.actionPrepare(t, i)
			grant := f.actionGrant(t, i)
			if consumed {
				r, _ := deviceActionRow(t, f.svc, i.GetActionId())
				if _, err := f.svc.consumeDeviceAction(t.Context(), r, grant, false); err != nil {
					t.Fatal(err)
				}
			}
			f.reopenActions(t)
			expected := agentv1.DeviceActionState_DEVICE_ACTION_STATE_EXPIRED
			if consumed {
				expected = agentv1.DeviceActionState_DEVICE_ACTION_STATE_OUTCOME_UNKNOWN
			}
			awaitDeviceAction(t, f.svc, i.GetActionId(), expected)
			if consumed {
				actionStart(t, f.svc, i.GetActionId(), grant)
			} else if _, err := f.svc.StartDeviceAction(t.Context(), connect.NewRequest(&agentv1.StartDeviceActionRequest{ActionId: i.GetActionId(), StartGrantEnvelope: grant})); err == nil {
				t.Fatal("restart revived unconsumed grant")
			}
			if f.actionNative.applies.Load() != 0 || f.actionNative.effects.Load() != 0 {
				t.Fatal("restart replayed imperative effect")
			}
		})
	}
}

func TestDeviceActionPartialEffectRemainsUnknown(t *testing.T) {
	f := newDeviceActionFixture(t)
	f.actionNative.failAfterEffect = true
	i := f.actionIntent(t, 1, nil)
	f.actionPrepare(t, i)
	grant := f.actionGrant(t, i)
	actionStart(t, f.svc, i.GetActionId(), grant)
	awaitDeviceAction(t, f.svc, i.GetActionId(), agentv1.DeviceActionState_DEVICE_ACTION_STATE_OUTCOME_UNKNOWN)
	f.reopenActions(t)
	actionStart(t, f.svc, i.GetActionId(), grant)
	if f.actionNative.effects.Load() != 1 {
		t.Fatal("unknown effect was replayed")
	}
}

func TestDeviceActionDestructiveApprovalExactBinding(t *testing.T) {
	f := newDeviceActionFixture(t)
	spec := &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_CryptoErase{CryptoErase: &agentv1.CryptoEraseAction{Mode: agentv1.CryptoEraseMode_CRYPTO_ERASE_MODE_OFFLINE, Target: &agentv1.StorageTarget{LuksUuid: uuid.NewString(), SizeBytes: 1 << 30}}}}
	i := f.actionIntent(t, 1, spec)
	f.actionPrepare(t, i)
	if _, err := f.svc.StartDeviceAction(t.Context(), connect.NewRequest(&agentv1.StartDeviceActionRequest{ActionId: i.GetActionId(), StartGrantEnvelope: f.actionGrant(t, i)})); err == nil {
		t.Fatal("destructive action accepted without two humans")
	}
	binding := &agentv1.DeviceActionApprovalBinding{DeviceId: i.GetDeviceId(), EnrollmentGeneration: i.GetEnrollmentGeneration(), SpecSha256: i.GetSpecSha256(), ExpiresAt: i.GetExpiresAt()}
	first := &agentv1.DeviceActionHumanApproval{ActorId: i.GetActorId(), AuthorizationVersion: 1, Binding: proto.CloneOf(binding)}
	second := &agentv1.DeviceActionHumanApproval{ActorId: uuid.NewString(), AuthorizationVersion: 1, Binding: proto.CloneOf(binding)}
	second.Binding.SpecSha256 = bytes.Repeat([]byte{5}, 32)
	if _, err := f.svc.StartDeviceAction(t.Context(), connect.NewRequest(&agentv1.StartDeviceActionRequest{ActionId: i.GetActionId(), StartGrantEnvelope: f.actionGrant(t, i, first, second)})); err == nil {
		t.Fatal("mismatched human approval accepted")
	}
	if f.actionNative.effects.Load() != 0 {
		t.Fatal("rejected approval reached effect")
	}
	second.Binding = proto.CloneOf(binding)
	actionStart(t, f.svc, i.GetActionId(), f.actionGrant(t, i, first, second))
	awaitDeviceAction(t, f.svc, i.GetActionId(), agentv1.DeviceActionState_DEVICE_ACTION_STATE_SUCCEEDED)
}
