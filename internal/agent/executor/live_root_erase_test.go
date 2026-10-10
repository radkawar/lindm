//go:build linux

package executor

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/agent/actionprovider"
)

// The native boundary is deterministic; actual root-device effects belong only
// in disposable encrypted guests. This exercises real journal+DSSE authority.
type liveRootBoundary struct {
	*actionBoundary
}

func (n *liveRootBoundary) Observe(ctx context.Context, spec *agentv1.DeviceActionSpec) (*agentv1.DeviceActionObservation, error) {
	before, err := n.actionBoundary.Observe(ctx, spec)
	before.RecoveryEnvironment, before.OffTargetJournal = false, false
	for index, target := range spec.GetCryptoErase().GetTargets() {
		before.CryptoEraseTargets = append(before.CryptoEraseTargets, &agentv1.CryptoEraseTargetPlan{Target: proto.CloneOf(target), MetadataSha256: bytes.Repeat([]byte{3}, 32), LuksHeaderBytes: 16 << 20, RootBacking: index == 0, RootMappingSha256: bytes.Repeat([]byte{4}, 32)})
	}
	return before, err
}

func (n *liveRootBoundary) Plan(_ context.Context, spec *agentv1.DeviceActionSpec, before *agentv1.DeviceActionObservation) (*agentv1.DeviceActionPlan, error) {
	plan := &agentv1.DeviceActionPlan{Spec: proto.CloneOf(spec), Before: proto.CloneOf(before)}
	for _, target := range before.GetCryptoEraseTargets() {
		plan.CryptoEraseTargets = append(plan.CryptoEraseTargets, proto.CloneOf(target))
	}
	return plan, nil
}

func (n *liveRootBoundary) Apply(ctx context.Context, plan *agentv1.DeviceActionPlan, credential []byte, gate func(context.Context) error) (*agentv1.DeviceActionVerification, error) {
	result, err := n.actionBoundary.Apply(ctx, plan, credential, gate)
	if result != nil {
		result.After.Encrypted = false
		result.After.CryptoEraseTargets = nil
		for _, target := range plan.GetCryptoEraseTargets() {
			result.CryptoEraseResults = append(result.CryptoEraseResults, &agentv1.CryptoEraseTargetResult{Target: proto.CloneOf(target.GetTarget()), HeaderBytes: target.GetLuksHeaderBytes(), NativeLuksErase: true, RawZeroVerified: true, MetadataAbsent: true})
		}
	}
	return result, err
}

func prepareLiveRootFixture(t *testing.T) (*deviceActionFixture, *agentv1.DeviceActionIntent, []byte, []byte) {
	t.Helper()
	f := newDeviceActionFixture(t)
	f.svc.actionProvider = &liveRootBoundary{f.actionNative}
	f.svc.pinLiveRoot = func() error { return nil } // no process-global mlock in unit tests
	spec := &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_CryptoErase{CryptoErase: &agentv1.CryptoEraseAction{Mode: agentv1.CryptoEraseMode_CRYPTO_ERASE_MODE_LIVE_ROOT_HEADER, Targets: []*agentv1.StorageTarget{{IdentityBasis: agentv1.StorageIdentityBasis_STORAGE_IDENTITY_BASIS_WWN_SERIAL, LuksUuid: uuid.NewString(), Wwn: "root-wwn", Serial: "root-serial", SizeBytes: 1 << 30}, {IdentityBasis: agentv1.StorageIdentityBasis_STORAGE_IDENTITY_BASIS_WWN_SERIAL, LuksUuid: uuid.NewString(), Wwn: "data-wwn", Serial: "data-serial", SizeBytes: 1 << 30}}}}}
	i := f.actionIntent(t, 1, spec)
	intent := f.actionPrepare(t, i)
	binding := &agentv1.DeviceActionApprovalBinding{DeviceId: i.GetDeviceId(), EnrollmentGeneration: i.GetEnrollmentGeneration(), SpecSha256: i.GetSpecSha256(), ExpiresAt: i.GetExpiresAt()}
	first := &agentv1.DeviceActionHumanApproval{ActorId: i.GetActorId(), AuthorizationVersion: 1, Binding: proto.CloneOf(binding)}
	second := &agentv1.DeviceActionHumanApproval{ActorId: uuid.NewString(), AuthorizationVersion: 1, Binding: proto.CloneOf(binding)}
	return f, i, intent, f.actionGrant(t, i, first, second)
}

func TestLiveRootClosesJournalBeforeEffectAndAttestsOnlyMemory(t *testing.T) {
	for _, failure := range []bool{false, true} {
		t.Run(map[bool]string{false: "success", true: "native-error"}[failure], func(t *testing.T) {
			f, i, intent, grant := prepareLiveRootFixture(t)
			public := publicOf(durable(t, f.svc).GetIdentityPrivateKey())
			_, runningRevision := deviceActionRow(t, f.svc, i.GetActionId())
			f.actionNative.failAfterEffect = failure
			f.actionNative.checkGate = func() error {
				f.svc.mu.Lock()
				defer f.svc.mu.Unlock()
				if f.svc.liveRoot == nil || !f.svc.liveRoot.status.GetReportOnly() || f.svc.liveRoot.record.GetState() != agentv1.DeviceActionState_DEVICE_ACTION_STATE_RUNNING || !bytes.Equal(f.svc.liveRoot.record.GetStartGrantEnvelope(), grant) {
					return errors.New("effect preceded consumed memory fence")
				}
				if _, err := f.svc.loadBound(t.Context()); !errors.Is(err, errServiceRejected) {
					return errors.New("journal remained accessible after memory fence")
				}
				return nil
			}
			actionStart(t, f.svc, i.GetActionId(), grant)
			state := agentv1.DeviceActionState_DEVICE_ACTION_STATE_SUCCEEDED
			if failure {
				state = agentv1.DeviceActionState_DEVICE_ACTION_STATE_OUTCOME_UNKNOWN
			}
			terminal := awaitDeviceAction(t, f.svc, i.GetActionId(), state)
			if !terminal.GetReportOnly() || !terminal.GetVolatileResult() {
				t.Fatal("memory-only status misrepresented as durable")
			}
			connection, err := f.svc.getConnection(t.Context(), &agentv1.GetConnectionRequest{})
			if err != nil || !connection.GetDeviceActionReportOnly() || !connection.GetSessionEpochUsable() {
				t.Fatalf("report connection lost pinned session: %v", err)
			}
			prepared, err := f.svc.PrepareDeviceAction(t.Context(), connect.NewRequest(&agentv1.PrepareDeviceActionRequest{IntentEnvelope: intent}))
			if err != nil || !proto.Equal(prepared.Msg.GetStatus(), terminal) {
				t.Fatalf("lost-response prepare did not use memory: %v", err)
			}
			for _, nonceByte := range []byte{7, 8} {
				nonce := bytes.Repeat([]byte{nonceByte}, 32)
				response, err := f.svc.AttestDeviceAction(t.Context(), connect.NewRequest(&agentv1.AttestDeviceActionRequest{ActionId: i.GetActionId(), Nonce: nonce}))
				if err != nil {
					t.Fatal(err)
				}
				attestation := new(agentv1.DeviceActionAttestation)
				if err := f.svc.authority.Verify(t.Context(), response.Msg.GetAttestationEnvelope(), attestation, 1, public); err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(attestation.GetNonce(), nonce) || !proto.Equal(attestation.GetStatus(), terminal) || attestation.GetActionRevision() <= uint64(runningRevision) {
					t.Fatal("nonce or terminal memory proof lost")
				}
			}
			if got := actionStart(t, f.svc, i.GetActionId(), grant); !proto.Equal(got, terminal) || f.actionNative.effects.Load() != 1 {
				t.Fatal("report failure/retry reexecuted erase")
			}
			if _, err := f.svc.StartDeviceAction(t.Context(), connect.NewRequest(&agentv1.StartDeviceActionRequest{ActionId: i.GetActionId(), StartGrantEnvelope: append(bytes.Clone(grant), ' ')})); err == nil {
				t.Fatal("changed grant accepted in memory mode")
			}
			f.reopenActions(t)
			recovered := awaitDeviceAction(t, f.svc, i.GetActionId(), agentv1.DeviceActionState_DEVICE_ACTION_STATE_OUTCOME_UNKNOWN)
			if recovered.GetVolatileResult() || recovered.GetVerification() != nil {
				t.Fatal("post-erase memory result was persisted")
			}
			actionStart(t, f.svc, i.GetActionId(), grant)
			if f.actionNative.effects.Load() != 1 {
				t.Fatal("memory loss replayed erase")
			}
		})
	}
}

func TestLiveRootCannotConsumeWithoutPinnedMemory(t *testing.T) {
	f, i, _, grant := prepareLiveRootFixture(t)
	f.svc.pinLiveRoot = func() error { return actionprovider.ErrUnsupported }
	if _, err := f.svc.StartDeviceAction(t.Context(), connect.NewRequest(&agentv1.StartDeviceActionRequest{ActionId: i.GetActionId(), StartGrantEnvelope: grant})); err == nil {
		t.Fatal("memory pin failure authorized effects")
	}
	if f.actionNative.effects.Load() != 0 || f.svc.liveRoot != nil {
		t.Fatal("memory pin failure crossed irreversible gate")
	}
	r, _ := deviceActionRow(t, f.svc, i.GetActionId())
	if len(r.GetStartGrantEnvelope()) != 0 {
		t.Fatal("unavailable pinned memory consumed native authority")
	}
}

func TestLiveRootCompletionRejectsMissingAggregateProof(t *testing.T) {
	plan := &agentv1.DeviceActionPlan{CryptoEraseTargets: []*agentv1.CryptoEraseTargetPlan{{Target: &agentv1.StorageTarget{IdentityBasis: agentv1.StorageIdentityBasis_STORAGE_IDENTITY_BASIS_WWN_SERIAL, LuksUuid: uuid.NewString(), Wwn: "fixture-wwn", Serial: "fixture-serial", SizeBytes: 1 << 30}, LuksHeaderBytes: 16 << 20}}}
	for _, result := range []*agentv1.DeviceActionVerification{{Verified: true}, {Verified: true, CryptoEraseResults: []*agentv1.CryptoEraseTargetResult{{Target: plan.CryptoEraseTargets[0].Target, HeaderBytes: 16 << 20, MetadataAbsent: true}}}} {
		if liveRootComplete(plan, result) {
			t.Fatal("partial aggregate evidence claimed success")
		}
	}
}
