//go:build linux

package executor

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/agent/fileprovider"
	"lindm/internal/agent/journal"
)

// ledgerNative follows the ownership contract of every ledger-owning provider
// against the executor's real journal: its effect claims and begins the ledger
// before the start gate, and its Plan refuses over an UNKNOWN ledger with an
// outcome-unknown sentinel (fileprovider's, as for the interrupted managed
// file seen live). Its effect is always interrupted after the start gate.
type ledgerNative struct {
	nativeResource
	store     *journal.Store
	intent    *agentv1.ResourceExecutionIntent
	dimension agentv1.ResourceOwnedDimension
	plans     atomic.Int32
	applies   atomic.Int32
}

func (n *ledgerNative) ledger(ctx context.Context) (*agentv1.ResourceOwnershipLedger, error) {
	ledger, err := n.store.LoadResourceOwnership(ctx, n.intent.GetDeploymentId(), n.intent.GetDeviceId(), n.intent.GetEnrollmentGeneration(), n.intent.GetDesired().GetRef())
	if errors.Is(err, journal.ErrResourceOwnershipNotFound) {
		return nil, nil
	}
	return ledger, err
}

func (n *ledgerNative) Plan(ctx context.Context, desired *resourcev1.ResourceDesiredState, operation resourcev1.ResourceOperation) (*resourcev1.ResourcePlan, error) {
	n.plans.Add(1)
	ledger, err := n.ledger(ctx)
	if err != nil {
		return nil, err
	}
	if ledger.GetState() == agentv1.ResourceOwnershipState_RESOURCE_OWNERSHIP_STATE_UNKNOWN {
		return nil, fileprovider.ErrOutcomeUnknown
	}
	plan, err := n.nativeResource.Plan(ctx, desired, operation)
	if err != nil {
		return nil, err
	}
	digest, err := journal.ResourceOwnershipDigest(ledger)
	if err != nil {
		return nil, err
	}
	plan.OwnershipRevisionSha256 = digest[:]
	return plan, nil
}

func (n *ledgerNative) Apply(ctx context.Context, plan *resourcev1.ResourcePlan, authorize func(context.Context) error) (*resourcev1.ResourceVerification, error) {
	n.applies.Add(1)
	snapshot := &agentv1.ResourceOwnershipSnapshot{Observation: proto.CloneOf(plan.GetBefore())}
	claimed, err := n.store.ClaimResourceOwnership(ctx, n.intent.GetActionId(), 0, snapshot)
	if err != nil {
		return nil, err
	}
	if _, err := n.store.BeginResourceOwnershipEffect(ctx, n.intent.GetActionId(), int64(claimed.GetRevision()), snapshot, []agentv1.ResourceOwnedDimension{n.dimension}); err != nil {
		return nil, err
	}
	if err := authorize(ctx); err != nil {
		return nil, err
	}
	return nil, errors.New("effect helper killed")
}

// ledgerNatives opens one ledgerNative per action around inner.
type ledgerNatives struct {
	mu      sync.Mutex
	natives map[string]*ledgerNative
}

func (l *ledgerNatives) open(svc *Service, inner nativeResource, dimension agentv1.ResourceOwnedDimension) {
	l.natives = map[string]*ledgerNative{}
	svc.openResource = func(_ context.Context, intent *agentv1.ResourceExecutionIntent, _ secretAccessor) (nativeResource, error) {
		return l.of(svc, inner, dimension, intent), nil
	}
}

func (l *ledgerNatives) of(svc *Service, inner nativeResource, dimension agentv1.ResourceOwnedDimension, intent *agentv1.ResourceExecutionIntent) *ledgerNative {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.natives[intent.GetActionId()] == nil {
		l.natives[intent.GetActionId()] = &ledgerNative{nativeResource: inner, store: svc.store, intent: intent, dimension: dimension}
	}
	return l.natives[intent.GetActionId()]
}

func (l *ledgerNatives) applies() int32 {
	l.mu.Lock()
	defer l.mu.Unlock()
	total := int32(0)
	for _, native := range l.natives {
		total += native.applies.Load()
	}
	return total
}

// interruptEffect runs a granted action whose effect is interrupted after the
// start gate and returns the UNKNOWN ledger it leaves.
func interruptEffect(t *testing.T, f *resourceFixture, natives *ledgerNatives, intent *agentv1.ResourceExecutionIntent) *agentv1.ResourceOwnershipLedger {
	t.Helper()
	startResource(t, f.svc, intent.GetActionId(), f.grant(t, intent))
	if status := awaitResourceTerminal(t, f.svc, intent.GetActionId()); status.GetState() != agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_OUTCOME_UNKNOWN {
		t.Fatalf("interrupted effect = %v", status)
	}
	natives.mu.Lock()
	native := natives.natives[intent.GetActionId()]
	natives.mu.Unlock()
	fence, err := native.ledger(t.Context())
	if err != nil || fence.GetState() != agentv1.ResourceOwnershipState_RESOURCE_OWNERSHIP_STATE_UNKNOWN || fence.GetEffectActionId() != intent.GetActionId() {
		t.Fatalf("interrupted effect left no UNKNOWN ledger: %v %v", fence, err)
	}
	return fence
}

// assertOwnershipUnknownRefusal checks the durable, attested, effect-free
// refusal of a later action and that the UNKNOWN fence is unchanged.
func assertOwnershipUnknownRefusal(t *testing.T, f *resourceFixture, natives *ledgerNatives, intent *agentv1.ResourceExecutionIntent, prepared *agentv1.PrepareResourceExecutionResponse, envelope []byte, fence *agentv1.ResourceOwnershipLedger) {
	t.Helper()
	status := prepared.GetStatus()
	refusal := status.GetAdmissionRefusal()
	if status.GetState() != agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_FAILED || status.GetFailure() != agentv1.ResourceExecutionFailure_RESOURCE_EXECUTION_FAILURE_PRECONDITION ||
		refusal.GetReason() != agentv1.ResourceAdmissionRefusalReason_RESOURCE_ADMISSION_REFUSAL_REASON_OWNERSHIP_UNKNOWN || !refusal.GetNativeEvidenceUnavailable() || refusal.GetDetail() != "" ||
		!proto.Equal(refusal.GetRef(), intent.GetDesired().GetRef()) || refusal.GetOperation() != intent.GetOperation() {
		t.Fatalf("later action over UNKNOWN ownership = %v", status)
	}
	if status.GetBefore() != nil || status.GetStartedAt() != nil || status.GetVerification() != nil || status.GetPreparationOutcome() != nil || status.GetCompletedAt() == nil || prepared.GetNativePlan() != nil || len(prepared.GetChallengeProof()) != 0 {
		t.Fatal("refusal fabricated native evidence or effect authority")
	}
	if _, attested := attestResource(t, f, status); !proto.Equal(attested.GetStatus(), status) {
		t.Fatal("signed history lost the refusal")
	}
	// The relay's next cycle replays the same prepare: history, not another
	// native preflight.
	plans := natives.of(f.svc, nil, 0, intent).plans.Load()
	retry, err := f.svc.PrepareResourceExecution(t.Context(), connect.NewRequest(&agentv1.PrepareResourceExecutionRequest{IntentEnvelope: envelope}))
	if err != nil || !proto.Equal(retry.Msg, prepared) || natives.of(f.svc, nil, 0, intent).plans.Load() != plans {
		t.Fatalf("exact retry reran preflight: %v", err)
	}
	if _, err := f.svc.StartResourceExecution(t.Context(), connect.NewRequest(&agentv1.StartResourceExecutionRequest{ActionId: intent.GetActionId(), StartGrantEnvelope: []byte("no grant exists")})); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("refused action could start: %v", err)
	}
	if natives.applies() != 1 {
		t.Fatal("a later action reached the native effect")
	}
	current, err := natives.of(f.svc, nil, 0, intent).ledger(t.Context())
	if err != nil || !proto.Equal(current, fence) {
		t.Fatalf("refusal changed the UNKNOWN fence: %v", err)
	}
}

// A native effect that ended OUTCOME_UNKNOWN leaves its ownership ledger
// UNKNOWN. Every later action for that resource used to fail Plan with an
// unclassified error, which the relay retried every management cycle while the
// server row stayed in progress. It now ends in one durable, attested,
// effect-free OWNERSHIP_UNKNOWN refusal; nothing native runs and the fence
// stays exactly as the interrupted effect left it.
func TestUnknownOwnershipLedgerRefusesLaterActionsDurably(t *testing.T) {
	f := newResourceFixture(t, false)
	f.native.incarnation = f.svc.incarnation
	natives := &ledgerNatives{}
	natives.open(f.svc, f.native, agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_SYSTEMD_RUNTIME)
	adopt := func(intent *agentv1.ResourceExecutionIntent) *agentv1.ResourceExecutionIntent {
		intent.Ownership.Policy.Mode = resourcev1.OwnershipMode_OWNERSHIP_MODE_APPROVED_ADOPTION
		intent.Ownership.Policy.AdoptionApprovalId = proto.String(uuid.NewString())
		return intent
	}
	first := adopt(f.intent(t, 1))
	if prepared, _ := f.prepare(t, first); prepared.GetStatus().GetState() != agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_PREPARED {
		t.Fatalf("drift was not prepared: %v", prepared.GetStatus())
	}
	fence := interruptEffect(t, f, natives, first)
	for sequence, operation := range []resourcev1.ResourceOperation{resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE, resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE} {
		t.Run(operation.String(), func(t *testing.T) {
			later := adopt(f.intent(t, uint64(sequence)+2))
			later.Operation = operation
			prepared, envelope := f.prepare(t, later)
			assertOwnershipUnknownRefusal(t, f, natives, later, prepared, envelope, fence)
		})
	}
}

// A package intent with staging is refused at admission, before any staging
// download or preparation outcome, by the same durable fence.
func TestUnknownOwnershipLedgerRefusesPackageStaging(t *testing.T) {
	f, staging, first := newPreparationFixture(t)
	staging.ready.Store(true)
	natives := &ledgerNatives{}
	natives.open(f.svc, staging, agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_NATIVE_PACKAGE_PRESENCE)
	_, envelope := f.prepare(t, first)
	ready, err := f.svc.PrepareResourceExecution(t.Context(), connect.NewRequest(&agentv1.PrepareResourceExecutionRequest{IntentEnvelope: envelope}))
	if err != nil || ready.Msg.GetStatus().GetState() != agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_PREPARED {
		t.Fatalf("staged package was not prepared: %v %v", ready.Msg.GetStatus(), err)
	}
	fence := interruptEffect(t, f, natives, first)
	polls, cancels := staging.polls.Load(), staging.cancels.Load()
	later := f.intent(t, 2)
	later.Desired, later.Preparation = proto.CloneOf(first.GetDesired()), &agentv1.ResourceExecutionPreparation{Deadline: protoTimestamp(f.now.Add(4 * time.Minute)), MaxCacheBytes: 1 << 20}
	prepared, laterEnvelope := f.prepare(t, later)
	assertOwnershipUnknownRefusal(t, f, natives, later, prepared, laterEnvelope, fence)
	if staging.polls.Load() != polls || staging.cancels.Load() != cancels {
		t.Fatal("refused package intent staged or planned")
	}
}
