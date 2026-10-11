//go:build linux

package executor

import (
	"bytes"
	"context"
	"crypto/ed25519"
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
	"lindm/internal/agent/journal"
	"lindm/internal/agent/serviceprovider"
	"lindm/internal/resource"
)

// boundaryNative is a deterministic effect-boundary harness, not systemd. These
// tests exercise real signed authority, journal CAS and worker ownership; actual
// D-Bus execution is separately qualified by the packaged VM smoke.
type boundaryNative struct {
	mu            sync.Mutex
	observation   *resourcev1.SystemdServiceObservation
	incarnation   string
	plans         atomic.Int32
	applies       atomic.Int32
	verifies      atomic.Int32
	effects       atomic.Int32
	beforeGate    chan struct{}
	releaseGate   chan struct{}
	afterGate     chan struct{}
	releaseEffect chan struct{}
	finished      chan struct{}
	once          sync.Once
	beforeEffect  func() error
	planEntered   chan struct{}
	releasePlan   chan struct{}
}

func (n *boundaryNative) Close() error { return nil }
func (n *boundaryNative) Plan(ctx context.Context, desired *resourcev1.ResourceDesiredState, operation resourcev1.ResourceOperation) (*resourcev1.ResourcePlan, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	n.plans.Add(1)
	if n.planEntered != nil {
		close(n.planEntered)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-n.releasePlan:
		}
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	before := n.envelope(proto.CloneOf(n.observation), boundaryBackend())
	desiredDigest, err := resource.DesiredDigest(desired)
	if err != nil {
		return nil, err
	}
	observationDigest, err := resource.ObservationDigest(before)
	if err != nil {
		return nil, err
	}
	claims, err := resource.Claims(desired)
	if err != nil {
		return nil, err
	}
	plan := &resourcev1.ResourcePlan{
		Ref: proto.CloneOf(desired.GetRef()), Operation: operation,
		Before: before, Backend: before.GetMetadata().GetBackend(),
		DesiredSha256: desiredDigest[:], ObservationSha256: observationDigest[:],
		OwnershipRevisionSha256: digestBytes([]byte("fixture ownership")), Claims: claims,
		Safety: &resourcev1.PlanSafety{LockDomains: []resourcev1.ClaimDomain{resourcev1.ClaimDomain_CLAIM_DOMAIN_SERVICE_RUNTIME}, Reversibility: resourcev1.Reversibility_REVERSIBILITY_IRREVERSIBLE, RollbackScope: resourcev1.RollbackScope_ROLLBACK_SCOPE_NONE, Confirmation: resourcev1.ConfirmationPolicy_CONFIRMATION_POLICY_NOT_REQUIRED},
		Plan: &resourcev1.ResourcePlan_SystemdService{SystemdService: &resourcev1.SystemdServicePlan{
			Desired: proto.CloneOf(desired.GetSystemdService()), Before: before.GetSystemdService(),
			ChangeRuntime: desired.GetSystemdService().GetRuntime() == resourcev1.ServiceRuntimeState_SERVICE_RUNTIME_STATE_ACTIVE && n.observation.GetActiveState() != "active",
		}},
	}
	if err := serviceprovider.ValidatePlan(plan); err != nil {
		return nil, err
	}
	return plan, nil
}
func (n *boundaryNative) Observe(context.Context, *resourcev1.ResourceDesiredState) (*resourcev1.ResourceObservation, error) {
	return nil, errors.New("fixture does not observe")
}

func (n *boundaryNative) Verify(ctx context.Context, plan *resourcev1.ResourcePlan) (*resourcev1.ResourceVerification, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	n.verifies.Add(1)
	n.mu.Lock()
	defer n.mu.Unlock()
	after := proto.CloneOf(n.observation)
	checks := &resourcev1.SystemdServiceChecks{Observation: after, RuntimeMatches: after.GetActiveState() == "active", EnablementMatches: true, DefinitionMatches: bytes.Equal(after.GetDefinitionSha256(), plan.GetSystemdService().GetBefore().GetDefinitionSha256()), JobCompleted: !after.GetJobPending()}
	checks.Converged = checks.GetJobCompleted() && checks.GetRuntimeMatches() && checks.GetEnablementMatches() && checks.GetDefinitionMatches() && after.GetBootId() == plan.GetSystemdService().GetBefore().GetBootId()
	disposition := resourcev1.VerificationDisposition_VERIFICATION_DISPOSITION_DRIFTED
	if checks.GetConverged() {
		disposition = resourcev1.VerificationDisposition_VERIFICATION_DISPOSITION_CONVERGED
	}
	digest, err := resource.PlanDigest(plan)
	if err != nil {
		return nil, err
	}
	result := &resourcev1.ResourceVerification{Ref: proto.CloneOf(plan.GetRef()), DesiredSha256: bytes.Clone(plan.GetDesiredSha256()), PlanSha256: digest[:], After: n.envelope(after, plan.GetBackend()), Disposition: disposition, Checks: &resourcev1.ResourceVerification_SystemdService{SystemdService: checks}}
	if err := serviceprovider.ValidateVerification(plan, result); err != nil {
		return nil, err
	}
	if !checks.GetConverged() {
		return result, serviceprovider.ErrNotConverged
	}
	return result, nil
}
func (n *boundaryNative) Apply(ctx context.Context, plan *resourcev1.ResourcePlan, authorize func(context.Context) error) (*resourcev1.ResourceVerification, error) {
	n.applies.Add(1)
	defer n.once.Do(func() { close(n.finished) })
	if n.beforeGate != nil {
		close(n.beforeGate)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-n.releaseGate:
		}
	}
	if err := authorize(ctx); err != nil {
		return nil, err
	}
	if n.beforeEffect != nil {
		if err := n.beforeEffect(); err != nil {
			return nil, err
		}
	}
	if n.afterGate != nil {
		close(n.afterGate)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-n.releaseEffect:
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	n.effects.Add(1)
	n.mu.Lock()
	n.observation.ActiveState, n.observation.SubState = "active", "running"
	setBoundaryFingerprint(n.observation)
	n.mu.Unlock()
	return n.Verify(ctx, plan)
}

func setBoundaryFingerprint(observation *resourcev1.SystemdServiceObservation) {
	copy := proto.CloneOf(observation)
	copy.ObservedAt, copy.FingerprintSha256 = nil, nil
	observation.FingerprintSha256, _ = digestMessage(copy)
}

type resourceFixture struct {
	svc               *Service
	fix               fixture
	native            *boundaryNative
	planKey, startKey ed25519.PrivateKey
	now               time.Time
	wall              atomic.Int64
	bootClock         atomic.Uint64
	boot              string
	// openNative replaces the systemd boundary harness for a single test.
	openNative func(*Service, secretAccessor) (nativeResource, error)
}

func newResourceFixture(t *testing.T, active bool, withoutDelegation ...bool) *resourceFixture {
	t.Helper()
	f := &resourceFixture{now: time.Date(2031, 9, 1, 0, 0, 0, 0, time.UTC), boot: uuid.NewString(), planKey: testKey(t), startKey: testKey(t)}
	f.wall.Store(f.now.UnixNano())
	f.bootClock.Store(uint64(time.Hour))
	f.fix = newFixture(t, f.now)
	observation := &resourcev1.SystemdServiceObservation{Unit: "example.service", BootId: f.boot, ObservedAt: protoTimestamp(f.now), LoadState: "loaded", ActiveState: "inactive", SubState: "dead", UnitFileState: "disabled", ServiceType: "simple", DefinitionSha256: digestBytes([]byte("root-owned fixture definition"))}
	if active {
		observation.ActiveState, observation.SubState = "active", "running"
	}
	setBoundaryFingerprint(observation)
	f.native = &boundaryNative{observation: observation, finished: make(chan struct{})}
	f.svc = openExecutor(t, f.now, f.options()...)
	prepare(t, f.svc, f.fix, "lg1_test-grant-secret-with-32-characters-minimum", false)
	device, generation := uuid.New(), uuid.New()
	cert := f.fix.leaf(t, publicOf(durable(t, f.svc).GetIdentityPrivateKey()), device, generation, f.now.Add(-time.Minute), f.now.Add(24*time.Hour))
	if _, err := f.svc.InstallEnrollment(t.Context(), connect.NewRequest(&agentv1.InstallEnrollmentRequest{DeviceId: device.String(), EnrollmentGeneration: generation.String(), CertificatePem: cert})); err != nil {
		t.Fatal(err)
	}
	pending := session(t, f.svc).GetPending()
	if _, err := f.svc.CommitSession(t.Context(), connect.NewRequest(&agentv1.CommitSessionRequest{RequestId: pending.GetRequestId(), ServerEpoch: 1})); err != nil {
		t.Fatal(err)
	}
	if len(withoutDelegation) == 0 || !withoutDelegation[0] {
		f.installDelegation(t, 1, 0)
	}
	return f
}

func (f *resourceFixture) options() []Option {
	return []Option{WithClock(func() time.Time { return time.Unix(0, f.wall.Load()).UTC() }), WithBootID(func() (string, error) { return f.boot, nil }), func(s *Service) {
		s.boottime = func() (uint64, error) { return f.bootClock.Load(), nil }
		s.openResource = func(_ context.Context, _ *agentv1.ResourceExecutionIntent, secrets secretAccessor) (nativeResource, error) {
			if f.openNative != nil {
				return f.openNative(s, secrets)
			}
			f.native.mu.Lock()
			f.native.incarnation = s.incarnation
			f.native.mu.Unlock()
			return f.native, nil
		}
	}}
}
func (f *resourceFixture) installDelegation(t *testing.T, version, floor uint64) {
	t.Helper()
	start := delegate(t, f.startKey)
	start.Role = agentv1.ExecutionSignerRole_EXECUTION_SIGNER_ROLE_START
	doc := delegationDocument(f.fix.deploy.String(), 1, version, floor, f.now, delegate(t, f.planKey), start)
	callTrust(t, f.svc, &agentv1.UpdateExecutionTrustRequest{DelegationEnvelope: mustSign(t, f.svc.authority, doc, f.fix.rootKey)})
}
func (f *resourceFixture) intent(t *testing.T, sequence uint64) *agentv1.ResourceExecutionIntent {
	t.Helper()
	state := durable(t, f.svc)
	return &agentv1.ResourceExecutionIntent{
		DeploymentId: f.fix.deploy.String(), DeviceId: state.GetDeviceId(), EnrollmentGeneration: state.GetEnrollmentGeneration(), ActionId: uuid.NewString(), DesiredRevision: uuid.NewString(), ActorId: uuid.NewString(), ResourceSequence: sequence, RootVersion: 1, DelegationVersion: 1, AuthorizationVersion: 1, NotBefore: protoTimestamp(f.now.Add(-time.Second)), ExpiresAt: protoTimestamp(f.now.Add(5 * time.Minute)),
		Operation: resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE,
		Ownership: &agentv1.ResourceOwnershipBinding{AssignmentId: uuid.NewString(), ResourceId: uuid.NewString(), Sources: []*agentv1.ResourceOwnershipSource{{ProfileId: uuid.NewString(), ProfileRevision: uuid.NewString(), ResourceId: uuid.NewString()}}, Policy: &resourcev1.OwnershipPolicy{Mode: resourcev1.OwnershipMode_OWNERSHIP_MODE_CREATE_ONLY, Release: resourcev1.ReleaseBehavior_RELEASE_BEHAVIOR_RESTORE_OWNED}},
		Desired:   &resourcev1.ResourceDesiredState{Ref: &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_SYSTEMD_SERVICE, CanonicalKey: "example.service"}, State: &resourcev1.ResourceDesiredState_SystemdService{SystemdService: &resourcev1.SystemdServiceDesired{Unit: "example.service", Runtime: resourcev1.ServiceRuntimeState_SERVICE_RUNTIME_STATE_ACTIVE, Enablement: resourcev1.ServiceEnablement_SERVICE_ENABLEMENT_UNMANAGED}}},
	}
}
func (f *resourceFixture) prepare(t *testing.T, intent *agentv1.ResourceExecutionIntent) (*agentv1.PrepareResourceExecutionResponse, []byte) {
	t.Helper()
	envelope := mustSign(t, f.svc.authority, intent, f.planKey)
	response, err := f.svc.PrepareResourceExecution(t.Context(), connect.NewRequest(&agentv1.PrepareResourceExecutionRequest{IntentEnvelope: envelope}))
	if err != nil {
		t.Fatal(err)
	}
	return response.Msg, envelope
}
func resourceRow(t *testing.T, svc *Service, action string) (*agentv1.ResourceExecutionRecord, int64) {
	t.Helper()
	svc.mu.Lock()
	defer svc.mu.Unlock()
	record, revision, err := svc.store.LoadResourceAction(t.Context(), action)
	if err != nil {
		t.Fatal(err)
	}
	return record, revision
}
func (f *resourceFixture) grant(t *testing.T, intent *agentv1.ResourceExecutionIntent) []byte {
	t.Helper()
	record, _ := resourceRow(t, f.svc, intent.GetActionId())
	return mustSign(t, f.svc.authority, &agentv1.ResourceExecutionStartGrant{Challenge: record.GetChallenge(), ActorId: intent.GetActorId(), AuthorizationVersion: intent.GetAuthorizationVersion(), RootVersion: 1, DelegationVersion: 1, NotBefore: record.GetChallenge().GetIssuedAt(), ExpiresAt: record.GetChallenge().GetExpiresAt()}, f.startKey)
}
func startResource(t *testing.T, svc *Service, action string, grant []byte) *agentv1.StartResourceExecutionResponse {
	t.Helper()
	response, err := svc.StartResourceExecution(t.Context(), connect.NewRequest(&agentv1.StartResourceExecutionRequest{ActionId: action, StartGrantEnvelope: grant}))
	if err != nil {
		t.Fatal(err)
	}
	return response.Msg
}
func waitBoundary(t *testing.T, event <-chan struct{}) {
	t.Helper()
	select {
	case <-event:
	case <-time.After(5 * time.Second):
		t.Fatal("worker boundary was not reached")
	}
}
func awaitResourceTerminal(t *testing.T, svc *Service, action string) *agentv1.ResourceExecutionStatus {
	t.Helper()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for {
		response, err := svc.GetResourceExecution(t.Context(), connect.NewRequest(&agentv1.GetResourceExecutionRequest{ActionId: action}))
		if err != nil {
			t.Fatal(err)
		}
		if response.Msg.GetStatus().GetCompletedAt() != nil {
			return response.Msg.GetStatus()
		}
		select {
		case <-deadline.C:
			t.Fatal("worker did not persist terminal evidence")
		case <-tick.C:
		}
	}
}

func TestServiceSignedPrepareReplayConflictAndNoDrift(t *testing.T) {
	for _, active := range []bool{false, true} {
		t.Run(map[bool]string{false: "drift", true: "no-drift"}[active], func(t *testing.T) {
			f := newResourceFixture(t, active)
			intent := f.intent(t, 1)
			prepared, envelope := f.prepare(t, intent)
			if active {
				if prepared.GetStatus().GetState() != agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_SUCCEEDED || len(prepared.GetChallengeProof()) != 0 || prepared.GetStatus().GetVerification().GetDisposition() != resourcev1.VerificationDisposition_VERIFICATION_DISPOSITION_CONVERGED {
					t.Fatal("no-drift work lacked durable read-only completion")
				}
			} else {
				record, _ := resourceRow(t, f.svc, intent.GetActionId())
				challenge := new(agentv1.ResourceExecutionChallenge)
				if err := f.svc.authority.Verify(t.Context(), prepared.GetChallengeProof(), challenge, 1, publicOf(durable(t, f.svc).GetIdentityPrivateKey())); err != nil || !proto.Equal(challenge, record.GetChallenge()) {
					t.Fatalf("protected challenge proof mismatch: %v", err)
				}
			}
			_, revision := resourceRow(t, f.svc, intent.GetActionId())
			f.wall.Store(f.now.Add(6 * time.Minute).UnixNano())
			retry, err := f.svc.PrepareResourceExecution(t.Context(), connect.NewRequest(&agentv1.PrepareResourceExecutionRequest{IntentEnvelope: envelope}))
			if err != nil || !proto.Equal(prepared, retry.Msg) {
				t.Fatalf("expired prepare retry changed historical evidence: %v", err)
			}
			_, after := resourceRow(t, f.svc, intent.GetActionId())
			if after != revision || f.native.plans.Load() != 1 || f.native.effects.Load() != 0 {
				t.Fatal("prepare retry replanned, committed or executed")
			}
			intent.DesiredRevision = uuid.NewString()
			conflict := mustSign(t, f.svc.authority, intent, f.planKey)
			if _, err := f.svc.PrepareResourceExecution(t.Context(), connect.NewRequest(&agentv1.PrepareResourceExecutionRequest{IntentEnvelope: conflict})); connect.CodeOf(err) != connect.CodeAlreadyExists {
				t.Fatalf("conflicting action UUID accepted: %v", err)
			}
		})
	}
}

func TestResourceStartOwnedWorkerCommitAndHistoricalRetry(t *testing.T) {
	f := newResourceFixture(t, false)
	f.native.beforeGate, f.native.releaseGate = make(chan struct{}), make(chan struct{})
	intent := f.intent(t, 1)
	f.prepare(t, intent)
	grant := f.grant(t, intent)
	f.native.beforeEffect = func() error {
		f.svc.mu.Lock()
		defer f.svc.mu.Unlock()
		record, _, err := f.svc.store.LoadResourceAction(context.Background(), intent.GetActionId())
		if err != nil {
			return err
		}
		if record.GetState() != agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_RUNNING || record.GetStartedAt() == nil {
			return errors.New("effect preceded durable RUNNING")
		}
		return nil
	}
	ctx, cancel := context.WithCancel(t.Context())
	response, err := f.svc.StartResourceExecution(ctx, connect.NewRequest(&agentv1.StartResourceExecutionRequest{ActionId: intent.GetActionId(), StartGrantEnvelope: grant}))
	if err != nil || response.Msg.GetStatus().GetState() != agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_QUEUED {
		t.Fatalf("start did not acknowledge durable queue: %v", err)
	}
	cancel()
	waitBoundary(t, f.native.beforeGate)
	close(f.native.releaseGate)
	terminal := awaitResourceTerminal(t, f.svc, intent.GetActionId())
	if terminal.GetState() != agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_SUCCEEDED || f.native.effects.Load() != 1 {
		t.Fatal("RPC cancellation killed owned work or missing durable completion")
	}
	_, revision := resourceRow(t, f.svc, intent.GetActionId())
	f.wall.Store(f.now.Add(6 * time.Minute).UnixNano())
	if retry := startResource(t, f.svc, intent.GetActionId(), grant); !proto.Equal(retry.GetStatus(), terminal) {
		t.Fatal("expired grant retry changed result")
	}
	_, after := resourceRow(t, f.svc, intent.GetActionId())
	if after != revision || f.native.effects.Load() != 1 || f.native.applies.Load() != 1 {
		t.Fatal("accepted grant replayed effect")
	}
	changed := bytes.Clone(grant)
	changed = append(changed, ' ')
	if _, err := f.svc.StartResourceExecution(t.Context(), connect.NewRequest(&agentv1.StartResourceExecutionRequest{ActionId: intent.GetActionId(), StartGrantEnvelope: changed})); connect.CodeOf(err) != connect.CodeAlreadyExists {
		t.Fatalf("different grant bytes accepted: %v", err)
	}
}

func TestServiceEffectGateRevalidatesExpiryTrustAndFloor(t *testing.T) {
	for _, cause := range []string{"boottime", "wall", "rotation", "superseded", "boot", "session"} {
		t.Run(cause, func(t *testing.T) {
			f := newResourceFixture(t, false)
			f.native.beforeGate, f.native.releaseGate = make(chan struct{}), make(chan struct{})
			intent := f.intent(t, 1)
			f.prepare(t, intent)
			startResource(t, f.svc, intent.GetActionId(), f.grant(t, intent))
			waitBoundary(t, f.native.beforeGate)
			switch cause {
			case "boottime":
				f.bootClock.Add(uint64(31 * time.Second)) // wall stays frozen: suspend-safe bound
			case "wall":
				f.wall.Store(f.now.Add(31 * time.Second).UnixNano())
			case "rotation":
				f.installDelegation(t, 2, 1)
			case "superseded":
				f.prepare(t, f.intent(t, 2))
			case "boot":
				f.svc.mu.Lock()
				f.svc.bootID = func() (string, error) { return uuid.NewString(), nil }
				f.svc.mu.Unlock()
			case "session":
				f.svc.mu.Lock()
				loaded, err := f.svc.load(t.Context())
				if err == nil {
					next := cloneState(loaded.state)
					next.SessionBootId = proto.String(uuid.NewString())
					err = f.svc.commit(t.Context(), loaded.revision, next)
				}
				f.svc.mu.Unlock()
				if err != nil {
					t.Fatal(err)
				}
			}
			close(f.native.releaseGate)
			waitBoundary(t, f.native.finished)
			terminal := awaitResourceTerminal(t, f.svc, intent.GetActionId())
			if terminal.GetState() == agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_SUCCEEDED || terminal.GetStartedAt() != nil || f.native.effects.Load() != 0 {
				t.Fatal("stale queued authority reached effect")
			}
		})
	}
}

func TestServiceRejectsWrongAuthorityBeforeNativePreflight(t *testing.T) {
	for _, cause := range []string{"wrong-role", "wrong-device", "wrong-generation", "unsigned", "no-delegation", "revoked-delegation", "expired-identity", "no-session"} {
		t.Run(cause, func(t *testing.T) {
			f := newResourceFixture(t, false, cause == "no-delegation")
			intent := f.intent(t, 1)
			key := f.planKey
			switch cause {
			case "wrong-role":
				key = f.startKey
			case "wrong-device":
				intent.DeviceId = uuid.NewString()
			case "wrong-generation":
				intent.EnrollmentGeneration = uuid.NewString()
			case "unsigned":
				key = testKey(t)
			case "revoked-delegation":
				// A configured but empty delegation is an explicit revocation, not
				// permission to fall back to root/device/transport signing keys.
				callTrust(t, f.svc, &agentv1.UpdateExecutionTrustRequest{DelegationEnvelope: mustSign(t, f.svc.authority, delegationDocument(f.fix.deploy.String(), 1, 2, 0, f.now), f.fix.rootKey)})
			case "expired-identity":
				f.wall.Store(f.now.Add(25 * time.Hour).UnixNano())
			case "no-session":
				f.svc.mu.Lock()
				f.svc.bootID = func() (string, error) { return uuid.NewString(), nil }
				f.svc.mu.Unlock()
			}
			envelope := mustSign(t, f.svc.authority, intent, key)
			if _, err := f.svc.PrepareResourceExecution(t.Context(), connect.NewRequest(&agentv1.PrepareResourceExecutionRequest{IntentEnvelope: envelope})); err == nil {
				t.Fatal("untrusted intent accepted")
			}
			if f.native.plans.Load() != 0 || f.native.effects.Load() != 0 {
				t.Fatal("untrusted intent reached native provider")
			}
			f.svc.mu.Lock()
			_, _, err := f.svc.store.LoadResourceAction(t.Context(), intent.GetActionId())
			f.svc.mu.Unlock()
			if !errors.Is(err, journal.ErrResourceActionNotFound) {
				t.Fatalf("rejected intent changed durable journal: %v", err)
			}
		})
	}
}

func TestServiceCloseJoinsWorkerAndBlocksAdmission(t *testing.T) {
	f := newResourceFixture(t, false)
	f.native.afterGate, f.native.releaseEffect = make(chan struct{}), make(chan struct{})
	intent := f.intent(t, 1)
	f.prepare(t, intent)
	grant := f.grant(t, intent)
	startResource(t, f.svc, intent.GetActionId(), grant)
	waitBoundary(t, f.native.afterGate)
	done := make(chan error, 1)
	go func() { done <- f.svc.Close() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Close deadlocked across native callback/worker join")
	}
	if f.native.effects.Load() != 0 {
		t.Fatal("shutdown allowed a waiting native mutation")
	}
	if _, err := f.svc.Status(t.Context(), connect.NewRequest(&agentv1.StatusRequest{})); connect.CodeOf(err) != connect.CodeUnavailable {
		t.Fatalf("closed executor admitted request: %v", err)
	}
	next, err := New(t.Context(), f.svc.directory, f.options()...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = next.Close() })
	result := startResource(t, next, intent.GetActionId(), grant).GetStatus()
	if result.GetState() != agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_OUTCOME_UNKNOWN || result.GetFailure() != agentv1.ResourceExecutionFailure_RESOURCE_EXECUTION_FAILURE_INTERRUPTED {
		t.Fatal("Close did not persist uncertainty after RUNNING")
	}
}

// Stop only the consumer before assembling an on-disk crash point with the real
// RPC/CAS transitions. The replacement lifetime permits preflight, but no worker
// can consume the staged row or clean it up on Close. New must recover it.
func pauseResourceConsumer(t *testing.T, svc *Service) {
	t.Helper()
	svc.workerCancel()
	svc.worker.Wait()
	svc.mu.Lock()
	svc.workerContext, svc.workerCancel = context.WithCancel(context.Background())
	svc.mu.Unlock()
}

func TestServiceRestartInvalidatesUnconsumedAndNeverReplaysRunning(t *testing.T) {
	for _, state := range []string{"prepared", "queued", "running-converged", "running-diverged", "running-other-boot"} {
		t.Run(state, func(t *testing.T) {
			f := newResourceFixture(t, false)
			pauseResourceConsumer(t, f.svc)
			intent := f.intent(t, 1)
			f.prepare(t, intent)
			if state != "prepared" {
				startResource(t, f.svc, intent.GetActionId(), f.grant(t, intent))
			}
			if state != "prepared" && state != "queued" {
				record, _ := resourceRow(t, f.svc, intent.GetActionId())
				if err := f.svc.consumeResourceStart(t.Context(), record); err != nil {
					t.Fatal(err)
				}
				f.native.mu.Lock()
				if state != "running-diverged" {
					f.native.observation.ActiveState, f.native.observation.SubState = "active", "running"
				}
				if state == "running-other-boot" {
					f.native.observation.BootId = uuid.NewString()
				}
				setBoundaryFingerprint(f.native.observation)
				f.native.mu.Unlock()
			}
			oldIncarnation := f.svc.incarnation
			if err := f.svc.Close(); err != nil {
				t.Fatal(err)
			}
			next, err := New(t.Context(), f.svc.directory, f.options()...)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = next.Close() })
			if next.incarnation == oldIncarnation {
				t.Fatal("same-boot restart retained incarnation")
			}
			result := awaitResourceTerminal(t, next, intent.GetActionId())
			want := agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_OUTCOME_UNKNOWN
			if state == "prepared" || state == "queued" {
				want = agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_EXPIRED
			}
			if state == "running-converged" {
				want = agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_SUCCEEDED
			}
			if result.GetState() != want || f.native.applies.Load() != 0 || f.native.effects.Load() != 0 {
				t.Fatalf("restart replayed or misclassified work: got %v want %v", result.GetState(), want)
			}
		})
	}
}

func TestServiceHistoricalEvidenceChecksCryptographyAndRetainedCertificate(t *testing.T) {
	f := newResourceFixture(t, false)
	intent := f.intent(t, 1)
	f.prepare(t, intent)
	record, _ := resourceRow(t, f.svc, intent.GetActionId())
	f.svc.mu.Lock()
	loaded, err := f.svc.load(t.Context())
	f.svc.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	// Historical verification cannot depend on today's certificate public key.
	loaded.identityPublic = publicOf(testKey(t))
	if err := f.svc.verifyResourceRecord(t.Context(), loaded, record); err != nil {
		t.Fatalf("retained certificate not used: %v", err)
	}
	for _, mutate := range []func(*agentv1.ResourceExecutionRecord){
		func(r *agentv1.ResourceExecutionRecord) { r.ChallengeProof[len(r.ChallengeProof)/2] ^= 1 },
		func(r *agentv1.ResourceExecutionRecord) {
			r.AcceptedDelegationEnvelope[len(r.AcceptedDelegationEnvelope)/2] ^= 1
		},
		func(r *agentv1.ResourceExecutionRecord) {
			r.IntentEnvelope[len(r.IntentEnvelope)/2] ^= 1
			r.IntentSha256 = digestBytes(r.IntentEnvelope)
		},
		func(r *agentv1.ResourceExecutionRecord) { r.NativePlan.GetSystemdService().ChangeRuntime = false },
		func(r *agentv1.ResourceExecutionRecord) {
			r.ChallengeCertificatePem = f.fix.leaf(t, publicOf(testKey(t)), uuid.MustParse(intent.GetDeviceId()), uuid.MustParse(intent.GetEnrollmentGeneration()), f.now.Add(-time.Minute), f.now.Add(time.Hour))
		},
	} {
		bad := proto.CloneOf(record)
		mutate(bad)
		if err := f.svc.verifyResourceRecord(t.Context(), loaded, bad); !errors.Is(err, errRecoveryHold) {
			t.Fatalf("corrupt protected evidence did not require hold: %v", err)
		}
	}
}

func TestServiceDamagedStoredSignatureEntersRecoveryHold(t *testing.T) {
	f := newResourceFixture(t, false)
	intent := f.intent(t, 1)
	f.prepare(t, intent)
	record, _ := resourceRow(t, f.svc, intent.GetActionId())
	// Model protected-storage damage that passes structural journal checks.
	// Cryptographic verification belongs to the executor, not SQLite.
	record.Intent.ActionId = uuid.NewString()
	record.Intent.ResourceSequence = 2
	record.IntentEnvelope = mustSign(t, f.svc.authority, record.Intent, f.planKey)
	record.IntentSha256 = digestBytes(record.IntentEnvelope)
	record.Challenge.ActionId = record.Intent.ActionId
	record.Challenge.ResourceSequence = 2
	record.Challenge.IntentSha256 = bytes.Clone(record.IntentSha256)
	record.ChallengeProof = mustSign(t, f.svc.authority, record.Challenge, testKey(t))
	f.svc.mu.Lock()
	loaded, err := f.svc.load(t.Context())
	if err == nil {
		_, err = f.svc.store.AcceptResourceAction(t.Context(), loaded.revision, loaded.execution.revision, record)
	}
	f.svc.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.GetResourceExecution(t.Context(), connect.NewRequest(&agentv1.GetResourceExecutionRequest{ActionId: record.Intent.ActionId})); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("corrupt signature was exposed: %v", err)
	}
	status, err := f.svc.Status(t.Context(), connect.NewRequest(&agentv1.StatusRequest{}))
	if err != nil || status.Msg.GetLifecycle() != agentv1.Lifecycle_LIFECYCLE_RECOVERY_HOLD {
		t.Fatalf("bad signature failed to hold: %v", err)
	}
	if err := f.svc.Close(); err != nil {
		t.Fatal(err)
	}
	next, err := New(t.Context(), f.svc.directory, f.options()...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = next.Close() })
	status, err = next.Status(t.Context(), connect.NewRequest(&agentv1.StatusRequest{}))
	if err != nil || status.Msg.GetLifecycle() != agentv1.Lifecycle_LIFECYCLE_RECOVERY_HOLD || f.native.effects.Load() != 0 {
		t.Fatalf("restart ignored corrupt signed action: %v", err)
	}
}

func TestResourceStartRequiresSeparateExactlyBoundGrant(t *testing.T) {
	f := newResourceFixture(t, false)
	intent := f.intent(t, 1)
	f.prepare(t, intent)
	record, revision := resourceRow(t, f.svc, intent.GetActionId())
	valid := &agentv1.ResourceExecutionStartGrant{Challenge: record.GetChallenge(), ActorId: intent.GetActorId(), AuthorizationVersion: intent.GetAuthorizationVersion(), RootVersion: 1, DelegationVersion: 1, NotBefore: record.GetChallenge().GetIssuedAt(), ExpiresAt: record.GetChallenge().GetExpiresAt()}
	for _, cause := range []string{"plan-role", "actor", "authorization-version", "nonce", "action", "root", "delegation"} {
		grant := proto.CloneOf(valid)
		key := f.startKey
		switch cause {
		case "plan-role":
			key = f.planKey
		case "actor":
			grant.ActorId = uuid.NewString()
		case "authorization-version":
			grant.AuthorizationVersion++
		case "nonce":
			grant.Challenge.Nonce[0] ^= 1
		case "action":
			grant.Challenge.ActionId = uuid.NewString()
		case "root":
			grant.RootVersion++
		case "delegation":
			grant.DelegationVersion++
		}
		envelope := mustSign(t, f.svc.authority, grant, key)
		if _, err := f.svc.StartResourceExecution(t.Context(), connect.NewRequest(&agentv1.StartResourceExecutionRequest{ActionId: intent.GetActionId(), StartGrantEnvelope: envelope})); connect.CodeOf(err) != connect.CodePermissionDenied {
			t.Fatalf("%s grant was accepted: %v", cause, err)
		}
		current, after := resourceRow(t, f.svc, intent.GetActionId())
		if after != revision || !proto.Equal(current, record) || f.native.applies.Load() != 0 {
			t.Fatalf("%s rejection changed authority", cause)
		}
	}
}

func TestServiceCloseCancelsPreflightBeforeReleasingStorage(t *testing.T) {
	f := newResourceFixture(t, false)
	f.native.planEntered, f.native.releasePlan = make(chan struct{}), make(chan struct{})
	intent := f.intent(t, 1)
	envelope := mustSign(t, f.svc.authority, intent, f.planKey)
	result := make(chan error, 1)
	go func() {
		_, err := f.svc.PrepareResourceExecution(context.Background(), connect.NewRequest(&agentv1.PrepareResourceExecutionRequest{IntentEnvelope: envelope}))
		result <- err
	}()
	waitBoundary(t, f.native.planEntered)
	done := make(chan error, 1)
	go func() { done <- f.svc.Close() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Close held mutex across preflight or failed to join")
	}
	if err := <-result; connect.CodeOf(err) != connect.CodeCanceled && connect.CodeOf(err) != connect.CodeUnavailable {
		t.Fatalf("shutdown preflight was accepted: %v", err)
	}
	next, err := New(t.Context(), f.svc.directory, f.options()...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = next.Close() })
	if _, err := next.GetResourceExecution(t.Context(), connect.NewRequest(&agentv1.GetResourceExecutionRequest{ActionId: intent.GetActionId()})); connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("canceled preflight was durably accepted: %v", err)
	}
}

func TestServiceHistoricalCompletionSurvivesRotationAndRestart(t *testing.T) {
	f := newResourceFixture(t, false)
	intent := f.intent(t, 1)
	_, envelope := f.prepare(t, intent)
	grant := f.grant(t, intent)
	startResource(t, f.svc, intent.GetActionId(), grant)
	terminal := awaitResourceTerminal(t, f.svc, intent.GetActionId())
	f.installDelegation(t, 2, 3)
	if err := f.svc.Close(); err != nil {
		t.Fatal(err)
	}
	f.wall.Store(f.now.Add(3 * time.Hour).UnixNano())
	next, err := New(t.Context(), f.svc.directory, f.options()...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = next.Close() })
	if got := startResource(t, next, intent.GetActionId(), grant); !proto.Equal(got.GetStatus(), terminal) {
		t.Fatal("revocation/restart invalidated historical grant evidence")
	}
	prepared, err := next.PrepareResourceExecution(t.Context(), connect.NewRequest(&agentv1.PrepareResourceExecutionRequest{IntentEnvelope: envelope}))
	if err != nil || !proto.Equal(prepared.Msg.GetStatus(), terminal) || f.native.applies.Load() != 1 {
		t.Fatalf("historical preparation replayed after revocation: %v", err)
	}
}

func TestServiceExpiryRetainsActualRollbackWallTime(t *testing.T) {
	f := newResourceFixture(t, false)
	intent := f.intent(t, 1)
	f.prepare(t, intent)
	rolledBack := f.now.Add(-time.Second)
	f.wall.Store(rolledBack.UnixNano())
	response, err := f.svc.GetResourceExecution(t.Context(), connect.NewRequest(&agentv1.GetResourceExecutionRequest{ActionId: intent.GetActionId()}))
	if err != nil {
		t.Fatal(err)
	}
	status := response.Msg.GetStatus()
	if status.GetState() != agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_EXPIRED || !status.GetCompletedAt().AsTime().Equal(rolledBack) || !status.GetCompletedAt().AsTime().Before(status.GetAcceptedAt().AsTime()) {
		t.Fatal("rollback expiry fabricated monotonic wall time")
	}
	// The actual earlier wall completion remains valid historical evidence.
	if _, err := f.svc.GetResourceExecution(t.Context(), connect.NewRequest(&agentv1.GetResourceExecutionRequest{ActionId: intent.GetActionId()})); err != nil {
		t.Fatalf("actual rollback wall time became recovery hold: %v", err)
	}
}

func TestServiceEffectGateChecksDeadlineAgainAfterDurableCommit(t *testing.T) {
	f := newResourceFixture(t, false)
	f.native.beforeGate, f.native.releaseGate = make(chan struct{}), make(chan struct{})
	intent := f.intent(t, 1)
	f.prepare(t, intent)
	grant := f.grant(t, intent)
	startResource(t, f.svc, intent.GetActionId(), grant)
	waitBoundary(t, f.native.beforeGate)
	record, _ := resourceRow(t, f.svc, intent.GetActionId())
	var reads atomic.Int32
	f.svc.mu.Lock()
	f.svc.boottime = func() (uint64, error) {
		if reads.Add(1) == 1 {
			return f.bootClock.Load(), nil
		}
		return record.GetChallengeBoottimeNs(), nil
	}
	f.svc.mu.Unlock()
	close(f.native.releaseGate)
	waitBoundary(t, f.native.finished)
	terminal := awaitResourceTerminal(t, f.svc, intent.GetActionId())
	if terminal.GetStartedAt() == nil || terminal.GetState() != agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_OUTCOME_UNKNOWN || f.native.effects.Load() != 0 {
		t.Fatal("durable commit extended the native start deadline")
	}
	if retry := startResource(t, f.svc, intent.GetActionId(), grant); !proto.Equal(retry.GetStatus(), terminal) || f.native.applies.Load() != 1 {
		t.Fatal("consumed postcommit rejection was reexecuted")
	}
}

func boundaryBackend() *resourcev1.BackendSelection {
	return &resourcev1.BackendSelection{Backend: resourcev1.Backend_BACKEND_SYSTEMD, NativeVersion: "fixture", ProviderVersion: "fixture", Product: &resourcev1.PlatformProduct{OsId: "fixture", Product: "Fixture Linux", Version: "1", Architecture: "x86_64"}}
}

func (n *boundaryNative) envelope(observation *resourcev1.SystemdServiceObservation, backend *resourcev1.BackendSelection) *resourcev1.ResourceObservation {
	return &resourcev1.ResourceObservation{
		Ref:      &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_SYSTEMD_SERVICE, CanonicalKey: observation.GetUnit()},
		Metadata: &resourcev1.ObservationMetadata{BootId: observation.GetBootId(), ExecutorIncarnation: n.incarnation, ObservedAt: observation.GetObservedAt(), Backend: proto.CloneOf(backend), NativeRevision: bytes.Clone(observation.GetFingerprintSha256()), ObservationStatus: resourcev1.ObservationStatus_OBSERVATION_STATUS_OK},
		Observed: &resourcev1.ResourceObservation_SystemdService{SystemdService: observation},
	}
}

func TestResourceIntentCannotBorrowSystemdCapability(t *testing.T) {
	f := newResourceFixture(t, false)
	intent := f.intent(t, 1)
	intent.Desired = &resourcev1.ResourceDesiredState{
		Ref:   &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_LOCAL_GROUP, CanonicalKey: "operators"},
		State: &resourcev1.ResourceDesiredState_LocalGroup{LocalGroup: &resourcev1.LocalGroupDesired{Name: "operators", Presence: resourcev1.Presence_PRESENCE_PRESENT}},
	}
	envelope := mustSign(t, f.svc.authority, intent, f.planKey)
	if _, err := f.svc.PrepareResourceExecution(t.Context(), connect.NewRequest(&agentv1.PrepareResourceExecutionRequest{IntentEnvelope: envelope})); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("systemd-only signer authorized local group: %v", err)
	}
	if f.native.plans.Load() != 0 || f.native.effects.Load() != 0 {
		t.Fatal("cross-kind intent reached native provider")
	}
}

func TestResourceGrantBindsKindAndOperation(t *testing.T) {
	for _, change := range []string{"kind", "operation"} {
		t.Run(change, func(t *testing.T) {
			f := newResourceFixture(t, false)
			intent := f.intent(t, 1)
			f.prepare(t, intent)
			record, _ := resourceRow(t, f.svc, intent.GetActionId())
			challenge := proto.CloneOf(record.GetChallenge())
			if change == "kind" {
				challenge.Ref = &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_LOCAL_GROUP, CanonicalKey: "operators"}
			} else {
				challenge.Operation = resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE
			}
			grant := mustSign(t, f.svc.authority, &agentv1.ResourceExecutionStartGrant{Challenge: challenge, ActorId: intent.GetActorId(), AuthorizationVersion: intent.GetAuthorizationVersion(), RootVersion: 1, DelegationVersion: 1, NotBefore: challenge.GetIssuedAt(), ExpiresAt: challenge.GetExpiresAt()}, f.startKey)
			if _, err := f.svc.StartResourceExecution(t.Context(), connect.NewRequest(&agentv1.StartResourceExecutionRequest{ActionId: intent.GetActionId(), StartGrantEnvelope: grant})); connect.CodeOf(err) != connect.CodePermissionDenied {
				t.Fatalf("mismatched %s start grant accepted: %v", change, err)
			}
			if f.native.effects.Load() != 0 {
				t.Fatal("mismatched grant performed an effect")
			}
		})
	}
}
