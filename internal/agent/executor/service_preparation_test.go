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
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/resource"
)

// This seam exercises signed executor/journal boundaries, not native downloads.
// The native staging unit and actual transaction are separately qualified.
type preparingNative struct {
	fixture  *serviceFixture
	service  *Service
	action   string
	artifact string
	ready    atomic.Bool
	corrupt  atomic.Bool
	polls    atomic.Int32
	cancels  atomic.Int32
	applies  atomic.Int32
	entered  chan struct{}
	release  chan struct{}
}

func (n *preparingNative) Close() error { return nil }
func (n *preparingNative) Plan(ctx context.Context, desired *resourcev1.ResourceDesiredState, operation resourcev1.ResourceOperation) (*resourcev1.ResourcePlan, error) {
	n.polls.Add(1)
	record, _, err := n.service.store.LoadResourceAction(ctx, n.action)
	if err != nil {
		return nil, err
	}
	if record.GetState() != agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_PREPARING || record.GetNativePlan() != nil || record.GetChallenge() != nil {
		return nil, errors.New("native staging preceded durable effect-free admission")
	}
	if n.entered != nil {
		close(n.entered)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-n.release:
		}
	}
	if !n.ready.Load() {
		return nil, resource.ErrPreparing
	}
	backend := &resourcev1.BackendSelection{Backend: resourcev1.Backend_BACKEND_APT, NativeVersion: "2.8.3", ProviderVersion: "1", Product: &resourcev1.PlatformProduct{OsId: "ubuntu", Product: "ubuntu", Version: "24.04", Architecture: "amd64"}}
	before := &resourcev1.ResourceObservation{Ref: proto.CloneOf(desired.GetRef()), Metadata: &resourcev1.ObservationMetadata{BootId: n.fixture.boot, ExecutorIncarnation: n.service.incarnation, ObservedAt: protoTimestamp(n.service.now()), Backend: backend, NativeRevision: bytes.Repeat([]byte{1}, 32), ObservationStatus: resourcev1.ObservationStatus_OBSERVATION_STATUS_OK}, Observed: &resourcev1.ResourceObservation_NativePackage{NativePackage: &resourcev1.NativePackageObservation{Package: proto.CloneOf(desired.GetNativePackage().GetPackage()), DatabaseRevisionSha256: bytes.Repeat([]byte{1}, 32)}}}
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
	artifact := &resourcev1.ArtifactRef{ArtifactId: n.artifact, Sha256: bytes.Repeat([]byte{2}, 32), SizeBytes: 128}
	plan := &resourcev1.ResourcePlan{Ref: proto.CloneOf(desired.GetRef()), Operation: operation, DesiredSha256: desiredDigest[:], ObservationSha256: observationDigest[:], Backend: backend, Claims: claims, OwnershipRevisionSha256: bytes.Repeat([]byte{3}, 32), Before: before,
		Safety: &resourcev1.PlanSafety{LockDomains: []resourcev1.ClaimDomain{resourcev1.ClaimDomain_CLAIM_DOMAIN_PACKAGE}, Reversibility: resourcev1.Reversibility_REVERSIBILITY_PARTIAL, RollbackScope: resourcev1.RollbackScope_ROLLBACK_SCOPE_OWNED_DIMENSIONS, Confirmation: resourcev1.ConfirmationPolicy_CONFIRMATION_POLICY_NOT_REQUIRED, PrerequisiteManifests: []*resourcev1.ArtifactRef{artifact}},
		Plan:   &resourcev1.ResourcePlan_NativePackage{NativePackage: &resourcev1.NativePackagePlan{Desired: proto.CloneOf(desired.GetNativePackage()), TransactionManifest: artifact, NativeDatabaseRevision: bytes.Repeat([]byte{1}, 32), NativeLockIdentity: "fixture-native-lock", ChangePackages: true}},
	}
	if n.corrupt.Load() {
		plan.DesiredSha256[0]++
	}
	return plan, nil
}
func (n *preparingNative) Verify(context.Context, *resourcev1.ResourcePlan) (*resourcev1.ResourceVerification, error) {
	return nil, errors.New("unexpected verification")
}
func (n *preparingNative) Apply(context.Context, *resourcev1.ResourcePlan, func(context.Context) error) (*resourcev1.ResourceVerification, error) {
	n.applies.Add(1)
	return nil, errors.New("unexpected unstarted native mutation")
}
func (n *preparingNative) option() Option {
	return func(s *Service) {
		n.service = s
		s.openResource = func(context.Context, *agentv1.ResourceExecutionIntent, secretAccessor) (nativeResource, error) {
			return n, nil
		}
		s.cancelPreparation = func(context.Context, *agentv1.ResourceExecutionIntent) error { n.cancels.Add(1); return nil }
	}
}
func newPreparationFixture(t *testing.T) (*serviceFixture, *preparingNative, *agentv1.ResourceExecutionIntent) {
	t.Helper()
	f := newServiceFixture(t, false, true)
	plan, start := delegate(t, f.planKey), delegate(t, f.startKey)
	plan.Capabilities, start.Capabilities = []string{"package.native.v1"}, []string{"package.native.v1"}
	start.Role = agentv1.ExecutionSignerRole_EXECUTION_SIGNER_ROLE_START
	doc := delegationDocument(f.fix.deploy.String(), 1, 1, 0, f.now, plan, start)
	callTrust(t, f.svc, &agentv1.UpdateExecutionTrustRequest{DelegationEnvelope: mustSign(t, f.svc.authority, doc, f.fix.rootKey)})
	intent := f.intent(t, 1)
	intent.Preparation = &agentv1.ResourceExecutionPreparation{Deadline: protoTimestamp(f.now.Add(4 * time.Minute)), MaxCacheBytes: 1 << 20}
	intent.Desired = &resourcev1.ResourceDesiredState{Ref: &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_NATIVE_PACKAGE, CanonicalKey: "deb/example/amd64"}, State: &resourcev1.ResourceDesiredState_NativePackage{NativePackage: &resourcev1.NativePackageDesired{Package: &resourcev1.PackageIdentity{Ecosystem: resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_DEB, NativeName: "example", Architecture: "amd64"}, Presence: resourcev1.Presence_PRESENCE_PRESENT, Version: &resourcev1.NativePackageDesired_Exact{Exact: &resourcev1.NativeVersion{Version: &resourcev1.NativeVersion_Deb{Deb: "1.0-1"}}}, Repository: &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_PACKAGE_REPOSITORY, CanonicalKey: "apt/" + uuid.NewString()}, Removal: resourcev1.PackageRemovalPolicy_PACKAGE_REMOVAL_POLICY_PRESERVE_DATA}}}
	n := &preparingNative{fixture: f, action: intent.GetActionId(), artifact: uuid.NewString()}
	f.svc.mu.Lock()
	n.option()(f.svc)
	f.svc.mu.Unlock()
	return f, n, intent
}
func assertPreparing(t *testing.T, response *agentv1.PrepareResourceExecutionResponse) {
	t.Helper()
	if response.GetStatus().GetState() != agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_PREPARING || response.GetStatus().GetBefore() != nil || response.GetNativePlan() != nil || len(response.GetChallengeProof()) != 0 || response.GetStatus().GetCompletedAt() != nil || response.GetStatus().GetPreparationOutcome() != nil {
		t.Fatal("pending staging fabricated native or terminal evidence")
	}
}

func TestResourcePreparationDurablePollRestartAndFreshChallenge(t *testing.T) {
	f, n, intent := newPreparationFixture(t)
	pending, envelope := f.prepare(t, intent)
	assertPreparing(t, pending)
	accepted, revision := serviceRow(t, f.svc, intent.GetActionId())
	f.wall.Store(f.now.Add(time.Minute).UnixNano())
	retry, err := f.svc.PrepareResourceExecution(t.Context(), connect.NewRequest(&agentv1.PrepareResourceExecutionRequest{IntentEnvelope: envelope}))
	if err != nil {
		t.Fatal(err)
	}
	assertPreparing(t, retry.Msg)
	after, afterRevision := serviceRow(t, f.svc, intent.GetActionId())
	if revision != afterRevision || !proto.Equal(accepted, after) || n.applies.Load() != 0 {
		t.Fatal("poll rewrote acceptance or issued native effects")
	}
	if err := f.svc.Close(); err != nil {
		t.Fatal(err)
	}
	if n.cancels.Load() != 0 {
		t.Fatal("executor shutdown canceled independent staging")
	}
	opts := append(f.options(), n.option())
	next, err := New(t.Context(), f.svc.directory, opts...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = next.Close() })
	f.svc = next
	n.ready.Store(true)
	ready, err := next.PrepareResourceExecution(t.Context(), connect.NewRequest(&agentv1.PrepareResourceExecutionRequest{IntentEnvelope: envelope}))
	if err != nil {
		t.Fatal(err)
	}
	if ready.Msg.GetStatus().GetState() != agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_PREPARED {
		t.Fatal("ready exact plan did not become prepared")
	}
	record, readyRevision := serviceRow(t, next, intent.GetActionId())
	if readyRevision != revision+1 || !proto.Equal(record.GetAcceptedAt(), accepted.GetAcceptedAt()) || !proto.Equal(record.GetIntent(), accepted.GetIntent()) || !record.GetChallenge().GetIssuedAt().AsTime().Equal(next.now()) || record.GetChallenge().GetExpiresAt().AsTime().Sub(next.now()) != 30*time.Second {
		t.Fatal("readiness extended acceptance or failed to create a fresh thirty-second challenge")
	}
	digest, err := resource.PlanDigest(record.GetNativePlan())
	if err != nil || !bytes.Equal(digest[:], record.GetChallenge().GetNativePlanSha256()) {
		t.Fatal("challenge did not bind exact ready plan")
	}
	polls := n.polls.Load()
	if _, err := next.PrepareResourceExecution(t.Context(), connect.NewRequest(&agentv1.PrepareResourceExecutionRequest{IntentEnvelope: envelope})); err != nil {
		t.Fatal(err)
	}
	if n.polls.Load() != polls || n.applies.Load() != 0 {
		t.Fatal("prepared retry restaged or mutated")
	}
}

func TestResourcePreparationExpiryCancelTrustAndCorruptDigest(t *testing.T) {
	for _, reason := range []string{"expiry", "restart-expiry", "cancel", "trust", "digest"} {
		t.Run(reason, func(t *testing.T) {
			f, n, intent := newPreparationFixture(t)
			_, envelope := f.prepare(t, intent)
			var status *agentv1.ResourceExecutionStatus
			if reason == "cancel" {
				response, err := f.svc.CancelResourcePreparation(t.Context(), connect.NewRequest(&agentv1.CancelResourcePreparationRequest{ActionId: intent.GetActionId(), IntentSha256: digestBytes(envelope)}))
				if err != nil {
					t.Fatal(err)
				}
				status = response.Msg.GetStatus()
			} else {
				switch reason {
				case "expiry":
					f.wall.Store(intent.GetPreparation().GetDeadline().AsTime().UnixNano())
				case "restart-expiry":
					if err := f.svc.Close(); err != nil {
						t.Fatal(err)
					}
					f.wall.Store(intent.GetPreparation().GetDeadline().AsTime().UnixNano())
					next, err := New(t.Context(), f.svc.directory, append(f.options(), n.option())...)
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { _ = next.Close() })
					f.svc = next
				case "trust":
					f.installDelegation(t, 2, 1)
				case "digest":
					n.ready.Store(true)
					n.corrupt.Store(true)
				}
				response, err := f.svc.PrepareResourceExecution(t.Context(), connect.NewRequest(&agentv1.PrepareResourceExecutionRequest{IntentEnvelope: envelope}))
				if err != nil {
					t.Fatal(err)
				}
				status = response.Msg.GetStatus()
			}
			if status.GetCompletedAt() == nil || status.GetPreparationOutcome() == nil || status.GetBefore() != nil || status.GetStartedAt() != nil || status.GetVerification() != nil || n.cancels.Load() != 1 || n.applies.Load() != 0 {
				t.Fatal("staging ended without exact cleanup-only evidence")
			}
			record, _ := serviceRow(t, f.svc, intent.GetActionId())
			if record.GetChallenge() != nil || record.GetNativePlan() != nil || !proto.Equal(record.GetPreparationOutcome().GetPreparation(), intent.GetPreparation()) {
				t.Fatal("terminated preparation invented native authority")
			}
			retry, err := f.svc.PrepareResourceExecution(t.Context(), connect.NewRequest(&agentv1.PrepareResourceExecutionRequest{IntentEnvelope: envelope}))
			if err != nil || !proto.Equal(status, retry.Msg.GetStatus()) || n.cancels.Load() != 1 {
				t.Fatal("terminal preparation retry changed evidence")
			}
		})
	}
}

func TestResourcePreparationCancelBeforeDeliveryFencesLatePrepare(t *testing.T) {
	f, n, intent := newPreparationFixture(t)
	envelope := mustSign(t, f.svc.authority, intent, f.planKey)
	request := &agentv1.CancelResourcePreparationRequest{ActionId: intent.GetActionId(), IntentSha256: digestBytes(envelope)}
	for range 2 {
		response, err := f.svc.CancelResourcePreparation(t.Context(), connect.NewRequest(request))
		if err != nil || !response.Msg.GetNeverPrepared() || response.Msg.GetStatus() != nil {
			t.Fatalf("never-prepared cancellation lost denial-only fence: %v", err)
		}
	}
	if _, err := f.svc.PrepareResourceExecution(t.Context(), connect.NewRequest(&agentv1.PrepareResourceExecutionRequest{IntentEnvelope: envelope})); err == nil {
		t.Fatal("late prepare bypassed durable cancellation")
	}
	if n.polls.Load() != 0 || n.applies.Load() != 0 {
		t.Fatal("never-prepared cancellation launched helper")
	}
}

func TestResourcePreparationDuplicateActionCannotRebindIntent(t *testing.T) {
	f, n, intent := newPreparationFixture(t)
	_, envelope := f.prepare(t, intent)
	before, revision := serviceRow(t, f.svc, intent.GetActionId())
	changed := proto.CloneOf(intent)
	changed.Preparation.MaxCacheBytes++
	conflict := mustSign(t, f.svc.authority, changed, f.planKey)
	if _, err := f.svc.PrepareResourceExecution(t.Context(), connect.NewRequest(&agentv1.PrepareResourceExecutionRequest{IntentEnvelope: conflict})); connect.CodeOf(err) != connect.CodeAlreadyExists {
		t.Fatalf("duplicate staging action rebound signed quota: %v", err)
	}
	if _, err := f.svc.CancelResourcePreparation(t.Context(), connect.NewRequest(&agentv1.CancelResourcePreparationRequest{ActionId: intent.GetActionId(), IntentSha256: digestBytes(conflict)})); connect.CodeOf(err) != connect.CodeAlreadyExists {
		t.Fatalf("foreign digest canceled owned staging: %v", err)
	}
	after, afterRevision := serviceRow(t, f.svc, intent.GetActionId())
	if revision != afterRevision || !proto.Equal(before, after) || n.polls.Load() != 1 || n.cancels.Load() != 0 || !bytes.Equal(after.GetIntentSha256(), digestBytes(envelope)) {
		t.Fatal("conflicting retry changed staging ownership, native work or acceptance")
	}
}

func TestResourcePreparationConcurrentExactPollDoesNotLaunchTwice(t *testing.T) {
	f, n, intent := newPreparationFixture(t)
	n.entered, n.release = make(chan struct{}), make(chan struct{})
	envelope := mustSign(t, f.svc.authority, intent, f.planKey)
	result := make(chan error, 1)
	go func() {
		_, err := f.svc.PrepareResourceExecution(t.Context(), connect.NewRequest(&agentv1.PrepareResourceExecutionRequest{IntentEnvelope: envelope}))
		result <- err
	}()
	waitBoundary(t, n.entered)
	second, err := f.svc.PrepareResourceExecution(t.Context(), connect.NewRequest(&agentv1.PrepareResourceExecutionRequest{IntentEnvelope: envelope}))
	if err != nil {
		t.Fatal(err)
	}
	assertPreparing(t, second.Msg)
	if n.polls.Load() != 1 {
		t.Fatal("concurrent exact request launched another native stage")
	}
	close(n.release)
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("bounded native poll did not return")
	}
}
