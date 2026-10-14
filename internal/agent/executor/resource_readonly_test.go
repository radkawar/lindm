// SPDX-License-Identifier: Apache-2.0

//go:build linux

package executor

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"

	"buf.build/go/protovalidate"
	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/agent/journal"
	"lindm/internal/device/dispatch"
	"lindm/internal/resource"
)

// Synthetic native observations isolate the real signed executor and journal
// lifecycle. These tests do not claim host encryption or module effects.
type readOnlyNative struct {
	fixture         *resourceFixture
	service         *Service
	disposition     resourcev1.VerificationDisposition
	verificationErr error
	corrupt         bool
	missing         bool
	applies         atomic.Int32
}

func (n *readOnlyNative) Close() error { return nil }
func (n *readOnlyNative) Plan(_ context.Context, desired *resourcev1.ResourceDesiredState, operation resourcev1.ResourceOperation) (*resourcev1.ResourcePlan, error) {
	backend := &resourcev1.BackendSelection{Backend: resourcev1.Backend_BACKEND_LUKS_COMPLIANCE, NativeVersion: "2", ProviderVersion: "1", Product: &resourcev1.PlatformProduct{OsId: "ubuntu", Product: "Ubuntu", Version: "24.04", Architecture: "x86_64"}}
	native := &resourcev1.EncryptionComplianceObservation{LuksRoot: proto.Bool(false), EvidenceSha256: bytes.Repeat([]byte{1}, 32)}
	if n.disposition == resourcev1.VerificationDisposition_VERIFICATION_DISPOSITION_CONVERGED {
		native.LuksRoot, native.RootLuksUuid = proto.Bool(true), proto.String(uuid.NewString())
		native.RootIdentityBasis = resourcev1.RootStorageIdentityBasis_ROOT_STORAGE_IDENTITY_BASIS_WWN_SERIAL
		native.RootWwn, native.RootSerial, native.RootSizeBytes = "synthetic-wwn", "synthetic-serial", 4096
	}
	before := &resourcev1.ResourceObservation{Ref: proto.CloneOf(desired.GetRef()), Metadata: &resourcev1.ObservationMetadata{BootId: n.fixture.boot, ExecutorIncarnation: n.service.incarnation, ObservedAt: protoTimestamp(n.service.now()), Backend: backend, NativeRevision: bytes.Repeat([]byte{2}, 32), ObservationStatus: resourcev1.ObservationStatus_OBSERVATION_STATUS_OK}, Observed: &resourcev1.ResourceObservation_EncryptionCompliance{EncryptionCompliance: native}}
	if n.disposition == resourcev1.VerificationDisposition_VERIFICATION_DISPOSITION_UNKNOWN {
		native.LuksRoot = nil
		before.Metadata.ObservationStatus = resourcev1.ObservationStatus_OBSERVATION_STATUS_UNAVAILABLE
		before.Metadata.Reason = "native evidence unavailable"
	}
	if blocklist := desired.GetManagedFile().GetKernelModuleBlocklist(); blocklist != nil {
		backend.Backend, backend.NativeVersion = resourcev1.Backend_BACKEND_POSIX_FILE, "6.8.0"
		modules := make([]*resourcev1.KernelModuleObservation, 0, len(blocklist.GetModules()))
		for _, name := range blocklist.GetModules() {
			modules = append(modules, &resourcev1.KernelModuleObservation{Name: name, Loaded: n.disposition == resourcev1.VerificationDisposition_VERIFICATION_DISPOSITION_PENDING_REBOOT, BuiltIn: n.disposition == resourcev1.VerificationDisposition_VERIFICATION_DISPOSITION_NOT_APPLICABLE, ModprobeBlocked: n.disposition != resourcev1.VerificationDisposition_VERIFICATION_DISPOSITION_NOT_APPLICABLE})
		}
		file := &resourcev1.ManagedFileObservation{Path: desired.GetManagedFile().GetPath(), Exists: true, File: &resourcev1.FileIdentity{Path: desired.GetManagedFile().GetPath(), Mode: 0644, Sha256: bytes.Repeat([]byte{1}, 32), Device: 1, Inode: 2}, AncestrySha256: bytes.Repeat([]byte{2}, 32), NativeIdentitySha256: bytes.Repeat([]byte{3}, 32), SecurityMetadataSha256: bytes.Repeat([]byte{4}, 32), KernelModuleBlocklist: &resourcev1.KernelModuleBlocklistObservation{Modules: modules, Initramfs: []*resourcev1.ModuleInitramfsObservation{{KernelRelease: "6.8.0", Path: "/boot/initrd.img-6.8.0", Sha256: bytes.Repeat([]byte{5}, 32), BlocklistSha256: bytes.Repeat([]byte{1}, 32)}}}}
		before.Observed = &resourcev1.ResourceObservation_ManagedFile{ManagedFile: file}
	}
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
	result := &resourcev1.ResourcePlan{Ref: proto.CloneOf(desired.GetRef()), Operation: operation, DesiredSha256: desiredDigest[:], ObservationSha256: observationDigest[:], Before: before, Backend: backend, Claims: claims, OwnershipRevisionSha256: bytes.Repeat([]byte{3}, 32),
		Safety: &resourcev1.PlanSafety{LockDomains: []resourcev1.ClaimDomain{resourcev1.ClaimDomain_CLAIM_DOMAIN_ENCRYPTION_COMPLIANCE}, Reversibility: resourcev1.Reversibility_REVERSIBILITY_REVERSIBLE, RollbackScope: resourcev1.RollbackScope_ROLLBACK_SCOPE_NONE, Confirmation: resourcev1.ConfirmationPolicy_CONFIRMATION_POLICY_NOT_REQUIRED},
		Plan:   &resourcev1.ResourcePlan_EncryptionCompliance{EncryptionCompliance: &resourcev1.EncryptionCompliancePlan{Desired: proto.CloneOf(desired.GetEncryptionCompliance()), Before: native, Change: resourcev1.NativeObjectChange_NATIVE_OBJECT_CHANGE_OBSERVE}},
	}
	if desired.GetManagedFile().GetKernelModuleBlocklist() != nil {
		result.Safety.LockDomains = []resourcev1.ClaimDomain{resourcev1.ClaimDomain_CLAIM_DOMAIN_NATIVE_FILE}
		result.Safety.RollbackScope = resourcev1.RollbackScope_ROLLBACK_SCOPE_OWNED_DIMENSIONS
		result.Plan = &resourcev1.ResourcePlan_ManagedFile{ManagedFile: &resourcev1.ManagedFilePlan{Desired: proto.CloneOf(desired.GetManagedFile()), Before: proto.CloneOf(before.GetManagedFile()), Change: resourcev1.NativeObjectChange_NATIVE_OBJECT_CHANGE_OBSERVE}}
	}
	return result, nil
}
func (n *readOnlyNative) Observe(context.Context, *resourcev1.ResourceDesiredState) (*resourcev1.ResourceObservation, error) {
	return nil, errors.New("fixture does not observe")
}

func (n *readOnlyNative) Verify(_ context.Context, plan *resourcev1.ResourcePlan) (*resourcev1.ResourceVerification, error) {
	if n.missing {
		return nil, n.verificationErr
	}
	digest, err := resource.PlanDigest(plan)
	if err != nil {
		return nil, err
	}
	converged := n.disposition == resourcev1.VerificationDisposition_VERIFICATION_DISPOSITION_CONVERGED
	verification := &resourcev1.ResourceVerification{Ref: proto.CloneOf(plan.GetRef()), DesiredSha256: bytes.Clone(plan.GetDesiredSha256()), PlanSha256: digest[:], After: proto.CloneOf(plan.GetBefore()), Disposition: n.disposition,
		Checks: &resourcev1.ResourceVerification_EncryptionCompliance{EncryptionCompliance: &resourcev1.EncryptionComplianceChecks{LuksRootRequirementMet: converged, EscrowRequirementMet: true, TpmRequirementMet: true, EvidenceComplete: n.disposition != resourcev1.VerificationDisposition_VERIFICATION_DISPOSITION_UNKNOWN, Converged: converged}},
	}
	if plan.GetManagedFile() != nil {
		verification.Checks = &resourcev1.ResourceVerification_ManagedFile{ManagedFile: &resourcev1.ManagedFileChecks{PresenceMatches: true, ContentMatches: true, ModeMatches: true, OwnerMatches: true, AncestrySafe: true, ModuleLoadsBlocked: proto.Bool(n.disposition != resourcev1.VerificationDisposition_VERIFICATION_DISPOSITION_NOT_APPLICABLE), ModulesUnloaded: proto.Bool(false), InitramfsMatches: proto.Bool(true)}}
	}
	if n.corrupt {
		verification.PlanSha256[0]++
	}
	return verification, n.verificationErr
}
func (n *readOnlyNative) Apply(context.Context, *resourcev1.ResourcePlan, func(context.Context) error) (*resourcev1.ResourceVerification, error) {
	n.applies.Add(1)
	return nil, errors.New("read-only plan reached effect worker")
}
func (n *readOnlyNative) option() Option {
	return func(s *Service) {
		n.service = s
		s.openResource = func(context.Context, *agentv1.ResourceExecutionIntent, secretAccessor) (nativeResource, error) {
			return n, nil
		}
	}
}
func readOnlyFixture(t *testing.T, disposition resourcev1.VerificationDisposition) (*resourceFixture, *readOnlyNative, *agentv1.ResourceExecutionIntent) {
	t.Helper()
	f := newResourceFixture(t, false, true)
	plan, start := delegate(t, f.planKey), delegate(t, f.startKey)
	plan.Capabilities, start.Capabilities = []string{"encryption.compliance.v1"}, []string{"encryption.compliance.v1"}
	start.Role = agentv1.ExecutionSignerRole_EXECUTION_SIGNER_ROLE_START
	doc := delegationDocument(f.fix.deploy.String(), 1, 1, 0, f.now, plan, start)
	callTrust(t, f.svc, &agentv1.UpdateExecutionTrustRequest{DelegationEnvelope: mustSign(t, f.svc.authority, doc, f.fix.rootKey)})
	intent := f.intent(t, 1)
	intent.Desired = &resourcev1.ResourceDesiredState{Ref: &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_ENCRYPTION_COMPLIANCE, CanonicalKey: "system/root"}, State: &resourcev1.ResourceDesiredState_EncryptionCompliance{EncryptionCompliance: &resourcev1.EncryptionComplianceDesired{RequireLuksRoot: true}}}
	n := &readOnlyNative{fixture: f, disposition: disposition}
	f.svc.mu.Lock()
	n.option()(f.svc)
	f.svc.mu.Unlock()
	return f, n, intent
}

func TestReadOnlyResourceFindingsAreDurableWithoutEffectAuthority(t *testing.T) {
	for _, disposition := range []resourcev1.VerificationDisposition{resourcev1.VerificationDisposition_VERIFICATION_DISPOSITION_CONVERGED, resourcev1.VerificationDisposition_VERIFICATION_DISPOSITION_DRIFTED, resourcev1.VerificationDisposition_VERIFICATION_DISPOSITION_UNKNOWN, resourcev1.VerificationDisposition_VERIFICATION_DISPOSITION_NOT_APPLICABLE} {
		t.Run(disposition.String(), func(t *testing.T) {
			f, n, intent := readOnlyFixture(t, disposition)
			if disposition == resourcev1.VerificationDisposition_VERIFICATION_DISPOSITION_NOT_APPLICABLE {
				intent.Operation = resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE
			}
			if disposition == resourcev1.VerificationDisposition_VERIFICATION_DISPOSITION_DRIFTED {
				n.verificationErr = fmt.Errorf("native observation: %w", resource.ErrNotConverged)
			}
			response, envelope := f.prepare(t, intent)
			status := response.GetStatus()
			failed := disposition == resourcev1.VerificationDisposition_VERIFICATION_DISPOSITION_DRIFTED || disposition == resourcev1.VerificationDisposition_VERIFICATION_DISPOSITION_UNKNOWN
			if !status.GetReadOnly() || status.GetCompletedAt() == nil || status.GetStartedAt() != nil || len(response.GetChallengeProof()) != 0 || status.GetVerification().GetDisposition() != disposition || n.applies.Load() != 0 {
				t.Fatal("read-only finding lost evidence or gained effect authority")
			}
			if failed && (status.GetState() != agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_FAILED || status.GetFailure() != agentv1.ResourceExecutionFailure_RESOURCE_EXECUTION_FAILURE_POSTCONDITION) {
				t.Fatal("noncompliance was not a postcondition failure")
			}
			if !failed && status.GetState() != agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_SUCCEEDED {
				t.Fatal("valid read-only success rejected")
			}
			_, attestation := attestResource(t, f, status)
			if !attestation.GetStatus().GetReadOnly() || !proto.Equal(attestation.GetStatus(), status) {
				t.Fatal("device attestation lost read-only terminal semantics")
			}
			record, revision := resourceRow(t, f.svc, intent.GetActionId())
			if record.GetChallenge() != nil || len(record.GetStartGrantEnvelope()) != 0 {
				t.Fatal("read-only record retained unused effect grant")
			}
			if err := f.svc.Close(); err != nil {
				t.Fatal(err)
			}
			next, err := New(t.Context(), f.svc.directory, append(f.options(), n.option())...)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = next.Close() })
			f.svc = next
			retry, err := next.PrepareResourceExecution(t.Context(), connect.NewRequest(&agentv1.PrepareResourceExecutionRequest{IntentEnvelope: envelope}))
			if err != nil || !proto.Equal(status, retry.Msg.GetStatus()) {
				t.Fatalf("restart lost read-only finding: %v", err)
			}
			_, afterRevision := resourceRow(t, next, intent.GetActionId())
			if afterRevision != revision || n.applies.Load() != 0 {
				t.Fatal("restart replayed a read-only terminal finding")
			}
		})
	}
}

func TestModuleReadOnlyFindingsRemainSignedFailedAndDurable(t *testing.T) {
	for _, disposition := range []resourcev1.VerificationDisposition{resourcev1.VerificationDisposition_VERIFICATION_DISPOSITION_PENDING_REBOOT, resourcev1.VerificationDisposition_VERIFICATION_DISPOSITION_NOT_APPLICABLE} {
		t.Run(disposition.String(), func(t *testing.T) {
			f, n, intent := readOnlyFixture(t, disposition)
			planSigner, startSigner := delegate(t, f.planKey), delegate(t, f.startKey)
			planSigner.Capabilities, startSigner.Capabilities = []string{"managed.file.v1"}, []string{"managed.file.v1"}
			startSigner.Role = agentv1.ExecutionSignerRole_EXECUTION_SIGNER_ROLE_START
			doc := delegationDocument(f.fix.deploy.String(), 1, 2, 0, f.now, planSigner, startSigner)
			callTrust(t, f.svc, &agentv1.UpdateExecutionTrustRequest{DelegationEnvelope: mustSign(t, f.svc.authority, doc, f.fix.rootKey)})
			intent.DelegationVersion = 2
			path := "/etc/modprobe.d/99-lindm-blocklist.conf"
			intent.Desired = &resourcev1.ResourceDesiredState{Ref: &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_MANAGED_FILE, CanonicalKey: path}, State: &resourcev1.ResourceDesiredState_ManagedFile{ManagedFile: &resourcev1.ManagedFileDesired{Path: path, Presence: resourcev1.Presence_PRESENCE_PRESENT, KernelModuleBlocklist: &resourcev1.KernelModuleBlocklist{Modules: []string{"usb_storage"}}}}}
			n.verificationErr = resource.ErrNotConverged
			response, envelope := f.prepare(t, intent)
			status := response.GetStatus()
			if !status.GetReadOnly() || status.GetState() != agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_FAILED || status.GetFailure() != agentv1.ResourceExecutionFailure_RESOURCE_EXECUTION_FAILURE_POSTCONDITION || status.GetVerification().GetDisposition() != disposition || status.GetStartedAt() != nil || len(response.GetChallengeProof()) != 0 || n.applies.Load() != 0 {
				t.Fatal("module finding became success or acquired effect authority")
			}
			if err := dispatch.ResourceResultBinding(intent, status); err != nil {
				t.Fatalf("server rejected typed module finding: %v", err)
			}
			// The same native finding after an actual effect must also remain a
			// schema-valid failed result rather than a successful release.
			effectful := proto.CloneOf(status)
			effectful.ReadOnly = false
			effectful.StartedAt = proto.CloneOf(effectful.AcceptedAt)
			effectful.Failure = agentv1.ResourceExecutionFailure_RESOURCE_EXECUTION_FAILURE_NATIVE
			if err := protovalidate.Validate(effectful); err != nil {
				t.Fatalf("effectful module finding rejected by schema: %v", err)
			}
			if err := dispatch.ResourceResultBinding(intent, effectful); err != nil {
				t.Fatalf("server rejected effectful module finding: %v", err)
			}
			_, attestation := attestResource(t, f, status)
			if !proto.Equal(attestation.GetStatus(), status) {
				t.Fatal("signed module finding changed")
			}
			record, revision := resourceRow(t, f.svc, intent.GetActionId())
			if record.GetChallenge() != nil || len(record.GetStartGrantEnvelope()) != 0 {
				t.Fatal("module finding retained effect authority")
			}
			if err := f.svc.Close(); err != nil {
				t.Fatal(err)
			}
			next, err := New(t.Context(), f.svc.directory, append(f.options(), n.option())...)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = next.Close() })
			f.svc = next
			retry, err := next.PrepareResourceExecution(t.Context(), connect.NewRequest(&agentv1.PrepareResourceExecutionRequest{IntentEnvelope: envelope}))
			if err != nil || !proto.Equal(status, retry.Msg.GetStatus()) {
				t.Fatalf("restart lost module finding: %v", err)
			}
			_, afterRevision := resourceRow(t, next, intent.GetActionId())
			if revision != afterRevision || n.applies.Load() != 0 {
				t.Fatal("restart replayed a module finding")
			}
		})
	}
}

func TestReadOnlyResourceRejectsInvalidOrUnrelatedVerificationFailures(t *testing.T) {
	for _, cause := range []string{"unrelated-error", "missing-evidence", "corrupt-digest", "reconcile-not-applicable", "converged-with-error"} {
		t.Run(cause, func(t *testing.T) {
			f, n, intent := readOnlyFixture(t, resourcev1.VerificationDisposition_VERIFICATION_DISPOSITION_CONVERGED)
			switch cause {
			case "unrelated-error":
				n.verificationErr = errors.New("native I/O failure")
			case "missing-evidence":
				n.missing = true
				n.verificationErr = resource.ErrNotConverged
			case "corrupt-digest":
				n.corrupt = true
			case "reconcile-not-applicable":
				n.disposition = resourcev1.VerificationDisposition_VERIFICATION_DISPOSITION_NOT_APPLICABLE
			case "converged-with-error":
				n.verificationErr = resource.ErrNotConverged
			}
			envelope := mustSign(t, f.svc.authority, intent, f.planKey)
			if _, err := f.svc.PrepareResourceExecution(t.Context(), connect.NewRequest(&agentv1.PrepareResourceExecutionRequest{IntentEnvelope: envelope})); err == nil {
				t.Fatal("invalid verification became accepted read-only success")
			}
			if _, _, err := f.svc.store.LoadResourceAction(t.Context(), intent.GetActionId()); !errors.Is(err, journal.ErrResourceActionNotFound) {
				t.Fatal("invalid evidence created durable authority")
			}
			if n.applies.Load() != 0 {
				t.Fatal("invalid read-only verification reached native mutation")
			}
		})
	}
}
