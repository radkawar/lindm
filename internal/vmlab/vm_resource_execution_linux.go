//go:build linux

package vmlab

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
	labv1 "lindm/gen/lindm/lab/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/devlab"
	"lindm/internal/trust"
)

// This lane precedes production profile admission. It uses real signed authority
// admitted by the offline root and the installed sandboxed executor, not a
// provider call or server gate bypass. Connected integration is a separate run.
func exerciseSignedNativeResources(ctx context.Context, packages *nativeGuestPackages, signer *devlab.ExecutionTrustExercise, result *VMDispatchResult) error {
	result.Resources.ExecutionPath = "installed-signed-executor"
	identity, err := readVMConnectionIdentity(ctx, packages.vm)
	if err != nil {
		return err
	}
	rpm := resourcePackaging{rpm: result.Distribution == "fedora", arm: result.Architecture == "arm64"}
	for _, kind := range []struct {
		index   int
		desired []*resourcev1.ResourceDesiredState
		names   []string
	}{
		{0, []*resourcev1.ResourceDesiredState{resourcePackageDesired(rpm, "1.0", true), resourcePackageDesired(rpm, "2.0", true), resourcePackageDesired(rpm, "2.0", true), resourcePackageDesired(rpm, "2.0", false), resourcePackageDesired(rpm, "2.0", true)}, []string{"exact-v1-dependency-readiness", "exact-v2-upgrade", "repeat-exact-v2", "owned-absence", "presence-after-absence"}},
		{1, []*resourcev1.ResourceDesiredState{resourceFileDesired("direct", "first\n"), resourceFileDesired("direct", "second\n"), resourceFileDesired("direct", "second\n")}, []string{"create", "reconcile", "repeat"}},
	} {
		evidence := &result.Resources.Kinds[kind.index]
		profile, resourceID := uuid.NewString(), uuid.NewString()
		for index, desired := range kind.desired {
			evidence.Scenarios = append(evidence.Scenarios, VMResourceScenario{Name: kind.names[index], StartedAt: time.Now().UTC()})
			s := &evidence.Scenarios[len(evidence.Scenarios)-1]
			status, intentBytes, err := executeSignedNativeResource(ctx, packages, signer, identity, profile, resourceID, uint64(index+1), desired, resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE, &s.ExecutorHistory)
			s.ExecutorStatus = status
			if err != nil {
				s.Failure = err.Error()
				return err
			}
			if index == 2 && status.GetStartedAt() != nil {
				return errors.New("repeat direct signed resource unexpectedly started")
			}
			var native VMResourceNativeRecord
			if kind.index == 0 {
				version := "2.0"
				if index == 0 {
					version = "1.0"
				}
				native, err = packageOracle(ctx, packages.vm, rpm, version, index != 3)
			} else {
				native, err = fileOracle(ctx, packages.vm, "direct", string(desired.GetManagedFile().GetContent()), true)
			}
			if err != nil {
				s.Failure = err.Error()
				return err
			}
			s.Native = []VMResourceNativeRecord{resourceNativeRecord("signed-intent-envelope", intentBytes), native}
			s.Passed = true
			s.FinishedAt = time.Now().UTC()
		}
		desired := kind.desired[len(kind.desired)-1]
		evidence.Scenarios = append(evidence.Scenarios, VMResourceScenario{Name: "signed-ledger-release", StartedAt: time.Now().UTC()})
		s := &evidence.Scenarios[len(evidence.Scenarios)-1]
		status, intentBytes, err := executeSignedNativeResource(ctx, packages, signer, identity, profile, resourceID, uint64(len(kind.desired)+1), desired, resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE, &s.ExecutorHistory)
		s.ExecutorStatus = status
		if err != nil {
			s.Failure = err.Error()
			return err
		}
		var native VMResourceNativeRecord
		if kind.index == 0 {
			native, err = packageOracle(ctx, packages.vm, rpm, "", false)
		} else {
			native, err = fileOracle(ctx, packages.vm, "direct", "", false)
		}
		if err != nil {
			s.Failure = err.Error()
			return err
		}
		s.Native = []VMResourceNativeRecord{resourceNativeRecord("signed-release-envelope", intentBytes), native}
		s.Passed = true
		s.FinishedAt = time.Now().UTC()
		evidence.Unproven = []string{"production server profile assignment, exact independent adoption approval and release dispatch require separate connected qualification", "negative wrong-key/version, external drift and interrupted-running no-replay scenarios require connected qualification"}
		required := append(append([]string(nil), kind.names...), "signed-ledger-release")
		if err := qualifyResourceEvidence(evidence, required); err != nil {
			return err
		}
	}
	return nil
}

func executeSignedNativeResource(ctx context.Context, packages *nativeGuestPackages, signer *devlab.ExecutionTrustExercise, identity *labv1.ConnectionIdentityEvidence, profile, resourceID string, sequence uint64, desired *resourcev1.ResourceDesiredState, operation resourcev1.ResourceOperation, history *[]vmServiceAttestationPhase) (*agentv1.ResourceExecutionStatus, []byte, error) {
	now := time.Now().UTC()
	revision := uuid.NewString()
	intent := &agentv1.ResourceExecutionIntent{DeploymentId: identity.GetDeploymentId(), DeviceId: identity.GetDeviceId(), EnrollmentGeneration: identity.GetEnrollmentGeneration(), ActionId: uuid.NewString(), DesiredRevision: revision, ActorId: uuid.NewString(), ResourceSequence: sequence, RecoveryEpoch: 1, RootVersion: 2, DelegationVersion: 2, AuthorizationVersion: 1, NotBefore: timestamppb.New(now.Add(-trust.MaxDeviceClockSkew)), ExpiresAt: timestamppb.New(now.Add(10 * time.Minute)), Desired: desired, Operation: operation, Ownership: &agentv1.ResourceOwnershipBinding{AssignmentId: revision, ResourceId: resourceID, Policy: resourceCreatePolicy(), Sources: []*agentv1.ResourceOwnershipSource{{ProfileId: profile, ProfileRevision: revision, ResourceId: resourceID}}}}
	if desired.GetNativePackage() != nil {
		intent.Preparation = &agentv1.ResourceExecutionPreparation{Deadline: timestamppb.New(now.Add(8 * time.Minute)), MaxCacheBytes: 128 << 20}
	}
	envelope, err := signer.SignResourceIntent(ctx, intent)
	if err != nil {
		return nil, nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 9*time.Minute)
	defer cancel()
	prepared := new(agentv1.PrepareResourceExecutionResponse)
	for {
		if err := vmServiceRPC(ctx, packages, "resource-prepare", intent.GetActionId(), &agentv1.PrepareResourceExecutionRequest{IntentEnvelope: envelope}, prepared); err != nil {
			return nil, envelope, err
		}
		if prepared.GetStatus().GetState() != agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_PREPARING {
			break
		}
		if err := lifecycleDelay(ctx, 250*time.Millisecond); err != nil {
			return prepared.GetStatus(), envelope, err
		}
	}
	status := prepared.GetStatus()
	if status.GetState() == agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_PREPARED {
		certificate, err := packages.vm.run(ctx, "sudo -n -u lindm -- "+nativeQuote(nativeGuestDir+"/lab-probe")+" guest connection-certificate", nil, 16384, 15*time.Second)
		if err != nil {
			return status, envelope, err
		}
		_, grant, err := signer.SignResourceStart(ctx, intent, envelope, certificate, prepared)
		if err != nil {
			return status, envelope, err
		}
		action := &vmPreparedService{intent: intent, envelope: envelope, prepared: prepared, start: &agentv1.StartResourceExecutionRequest{ActionId: intent.GetActionId(), StartGrantEnvelope: grant}}
		status, err = vmStartService(ctx, packages, action)
		if err != nil {
			return status, envelope, err
		}
	}
	if status.GetState() != agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_SUCCEEDED || status.GetVerification().GetDisposition() != resourcev1.VerificationDisposition_VERIFICATION_DISPOSITION_CONVERGED {
		return status, envelope, fmt.Errorf("direct native resource did not converge: %s", status)
	}
	// Authenticate retained executor history with the same established identity
	// binding used by the service lane; it is not a fresh observation oracle.
	deployment, err := uuid.Parse(identity.GetDeploymentId())
	if err != nil {
		return status, envelope, err
	}
	device, err := uuid.Parse(identity.GetDeviceId())
	if err != nil {
		return status, envelope, err
	}
	generation, err := uuid.Parse(identity.GetEnrollmentGeneration())
	if err != nil {
		return status, envelope, err
	}
	actionID, err := uuid.Parse(intent.GetActionId())
	if err != nil {
		return status, envelope, err
	}
	evidence := &vmServiceExecutionEvidence{packages: packages, verifier: signer, identity: proto.CloneOf(identity), Completed: []*agentv1.ResourceExecutionStatus{status}, bindings: map[string]trust.ResourceAttestationBinding{intent.GetActionId(): {DeploymentID: deployment, DeviceID: device, EnrollmentGeneration: generation, ActionID: actionID, IntentSHA256: sha256.Sum256(envelope)}}}
	if err := vmAttestServiceActions(ctx, evidence, "native-resource", false); err != nil {
		return status, envelope, err
	}
	*history = evidence.Attestations
	return status, envelope, nil
}
