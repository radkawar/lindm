// SPDX-License-Identifier: Apache-2.0

//go:build linux

package executor

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/agent/fileprovider"
	"lindm/internal/agent/journal"
	"lindm/internal/agent/nativeexec"
	"lindm/internal/agent/serviceprovider"
	"lindm/internal/agent/sshprovider"
	"lindm/internal/custody"
)

type admissionRefusingNative struct {
	nativeResource
	refusal       error
	plans         int
	beforeRefusal func()
}

func (n *admissionRefusingNative) Plan(context.Context, *resourcev1.ResourceDesiredState, resourcev1.ResourceOperation) (*resourcev1.ResourcePlan, error) {
	n.plans++
	if n.beforeRefusal != nil {
		n.beforeRefusal()
	}
	return nil, n.refusal
}

func TestResourceAdmissionRefusalIsDurableAuthenticatedAndNeverAnEffect(t *testing.T) {
	for _, tc := range []struct {
		name    string
		cause   error
		reason  agentv1.ResourceAdmissionRefusalReason
		failure agentv1.ResourceExecutionFailure
	}{
		{"baseline", serviceprovider.ErrBaselineUnknown, agentv1.ResourceAdmissionRefusalReason_RESOURCE_ADMISSION_REFUSAL_REASON_BASELINE_UNKNOWN, agentv1.ResourceExecutionFailure_RESOURCE_EXECUTION_FAILURE_UNSUPPORTED},
		{"unsupported", serviceprovider.ErrUnsupported, agentv1.ResourceAdmissionRefusalReason_RESOURCE_ADMISSION_REFUSAL_REASON_UNSUPPORTED_NATIVE, agentv1.ResourceExecutionFailure_RESOURCE_EXECUTION_FAILURE_UNSUPPORTED},
		{"precondition", serviceprovider.ErrConflict, agentv1.ResourceAdmissionRefusalReason_RESOURCE_ADMISSION_REFUSAL_REASON_PRECONDITION, agentv1.ResourceExecutionFailure_RESOURCE_EXECUTION_FAILURE_PRECONDITION},
		{"ssh-unsupported", sshprovider.ErrUnsupported, agentv1.ResourceAdmissionRefusalReason_RESOURCE_ADMISSION_REFUSAL_REASON_UNSUPPORTED_NATIVE, agentv1.ResourceExecutionFailure_RESOURCE_EXECUTION_FAILURE_UNSUPPORTED},
		{"ssh-collision", sshprovider.ErrConflict, agentv1.ResourceAdmissionRefusalReason_RESOURCE_ADMISSION_REFUSAL_REASON_PRECONDITION, agentv1.ResourceExecutionFailure_RESOURCE_EXECUTION_FAILURE_PRECONDITION},
		// The record and status schemas once omitted this reason, so its
		// refusal failed validation and was retried as an internal error.
		{"unsafe-tool-path", errors.Join(nativeexec.ErrUntrustedExecutable, fmt.Errorf("%w: replaceable ancestry of /usr/bin/rpm", custody.ErrUnsafe)), agentv1.ResourceAdmissionRefusalReason_RESOURCE_ADMISSION_REFUSAL_REASON_UNSAFE_NATIVE_TOOL_PATH, agentv1.ResourceExecutionFailure_RESOURCE_EXECUTION_FAILURE_PRECONDITION},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newResourceFixture(t, false)
			native := &admissionRefusingNative{nativeResource: f.native, refusal: tc.cause}
			f.svc.openResource = func(context.Context, *agentv1.ResourceExecutionIntent, secretAccessor) (nativeResource, error) {
				return native, nil
			}
			intent := f.intent(t, 1)
			intent.Operation = resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE
			prepared, envelope := f.prepare(t, intent)
			status := prepared.GetStatus()
			refusal := status.GetAdmissionRefusal()
			if status.GetState() != agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_FAILED || status.GetFailure() != tc.failure || refusal.GetReason() != tc.reason || !refusal.GetNativeEvidenceUnavailable() || !proto.Equal(refusal.GetRef(), intent.GetDesired().GetRef()) || refusal.GetOperation() != intent.GetOperation() || refusal.GetBootId() != f.boot || refusal.GetExecutorIncarnation() != f.svc.incarnation {
				t.Fatal("admission rejection lost its authenticated identity or honest classification")
			}
			if prepared.GetNativePlan() != nil || len(prepared.GetChallengeProof()) != 0 || status.GetBefore() != nil || status.GetVerification() != nil || status.GetStartedAt() != nil || status.GetReadOnly() || status.GetPreparationOutcome() != nil || status.GetCompletedAt() == nil {
				t.Fatal("refusal fabricated native evidence, success, or effect authority")
			}
			_, attested := attestResource(t, f, status)
			if !proto.Equal(attested.GetStatus(), status) {
				t.Fatal("signed history lost refusal")
			}
			record, revision := resourceRow(t, f.svc, intent.GetActionId())
			if record.GetChallenge() != nil || len(record.GetStartGrantEnvelope()) != 0 {
				t.Fatal("refusal retained effect authority")
			}
			if _, err := f.svc.StartResourceExecution(t.Context(), connect.NewRequest(&agentv1.StartResourceExecutionRequest{ActionId: intent.GetActionId(), StartGrantEnvelope: []byte("no grant exists")})); connect.CodeOf(err) != connect.CodePermissionDenied {
				t.Fatalf("refused action could start: %v", err)
			}
			retry, err := f.svc.PrepareResourceExecution(t.Context(), connect.NewRequest(&agentv1.PrepareResourceExecutionRequest{IntentEnvelope: envelope}))
			if err != nil || !proto.Equal(retry.Msg, prepared) || native.plans != 1 {
				t.Fatalf("exact retry reran preflight: %v", err)
			}
			if f.native.applies.Load() != 0 || f.native.verifies.Load() != 0 || f.native.effects.Load() != 0 {
				t.Fatal("refusal touched native state")
			}
			directory := f.svc.directory
			if err := f.svc.Close(); err != nil {
				t.Fatal(err)
			}
			f.svc, err = New(t.Context(), directory, f.options()...)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = f.svc.Close() })
			after, afterRevision := resourceRow(t, f.svc, intent.GetActionId())
			if revision != afterRevision || !proto.Equal(record, after) {
				t.Fatal("restart changed terminal refusal")
			}
			if _, err := f.svc.GetResourceExecution(t.Context(), connect.NewRequest(&agentv1.GetResourceExecutionRequest{ActionId: intent.GetActionId()})); err != nil {
				t.Fatalf("historical refusal rejected after restart: %v", err)
			}
		})
	}
}

func TestResourceAdmissionRefusalRequiresFreshAuthorityAndClassifiedCause(t *testing.T) {
	for _, scenario := range []string{"expired-during-plan", "unclassified-error", "canceled", "baseline-on-reconcile", "outcome-unknown-without-unknown-ledger"} {
		t.Run(scenario, func(t *testing.T) {
			f := newResourceFixture(t, false)
			native := &admissionRefusingNative{nativeResource: f.native, refusal: serviceprovider.ErrUnsupported}
			switch scenario {
			case "expired-during-plan":
				native.beforeRefusal = func() { f.wall.Store(f.now.Add(6 * time.Minute).UnixNano()) }
			case "unclassified-error":
				native.refusal = errors.New("unexpected native failure")
			case "canceled":
				native.refusal = context.Canceled
			case "baseline-on-reconcile":
				native.refusal = serviceprovider.ErrBaselineUnknown
			case "outcome-unknown-without-unknown-ledger":
				// Only a durably UNKNOWN ledger proves the earlier effect.
				native.refusal = fileprovider.ErrOutcomeUnknown
			}
			f.svc.openResource = func(context.Context, *agentv1.ResourceExecutionIntent, secretAccessor) (nativeResource, error) {
				return native, nil
			}
			intent := f.intent(t, 1)
			envelope := mustSign(t, f.svc.authority, intent, f.planKey)
			if _, err := f.svc.PrepareResourceExecution(t.Context(), connect.NewRequest(&agentv1.PrepareResourceExecutionRequest{IntentEnvelope: envelope})); err == nil {
				t.Fatal("invalid refusal was accepted")
			}
			if _, _, err := f.svc.store.LoadResourceAction(t.Context(), intent.GetActionId()); !errors.Is(err, journal.ErrResourceActionNotFound) {
				t.Fatalf("invalid refusal persisted: %v", err)
			}
		})
	}
}

func TestResourceProviderOpenRefusalIsNotNativeObservation(t *testing.T) {
	f := newResourceFixture(t, false)
	f.svc.openResource = func(context.Context, *agentv1.ResourceExecutionIntent, secretAccessor) (nativeResource, error) {
		return nil, serviceprovider.ErrUnsupported
	}
	prepared, _ := f.prepare(t, f.intent(t, 1))
	if prepared.GetStatus().GetAdmissionRefusal().GetReason() != agentv1.ResourceAdmissionRefusalReason_RESOURCE_ADMISSION_REFUSAL_REASON_UNSUPPORTED_NATIVE || prepared.GetStatus().GetBefore() != nil || f.native.plans.Load() != 0 {
		t.Fatal("provider setup refusal fabricated observation")
	}
}

func TestSSHUnknownEffectIsNeverAnAdmissionRefusal(t *testing.T) {
	if _, _, classified := resourceAdmissionCause(sshprovider.ErrOutcomeUnknown); classified {
		t.Fatal("unknown native effect was represented as effect-free refusal")
	}
}
