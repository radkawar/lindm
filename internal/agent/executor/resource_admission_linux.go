//go:build linux

package executor

import (
	"bytes"
	"context"
	"errors"
	"log/slog"

	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/agent/accountprovider"
	"lindm/internal/agent/admissiondetail"
	"lindm/internal/agent/definitionprovider"
	"lindm/internal/agent/encryptionprovider"
	"lindm/internal/agent/fileprovider"
	"lindm/internal/agent/firewallprovider"
	"lindm/internal/agent/journal"
	"lindm/internal/agent/nativeexec"
	"lindm/internal/agent/nativefile"
	"lindm/internal/agent/osupdateprovider"
	"lindm/internal/agent/packageprovider"
	"lindm/internal/agent/passwordprovider"
	"lindm/internal/agent/serviceprovider"
	"lindm/internal/agent/sshprovider"
	"lindm/internal/agent/sysctlprovider"
	"lindm/internal/custody"
)

// refuseResourceAdmission records only classified, effect-free native preflight
// rejection. It never invents a plan, inverse or observation when none exists.
// Cancellation, authority errors and unclassified failures remain RPC errors.
func (s *Service) refuseResourceAdmission(ctx context.Context, envelope []byte, operationErr error) (*agentv1.PrepareResourceExecutionResponse, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	reason, failure, classified := resourceAdmissionCause(operationErr)
	if !classified {
		return nil, operationErr
	}
	// The signed refusal carries only the typed reason; the local journal keeps
	// the provider's precondition detail for the device administrator.
	slog.Warn("resource admission refused", "reason", reason.String(), "error", operationErr)
	if err := s.lock(ctx); err != nil {
		return nil, err
	}
	defer s.mu.Unlock()
	loaded, err := s.enrolled(ctx)
	if err != nil {
		return nil, err
	}
	actionID, err := resourceAction.lookup(s, envelope)
	if err != nil {
		return nil, err
	}
	// A concurrent identical preflight may have committed first. This is a
	// historical retry, not permission to replace evidence or renew authority.
	if old, _, err := s.loadResourceAction(ctx, loaded, actionID); err == nil {
		if !bytes.Equal(old.GetIntentEnvelope(), envelope) {
			return nil, errIdempotencyConflict
		}
		return resourcePreparation(old), nil
	} else if !errors.Is(err, journal.ErrResourceActionNotFound) {
		return nil, err
	}
	intent, err := resourceAction.current(ctx, s, loaded, envelope)
	if err != nil {
		return nil, err
	}
	if errors.Is(operationErr, definitionprovider.ErrBaselineUnknown) && intent.GetOperation() == resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE {
		reason = agentv1.ResourceAdmissionRefusalReason_RESOURCE_ADMISSION_REFUSAL_REASON_PRECONDITION
		failure = agentv1.ResourceExecutionFailure_RESOURCE_EXECUTION_FAILURE_PRECONDITION
	}
	// Only a capability refusal or an earlier effect's unknown outcome
	// precedes preparation: nothing was staged.
	if (intent.GetPreparation() != nil && reason != agentv1.ResourceAdmissionRefusalReason_RESOURCE_ADMISSION_REFUSAL_REASON_CAPABILITY_NOT_ENABLED && reason != agentv1.ResourceAdmissionRefusalReason_RESOURCE_ADMISSION_REFUSAL_REASON_OWNERSHIP_UNKNOWN) || (reason == agentv1.ResourceAdmissionRefusalReason_RESOURCE_ADMISSION_REFUSAL_REASON_BASELINE_UNKNOWN && intent.GetOperation() != resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE) {
		return nil, operationErr
	}
	now := protoTimestamp(s.now())
	record := &agentv1.ResourceExecutionRecord{
		FormatVersion: 1, InstallationId: loaded.state.GetInstallationId(),
		IntentEnvelope: bytes.Clone(envelope), IntentSha256: digestBytes(envelope),
		Intent: intent, AcceptedRoot: loaded.execution.root,
		AcceptedDelegationEnvelope: bytes.Clone(loaded.execution.state.GetDelegationEnvelope()),
		AcceptedAt:                 now, CompletedAt: proto.CloneOf(now),
		State: agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_FAILED, Failure: failure,
		AdmissionRefusal: &agentv1.ResourceAdmissionRefusal{
			Ref: proto.CloneOf(intent.GetDesired().GetRef()), Operation: intent.GetOperation(), Reason: reason,
			BootId: loaded.state.GetSessionBootId(), ExecutorIncarnation: s.incarnation,
			NativeEvidenceUnavailable: true, Detail: admissiondetail.Of(operationErr),
		},
	}
	if refusal := new(capabilityRefusal); errors.As(operationErr, &refusal) {
		record.AdmissionRefusal.Capability = refusal.capability
	}
	if err := s.verifyResourceRecord(ctx, loaded, record); err != nil {
		return nil, errInternal
	}
	// Refusal advances the same kind/key sequence floor and retains the same
	// authority/trust CAS as successful preflight, without reserving ownership.
	if _, err := s.store.AcceptResourceAction(ctx, loaded.revision, loaded.execution.revision, record); err != nil {
		return nil, s.resourceStoreError(err)
	}
	return resourcePreparation(record), nil
}

// ownershipUnknownRefusal refuses an action because the resource's durable
// ownership ledger is UNKNOWN: an earlier effect on the same resource
// (effectActionID) ended with an unknown outcome. It deliberately does not
// unwrap to a provider's outcome-unknown sentinel, which stays unclassified
// when the ledger does not record that fence.
type ownershipUnknownRefusal struct {
	effectActionID string
	cause          error
}

func (r *ownershipUnknownRefusal) Error() string {
	message := "resource_ownership_unknown: effect action " + r.effectActionID
	if r.cause != nil {
		message += ": " + r.cause.Error()
	}
	return message
}

// ownershipUnknown returns the refusal for a resource whose durable ownership
// ledger is UNKNOWN, or nil. It reads the ledger only; the fence is never
// changed here, so the earlier effect is never replayed or resolved.
func (s *Service) ownershipUnknown(ctx context.Context, intent *agentv1.ResourceExecutionIntent, cause error) *ownershipUnknownRefusal {
	ledger, err := s.store.LoadResourceOwnership(ctx, intent.GetDeploymentId(), intent.GetDeviceId(), intent.GetEnrollmentGeneration(), intent.GetDesired().GetRef())
	if err != nil || ledger.GetState() != agentv1.ResourceOwnershipState_RESOURCE_OWNERSHIP_STATE_UNKNOWN {
		return nil
	}
	return &ownershipUnknownRefusal{effectActionID: ledger.GetEffectActionId(), cause: cause}
}

// ownershipFence turns a provider's outcome-unknown Plan refusal into a
// classified admission refusal only when the resource's ownership ledger is
// durably UNKNOWN. Plan observes but never changes native state, so this
// action had no effect. Any hazard that keeps an error unclassified
// (cancellation, custody, authority) also keeps this refusal unclassified.
func (s *Service) ownershipFence(ctx context.Context, intent *agentv1.ResourceExecutionIntent, err error) error {
	if !nativeOutcomeUnknown(err) || admissionHazard(err) {
		return err
	}
	if refusal := s.ownershipUnknown(ctx, intent, err); refusal != nil {
		return refusal
	}
	return err
}

// nativeOutcomeUnknown reports a provider's possibly performed native effect.
func nativeOutcomeUnknown(err error) bool {
	return errors.Is(err, serviceprovider.ErrOutcomeUnknown) || errors.Is(err, accountprovider.ErrOutcomeUnknown) ||
		errors.Is(err, definitionprovider.ErrOutcomeUnknown) || errors.Is(err, fileprovider.ErrOutcomeUnknown) ||
		errors.Is(err, firewallprovider.ErrOutcomeUnknown) || errors.Is(err, packageprovider.ErrOutcomeUnknown) ||
		errors.Is(err, passwordprovider.ErrOutcomeUnknown) || errors.Is(err, sysctlprovider.ErrOutcomeUnknown) ||
		errors.Is(err, osupdateprovider.ErrOutcomeUnknown) || errors.Is(err, sshprovider.ErrOutcomeUnknown)
}

// admissionHazard reports cancellation, damaged protected custody or lost
// authority, which a joined diagnostic must never hide.
func admissionHazard(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) ||
		errors.Is(err, errResourceRejected) || errors.Is(err, errRecoveryHold) || errors.Is(err, errInternal) ||
		errors.Is(err, errResourceExpired) || errors.Is(err, errIdentityExpired) || errors.Is(err, errSessionPending) ||
		errors.Is(err, errSessionRequired) || errors.Is(err, errRenewalPending) || errors.Is(err, errExecutionTrustRejected) ||
		errors.Is(err, errClosed) || errors.Is(err, errInvalid) ||
		errors.Is(err, journal.ErrRecoveryHold) || errors.Is(err, journal.ErrResourceOwnershipUnknown) ||
		errors.Is(err, journal.ErrResourceOwnershipCapacity) || errors.Is(err, journal.ErrClosed)
}

func resourceAdmissionCause(err error) (agentv1.ResourceAdmissionRefusalReason, agentv1.ResourceExecutionFailure, bool) {
	unspecified := agentv1.ResourceAdmissionRefusalReason_RESOURCE_ADMISSION_REFUSAL_REASON_UNSPECIFIED
	none := agentv1.ResourceExecutionFailure_RESOURCE_EXECUTION_FAILURE_UNSPECIFIED
	switch {
	// A possibly performed native effect is never an effect-free refusal.
	case admissionHazard(err), nativeOutcomeUnknown(err):
		return unspecified, none, false
	// The durable ledger, not the provider's error, proves the earlier
	// effect's unknown outcome; this action refused before any effect.
	case errors.As(err, new(*ownershipUnknownRefusal)):
		return agentv1.ResourceAdmissionRefusalReason_RESOURCE_ADMISSION_REFUSAL_REASON_OWNERSHIP_UNKNOWN, agentv1.ResourceExecutionFailure_RESOURCE_EXECUTION_FAILURE_PRECONDITION, true
	// The kind's provider is not effective: no native object was opened.
	case errors.As(err, new(*capabilityRefusal)):
		return agentv1.ResourceAdmissionRefusalReason_RESOURCE_ADMISSION_REFUSAL_REASON_CAPABILITY_NOT_ENABLED, agentv1.ResourceExecutionFailure_RESOURCE_EXECUTION_FAILURE_PRECONDITION, true
	// An unowned native object collides with CREATE_ONLY ownership. These
	// sentinels also match ErrConflict, so they are classified first.
	case errors.Is(err, accountprovider.ErrAdoptionRequired), errors.Is(err, definitionprovider.ErrAdoptionRequired),
		errors.Is(err, fileprovider.ErrAdoptionRequired), errors.Is(err, packageprovider.ErrAdoptionRequired),
		errors.Is(err, sshprovider.ErrAdoptionRequired), errors.Is(err, sysctlprovider.ErrAdoptionRequired):
		return agentv1.ResourceAdmissionRefusalReason_RESOURCE_ADMISSION_REFUSAL_REASON_ADOPTION_REQUIRED, agentv1.ResourceExecutionFailure_RESOURCE_EXECUTION_FAILURE_PRECONDITION, true
	// nativeexec refused the tool before running it: its ancestry is not
	// root-protected (inventory NativeToolCustody reports which path).
	case errors.Is(err, nativeexec.ErrUntrustedExecutable) && errors.Is(err, custody.ErrUnsafe):
		return agentv1.ResourceAdmissionRefusalReason_RESOURCE_ADMISSION_REFUSAL_REASON_UNSAFE_NATIVE_TOOL_PATH, agentv1.ResourceExecutionFailure_RESOURCE_EXECUTION_FAILURE_PRECONDITION, true
	case errors.Is(err, serviceprovider.ErrBaselineUnknown), errors.Is(err, definitionprovider.ErrBaselineUnknown):
		return agentv1.ResourceAdmissionRefusalReason_RESOURCE_ADMISSION_REFUSAL_REASON_BASELINE_UNKNOWN, agentv1.ResourceExecutionFailure_RESOURCE_EXECUTION_FAILURE_UNSUPPORTED, true
	// nativefile is the shared protected file boundary of the file provider:
	// metadata it cannot preserve (POSIX ACLs, capabilities) is refused before
	// any effect, exactly like the provider's own unsupported preflight.
	case errors.Is(err, serviceprovider.ErrUnsupported), errors.Is(err, accountprovider.ErrUnsupported),
		errors.Is(err, definitionprovider.ErrUnsupported), errors.Is(err, encryptionprovider.ErrUnsupported),
		errors.Is(err, fileprovider.ErrUnsupported), errors.Is(err, firewallprovider.ErrUnsupported),
		errors.Is(err, packageprovider.ErrUnsupported), errors.Is(err, passwordprovider.ErrUnsupported),
		errors.Is(err, sysctlprovider.ErrUnsupported), errors.Is(err, nativefile.ErrUnsupported),
		errors.Is(err, osupdateprovider.ErrUnsupported), errors.Is(err, sshprovider.ErrUnsupported):
		return agentv1.ResourceAdmissionRefusalReason_RESOURCE_ADMISSION_REFUSAL_REASON_UNSUPPORTED_NATIVE, agentv1.ResourceExecutionFailure_RESOURCE_EXECUTION_FAILURE_UNSUPPORTED, true
	case errors.Is(err, serviceprovider.ErrConflict), errors.Is(err, accountprovider.ErrConflict), errors.Is(err, accountprovider.ErrUnsafe),
		errors.Is(err, definitionprovider.ErrConflict), errors.Is(err, definitionprovider.ErrProtected),
		errors.Is(err, encryptionprovider.ErrConflict), errors.Is(err, fileprovider.ErrConflict), errors.Is(err, fileprovider.ErrUnsafePath),
		errors.Is(err, nativefile.ErrConflict), errors.Is(err, nativefile.ErrUnsafePath),
		errors.Is(err, firewallprovider.ErrConflict), errors.Is(err, packageprovider.ErrConflict),
		errors.Is(err, passwordprovider.ErrConflict), errors.Is(err, passwordprovider.ErrAccessGuard), errors.Is(err, passwordprovider.ErrMissingModule),
		errors.Is(err, sysctlprovider.ErrConflict), errors.Is(err, journal.ErrResourceOwnershipConflict), errors.Is(err, journal.ErrResourceOwnershipDrift),
		errors.Is(err, osupdateprovider.ErrConflict), errors.Is(err, osupdateprovider.ErrMissingPrerequisite), errors.Is(err, sshprovider.ErrConflict):
		return agentv1.ResourceAdmissionRefusalReason_RESOURCE_ADMISSION_REFUSAL_REASON_PRECONDITION, agentv1.ResourceExecutionFailure_RESOURCE_EXECUTION_FAILURE_PRECONDITION, true
	default:
		return unspecified, none, false
	}
}
