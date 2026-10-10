package journal

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/agent/journal/journaldb"
	"lindm/internal/protodata"
	"lindm/internal/resource"
)

func resourcePlanDrifts(record *agentv1.ResourceExecutionRecord) bool {
	return resource.PlanRequiresEffect(record.GetNativePlan())
}

func readOnlyResourceTerminal(record *agentv1.ResourceExecutionRecord) bool {
	return (record.GetState() == agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_SUCCEEDED || record.GetState() == agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_FAILED) &&
		record.GetNativePlan() != nil && record.GetVerification() != nil && len(record.GetStartGrantEnvelope()) == 0 && record.GetStartedAt() == nil && !resourcePlanDrifts(record)
}

func canonicalResourceID(value string) bool {
	id, err := uuid.Parse(value)
	return err == nil && id != uuid.Nil && id.String() == value
}

func resourceTimestampBefore(left, right *timestamppb.Timestamp) bool {
	return left != nil && right != nil && left.AsTime().Before(right.AsTime())
}

// This is structural/digest validation, not authorization. The executor must
// authenticate exact signed envelopes and historical device proof separately.
func (s *Store) validateResourceAction(record *agentv1.ResourceExecutionRecord) error {
	if record == nil || record.GetInstallationId() != s.installationID || proto.Size(record) > maximumResourceActionBytes {
		return ErrResourceActionRejected
	}
	if err := protodata.ValidateClosed(record.ProtoReflect()); err != nil {
		return ErrResourceActionRejected
	}
	if err := s.validator.Validate(record); err != nil {
		return ErrResourceActionRejected
	}
	intent := record.GetIntent()
	for _, id := range []string{record.GetInstallationId(), intent.GetActionId(), intent.GetDeploymentId(), intent.GetDeviceId(), intent.GetEnrollmentGeneration(), intent.GetDesiredRevision(), intent.GetActorId()} {
		if !canonicalResourceID(id) {
			return ErrResourceActionRejected
		}
	}
	if resource.ValidateDesired(intent.GetDesired()) != nil {
		return ErrResourceActionRejected
	}
	if record.GetNativePlan() != nil {
		if resource.ValidatePlan(record.GetNativePlan()) != nil || !resource.RefEqual(intent.GetDesired().GetRef(), record.GetNativePlan().GetRef()) || intent.GetOperation() != record.GetNativePlan().GetOperation() {
			return ErrResourceActionRejected
		}
		desiredDigest, err := resource.DesiredDigest(intent.GetDesired())
		if err != nil || !bytes.Equal(desiredDigest[:], record.GetNativePlan().GetDesiredSha256()) {
			return ErrResourceActionRejected
		}
	}
	intentDigest := sha256.Sum256(record.GetIntentEnvelope())
	if !bytes.Equal(intentDigest[:], record.GetIntentSha256()) || record.GetAcceptedRoot().GetDeploymentId() != intent.GetDeploymentId() || record.GetAcceptedRoot().GetVersion() != intent.GetRootVersion() ||
		resourceTimestampBefore(record.GetAcceptedAt(), intent.GetNotBefore()) || !resourceTimestampBefore(record.GetAcceptedAt(), intent.GetExpiresAt()) {
		return ErrResourceActionRejected
	}
	if refusal := record.GetAdmissionRefusal(); refusal != nil {
		// Closed-schema guards bind kind/key/operation and forbid fabricated
		// native or effect evidence. Refusal is retained, never read-only success.
		if !canonicalResourceID(refusal.GetBootId()) || !canonicalResourceID(refusal.GetExecutorIncarnation()) {
			return ErrResourceActionRejected
		}
		return nil
	}
	if record.GetNativePlan() == nil {
		// The protobuf guard restricts absent native evidence to pending or
		// explicitly terminated preparation, never an accepted effect.
		if intent.GetPreparation() == nil || !resourceTimestampBefore(record.GetAcceptedAt(), intent.GetPreparation().GetDeadline()) {
			return ErrResourceActionRejected
		}
		return nil
	}
	// Wall-clock observations are evidence, not logical counters. In particular,
	// clock rollback must not prevent recording an outcome or invent its time.
	// The executor validates grant/start authority at the actual admission time.
	if verification := record.GetVerification(); verification != nil && resource.ValidatePlanVerification(record.GetNativePlan(), verification) != nil {
		return ErrResourceActionRejected
	}
	drifting := resourcePlanDrifts(record)
	if drifting != (record.GetChallenge() != nil) {
		return ErrResourceActionRejected
	}
	if !drifting && (!readOnlyResourceTerminal(record) || resource.ValidateReadOnlyVerification(record.GetNativePlan(), record.GetVerification()) != nil) {
		return ErrResourceActionRejected
	}
	if challenge := record.GetChallenge(); challenge != nil {
		planDigest, err := resource.PlanDigest(record.GetNativePlan())
		if err != nil {
			return ErrResourceActionRejected
		}
		if challenge.GetDeploymentId() != intent.GetDeploymentId() || challenge.GetDeviceId() != intent.GetDeviceId() ||
			challenge.GetEnrollmentGeneration() != intent.GetEnrollmentGeneration() || challenge.GetActionId() != intent.GetActionId() ||
			challenge.GetDesiredRevision() != intent.GetDesiredRevision() || challenge.GetResourceSequence() != intent.GetResourceSequence() ||
			challenge.GetRecoveryEpoch() != intent.GetRecoveryEpoch() || !bytes.Equal(challenge.GetIntentSha256(), record.GetIntentSha256()) ||
			!bytes.Equal(challenge.GetNativePlanSha256(), planDigest[:]) || !canonicalResourceID(challenge.GetBootId()) || !canonicalResourceID(challenge.GetExecutorIncarnation()) ||
			!resource.RefEqual(challenge.GetRef(), intent.GetDesired().GetRef()) || challenge.GetOperation() != intent.GetOperation() ||
			challenge.GetBootId() != record.GetNativePlan().GetBefore().GetMetadata().GetBootId() || resourceTimestampBefore(challenge.GetIssuedAt(), record.GetAcceptedAt()) ||
			!resourceTimestampBefore(challenge.GetIssuedAt(), challenge.GetExpiresAt()) || resourceTimestampBefore(intent.GetExpiresAt(), challenge.GetExpiresAt()) {
			return ErrResourceActionRejected
		}
		if record.GetGrantAcceptedAt() != nil && !resourceTimestampBefore(record.GetGrantAcceptedAt(), challenge.GetExpiresAt()) {
			return ErrResourceActionRejected
		}
	}
	if len(record.GetStartGrantEnvelope()) != 0 {
		digest := sha256.Sum256(record.GetStartGrantEnvelope())
		if !bytes.Equal(digest[:], record.GetStartGrantSha256()) {
			return ErrResourceActionRejected
		}
	}
	started := record.GetStartedAt() != nil
	if started && len(record.GetStartGrantEnvelope()) == 0 {
		return ErrResourceActionRejected
	}
	switch record.GetState() {
	case agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_PREPARED, agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_QUEUED, agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_RUNNING:
		if record.GetVerification() != nil {
			return ErrResourceActionRejected
		}
	case agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_SUCCEEDED:
		if drifting && !started {
			return ErrResourceActionRejected
		}
	case agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_OUTCOME_UNKNOWN:
		if !started {
			return ErrResourceActionRejected
		}
	case agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_EXPIRED:
		if started || (record.GetFailure() != agentv1.ResourceExecutionFailure_RESOURCE_EXECUTION_FAILURE_EXPIRED && record.GetFailure() != agentv1.ResourceExecutionFailure_RESOURCE_EXECUTION_FAILURE_INTERRUPTED) {
			return ErrResourceActionRejected
		}
	case agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_SUPERSEDED:
		if started || record.GetFailure() != agentv1.ResourceExecutionFailure_RESOURCE_EXECUTION_FAILURE_SUPERSEDED {
			return ErrResourceActionRejected
		}
	}
	return nil
}

func (s *Store) encodeResourceAction(record *agentv1.ResourceExecutionRecord) ([]byte, error) {
	if err := s.validateResourceAction(record); err != nil {
		return nil, err
	}
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(record)
	if err != nil {
		return nil, ErrResourceActionRejected
	}
	return encoded, nil
}

func (s *Store) decodeResourceAction(row journaldb.ResourceAction) (*agentv1.ResourceExecutionRecord, error) {
	if row.Revision < 1 || len(row.Record) == 0 || len(row.Record) > maximumResourceActionBytes {
		return nil, ErrRecoveryHold
	}
	record := new(agentv1.ResourceExecutionRecord)
	if err := proto.Unmarshal(row.Record, record); err != nil {
		return nil, ErrRecoveryHold
	}
	if err := s.validateResourceAction(record); err != nil {
		return nil, ErrRecoveryHold
	}
	intent := record.GetIntent()
	if row.ActionID != intent.GetActionId() || row.DeploymentID != intent.GetDeploymentId() || row.DeviceID != intent.GetDeviceId() ||
		row.EnrollmentGeneration != intent.GetEnrollmentGeneration() || row.Kind != int64(intent.GetDesired().GetRef().GetKind()) || row.CanonicalKey != intent.GetDesired().GetRef().GetCanonicalKey() ||
		row.ResourceSequence != int64(intent.GetResourceSequence()) || row.State != int64(record.GetState()) || (row.ReadOnlyTerminal == 1) != readOnlyResourceTerminal(record) {
		return nil, ErrRecoveryHold
	}
	return record, nil
}

func (s *Store) checkedResourceAction(ctx context.Context, q *journaldb.Queries, row journaldb.ResourceAction) (*agentv1.ResourceExecutionRecord, int64, error) {
	record, err := s.decodeResourceAction(row)
	if err != nil {
		return nil, 0, err
	}
	floor, err := q.ReadResourceFloor(ctx, resourceFloorKey(record))
	if err != nil {
		return nil, 0, stateReadError(ctx)
	}
	current := floor.ActionID == row.ActionID
	if floor.ResourceSequence < row.ResourceSequence || (floor.ResourceSequence == row.ResourceSequence) != current ||
		(resourceActionPending(record.GetState()) && !current) {
		return nil, 0, ErrRecoveryHold
	}
	return record, row.Revision, nil
}

func rejectResourceActionTransition(current, next *agentv1.ResourceExecutionRecord) error {
	if current.GetFormatVersion() != next.GetFormatVersion() || current.GetInstallationId() != next.GetInstallationId() ||
		!bytes.Equal(current.GetIntentEnvelope(), next.GetIntentEnvelope()) || !bytes.Equal(current.GetIntentSha256(), next.GetIntentSha256()) ||
		!proto.Equal(current.GetIntent(), next.GetIntent()) ||
		!proto.Equal(current.GetAcceptedRoot(), next.GetAcceptedRoot()) || !bytes.Equal(current.GetAcceptedDelegationEnvelope(), next.GetAcceptedDelegationEnvelope()) ||
		!proto.Equal(current.GetAcceptedAt(), next.GetAcceptedAt()) {
		return ErrResourceActionRejected
	}
	// Refusals are terminal and cannot replace previously accepted native
	// evidence through a later lifecycle transition.
	preparing := current.GetState() == agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_PREPARING
	if !preparing && (!proto.Equal(current.GetNativePlan(), next.GetNativePlan()) || !proto.Equal(current.GetChallenge(), next.GetChallenge()) ||
		!bytes.Equal(current.GetChallengeProof(), next.GetChallengeProof()) || current.GetChallengeBoottimeNs() != next.GetChallengeBoottimeNs() ||
		!bytes.Equal(current.GetChallengeCertificatePem(), next.GetChallengeCertificatePem()) || !proto.Equal(current.GetPreparationOutcome(), next.GetPreparationOutcome()) || !proto.Equal(current.GetAdmissionRefusal(), next.GetAdmissionRefusal())) {
		return ErrResourceActionRejected
	}
	allowed := false
	switch current.GetState() {
	case agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_PREPARING:
		allowed = next.GetState() == agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_PREPARED ||
			readOnlyResourceTerminal(next) ||
			(resourceUnstartedTerminal(next.GetState()) && next.GetPreparationOutcome() != nil)
	case agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_PREPARED:
		allowed = next.GetState() == agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_QUEUED || resourceUnstartedTerminal(next.GetState())
	case agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_QUEUED:
		allowed = next.GetState() == agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_RUNNING || resourceUnstartedTerminal(next.GetState())
	case agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_RUNNING:
		allowed = next.GetState() == agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_SUCCEEDED || next.GetState() == agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_FAILED || next.GetState() == agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_OUTCOME_UNKNOWN
	}
	if !allowed {
		return ErrResourceActionRejected
	}
	queueing := current.GetState() == agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_PREPARED && next.GetState() == agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_QUEUED
	if !queueing && (!bytes.Equal(current.GetStartGrantEnvelope(), next.GetStartGrantEnvelope()) || !bytes.Equal(current.GetStartGrantSha256(), next.GetStartGrantSha256()) || !proto.Equal(current.GetGrantAcceptedAt(), next.GetGrantAcceptedAt())) {
		return ErrResourceActionRejected
	}
	starting := current.GetState() == agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_QUEUED && next.GetState() == agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_RUNNING
	if !starting && !proto.Equal(current.GetStartedAt(), next.GetStartedAt()) {
		return ErrResourceActionRejected
	}
	return nil
}

func resourceUnstartedTerminal(state agentv1.ResourceExecutionState) bool {
	return state == agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_EXPIRED || state == agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_FAILED || state == agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_SUPERSEDED
}

func resourceActionPending(state agentv1.ResourceExecutionState) bool {
	switch state {
	case agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_PREPARING,
		agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_PREPARED,
		agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_QUEUED,
		agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_RUNNING:
		return true
	default:
		return false
	}
}

func (s *Store) validateResourceActions(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	canceled, err := s.queries.CountResourcePreparationCancellations(ctx)
	if err != nil {
		return stateReadError(ctx)
	}
	invalidCanceled, err := s.queries.InvalidResourcePreparationCancellationCount(ctx)
	if err != nil {
		return stateReadError(ctx)
	}
	if canceled > maximumResourceActions || invalidCanceled != 0 {
		return ErrRecoveryHold
	}
	usage, err := s.queries.ReadResourceActionUsage(ctx)
	if err != nil {
		return stateReadError(ctx)
	}
	totals, err := s.queries.ResourceActionTotals(ctx)
	if err != nil {
		return stateReadError(ctx)
	}
	if usage.RecordCount != totals.RecordCount || usage.RecordBytes != totals.RecordBytes || usage.RecordCount < 0 || usage.RecordCount > maximumResourceActions || usage.RecordBytes < 0 || usage.RecordBytes > maximumResourceActionTotalBytes {
		return ErrRecoveryHold
	}
	invalid, err := s.queries.InvalidResourceFloorCount(ctx)
	if err != nil {
		return stateReadError(ctx)
	}
	if invalid != 0 {
		return ErrRecoveryHold
	}
	var count int64
	for cursor := ""; ; {
		row, err := s.queries.NextResourceAction(ctx, cursor)
		if errors.Is(err, sql.ErrNoRows) {
			break
		}
		if err != nil {
			return stateReadError(ctx)
		}
		if _, _, err := s.checkedResourceAction(ctx, s.queries, row); err != nil {
			return err
		}
		cursor = row.ActionID
		count++
	}
	if count != usage.RecordCount {
		return ErrRecoveryHold
	}
	return nil
}
