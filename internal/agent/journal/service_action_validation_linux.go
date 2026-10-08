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
)

func servicePlanDrifts(record *agentv1.ServiceExecutionRecord) bool {
	return record.GetNativePlan().GetChangeRuntime() || record.GetNativePlan().GetChangeEnablement()
}

func canonicalServiceID(value string) bool {
	id, err := uuid.Parse(value)
	return err == nil && id != uuid.Nil && id.String() == value
}

func serviceTimestampBefore(left, right *timestamppb.Timestamp) bool {
	return left != nil && right != nil && left.AsTime().Before(right.AsTime())
}

// This is structural/digest validation, not authorization. The executor must
// authenticate exact signed envelopes and historical device proof separately.
func (s *Store) validateServiceAction(record *agentv1.ServiceExecutionRecord) error {
	if record == nil || record.GetInstallationId() != s.installationID || proto.Size(record) > maximumServiceActionBytes {
		return ErrServiceActionRejected
	}
	if err := protodata.ValidateClosed(record.ProtoReflect()); err != nil {
		return ErrServiceActionRejected
	}
	if err := s.validator.Validate(record); err != nil {
		return ErrServiceActionRejected
	}
	intent := record.GetIntent()
	for _, id := range []string{record.GetInstallationId(), intent.GetActionId(), intent.GetDeploymentId(), intent.GetDeviceId(), intent.GetEnrollmentGeneration(), intent.GetDesiredRevision(), intent.GetActorId()} {
		if !canonicalServiceID(id) {
			return ErrServiceActionRejected
		}
	}
	intentDigest := sha256.Sum256(record.GetIntentEnvelope())
	if !bytes.Equal(intentDigest[:], record.GetIntentSha256()) || record.GetAcceptedRoot().GetDeploymentId() != intent.GetDeploymentId() || record.GetAcceptedRoot().GetVersion() != intent.GetRootVersion() ||
		serviceTimestampBefore(record.GetAcceptedAt(), intent.GetNotBefore()) || !serviceTimestampBefore(record.GetAcceptedAt(), intent.GetExpiresAt()) {
		return ErrServiceActionRejected
	}
	// Wall-clock observations are evidence, not logical counters. In particular,
	// clock rollback must not prevent recording an outcome or invent its time.
	// The executor validates grant/start authority at the actual admission time.
	if verification := record.GetVerification(); verification != nil && verification.GetObservation().GetUnit() != intent.GetDesired().GetUnit() {
		return ErrServiceActionRejected
	}
	drifting := servicePlanDrifts(record)
	if drifting != (record.GetChallenge() != nil) {
		return ErrServiceActionRejected
	}
	if !drifting && (record.GetState() != agentv1.ServiceExecutionState_SERVICE_EXECUTION_STATE_SUCCEEDED || record.GetStartedAt() != nil || len(record.GetStartGrantEnvelope()) != 0) {
		return ErrServiceActionRejected
	}
	if challenge := record.GetChallenge(); challenge != nil {
		plan, err := proto.MarshalOptions{Deterministic: true}.Marshal(record.GetNativePlan())
		if err != nil {
			return ErrServiceActionRejected
		}
		planDigest := sha256.Sum256(plan)
		if challenge.GetDeploymentId() != intent.GetDeploymentId() || challenge.GetDeviceId() != intent.GetDeviceId() ||
			challenge.GetEnrollmentGeneration() != intent.GetEnrollmentGeneration() || challenge.GetActionId() != intent.GetActionId() ||
			challenge.GetDesiredRevision() != intent.GetDesiredRevision() || challenge.GetResourceSequence() != intent.GetResourceSequence() ||
			challenge.GetRecoveryEpoch() != intent.GetRecoveryEpoch() || !bytes.Equal(challenge.GetIntentSha256(), record.GetIntentSha256()) ||
			!bytes.Equal(challenge.GetNativePlanSha256(), planDigest[:]) || !canonicalServiceID(challenge.GetBootId()) || !canonicalServiceID(challenge.GetExecutorIncarnation()) ||
			challenge.GetBootId() != record.GetNativePlan().GetBefore().GetBootId() || serviceTimestampBefore(record.GetAcceptedAt(), challenge.GetIssuedAt()) ||
			!serviceTimestampBefore(record.GetAcceptedAt(), challenge.GetExpiresAt()) || serviceTimestampBefore(intent.GetExpiresAt(), challenge.GetExpiresAt()) {
			return ErrServiceActionRejected
		}
		if record.GetGrantAcceptedAt() != nil && !serviceTimestampBefore(record.GetGrantAcceptedAt(), challenge.GetExpiresAt()) {
			return ErrServiceActionRejected
		}
	}
	if len(record.GetStartGrantEnvelope()) != 0 {
		digest := sha256.Sum256(record.GetStartGrantEnvelope())
		if !bytes.Equal(digest[:], record.GetStartGrantSha256()) {
			return ErrServiceActionRejected
		}
	}
	started := record.GetStartedAt() != nil
	if started && len(record.GetStartGrantEnvelope()) == 0 {
		return ErrServiceActionRejected
	}
	switch record.GetState() {
	case agentv1.ServiceExecutionState_SERVICE_EXECUTION_STATE_PREPARED, agentv1.ServiceExecutionState_SERVICE_EXECUTION_STATE_QUEUED, agentv1.ServiceExecutionState_SERVICE_EXECUTION_STATE_RUNNING:
		if record.GetVerification() != nil {
			return ErrServiceActionRejected
		}
	case agentv1.ServiceExecutionState_SERVICE_EXECUTION_STATE_SUCCEEDED:
		if drifting && !started {
			return ErrServiceActionRejected
		}
	case agentv1.ServiceExecutionState_SERVICE_EXECUTION_STATE_OUTCOME_UNKNOWN:
		if !started {
			return ErrServiceActionRejected
		}
	case agentv1.ServiceExecutionState_SERVICE_EXECUTION_STATE_EXPIRED:
		if started || (record.GetFailure() != agentv1.ServiceExecutionFailure_SERVICE_EXECUTION_FAILURE_EXPIRED && record.GetFailure() != agentv1.ServiceExecutionFailure_SERVICE_EXECUTION_FAILURE_INTERRUPTED) {
			return ErrServiceActionRejected
		}
	case agentv1.ServiceExecutionState_SERVICE_EXECUTION_STATE_SUPERSEDED:
		if started || record.GetFailure() != agentv1.ServiceExecutionFailure_SERVICE_EXECUTION_FAILURE_SUPERSEDED {
			return ErrServiceActionRejected
		}
	}
	return nil
}

func (s *Store) encodeServiceAction(record *agentv1.ServiceExecutionRecord) ([]byte, error) {
	if err := s.validateServiceAction(record); err != nil {
		return nil, err
	}
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(record)
	if err != nil {
		return nil, ErrServiceActionRejected
	}
	return encoded, nil
}

func (s *Store) decodeServiceAction(row journaldb.ServiceAction) (*agentv1.ServiceExecutionRecord, error) {
	if row.Revision < 1 || len(row.Record) == 0 || len(row.Record) > maximumServiceActionBytes {
		return nil, ErrRecoveryHold
	}
	record := new(agentv1.ServiceExecutionRecord)
	if err := proto.Unmarshal(row.Record, record); err != nil {
		return nil, ErrRecoveryHold
	}
	if err := s.validateServiceAction(record); err != nil {
		return nil, ErrRecoveryHold
	}
	intent := record.GetIntent()
	if row.ActionID != intent.GetActionId() || row.DeploymentID != intent.GetDeploymentId() || row.DeviceID != intent.GetDeviceId() ||
		row.EnrollmentGeneration != intent.GetEnrollmentGeneration() || row.Unit != intent.GetDesired().GetUnit() ||
		row.ResourceSequence != int64(intent.GetResourceSequence()) || row.State != int64(record.GetState()) {
		return nil, ErrRecoveryHold
	}
	return record, nil
}

func (s *Store) checkedServiceAction(ctx context.Context, q *journaldb.Queries, row journaldb.ServiceAction) (*agentv1.ServiceExecutionRecord, int64, error) {
	record, err := s.decodeServiceAction(row)
	if err != nil {
		return nil, 0, err
	}
	floor, err := q.ReadServiceResourceFloor(ctx, serviceFloorKey(record))
	if err != nil {
		return nil, 0, stateReadError(ctx)
	}
	current := floor.ActionID == row.ActionID
	if floor.ResourceSequence < row.ResourceSequence || (floor.ResourceSequence == row.ResourceSequence) != current ||
		(row.State <= int64(agentv1.ServiceExecutionState_SERVICE_EXECUTION_STATE_RUNNING) && !current) {
		return nil, 0, ErrRecoveryHold
	}
	return record, row.Revision, nil
}

func rejectServiceActionTransition(current, next *agentv1.ServiceExecutionRecord) error {
	if current.GetFormatVersion() != next.GetFormatVersion() || current.GetInstallationId() != next.GetInstallationId() ||
		!bytes.Equal(current.GetIntentEnvelope(), next.GetIntentEnvelope()) || !bytes.Equal(current.GetIntentSha256(), next.GetIntentSha256()) ||
		!proto.Equal(current.GetIntent(), next.GetIntent()) || !proto.Equal(current.GetNativePlan(), next.GetNativePlan()) ||
		!proto.Equal(current.GetAcceptedRoot(), next.GetAcceptedRoot()) || !bytes.Equal(current.GetAcceptedDelegationEnvelope(), next.GetAcceptedDelegationEnvelope()) ||
		!proto.Equal(current.GetAcceptedAt(), next.GetAcceptedAt()) || !proto.Equal(current.GetChallenge(), next.GetChallenge()) ||
		!bytes.Equal(current.GetChallengeProof(), next.GetChallengeProof()) || current.GetChallengeBoottimeNs() != next.GetChallengeBoottimeNs() ||
		!bytes.Equal(current.GetChallengeCertificatePem(), next.GetChallengeCertificatePem()) {
		return ErrServiceActionRejected
	}
	allowed := false
	switch current.GetState() {
	case agentv1.ServiceExecutionState_SERVICE_EXECUTION_STATE_PREPARED:
		allowed = next.GetState() == agentv1.ServiceExecutionState_SERVICE_EXECUTION_STATE_QUEUED || serviceUnstartedTerminal(next.GetState())
	case agentv1.ServiceExecutionState_SERVICE_EXECUTION_STATE_QUEUED:
		allowed = next.GetState() == agentv1.ServiceExecutionState_SERVICE_EXECUTION_STATE_RUNNING || serviceUnstartedTerminal(next.GetState())
	case agentv1.ServiceExecutionState_SERVICE_EXECUTION_STATE_RUNNING:
		allowed = next.GetState() == agentv1.ServiceExecutionState_SERVICE_EXECUTION_STATE_SUCCEEDED || next.GetState() == agentv1.ServiceExecutionState_SERVICE_EXECUTION_STATE_FAILED || next.GetState() == agentv1.ServiceExecutionState_SERVICE_EXECUTION_STATE_OUTCOME_UNKNOWN
	}
	if !allowed {
		return ErrServiceActionRejected
	}
	queueing := current.GetState() == agentv1.ServiceExecutionState_SERVICE_EXECUTION_STATE_PREPARED && next.GetState() == agentv1.ServiceExecutionState_SERVICE_EXECUTION_STATE_QUEUED
	if !queueing && (!bytes.Equal(current.GetStartGrantEnvelope(), next.GetStartGrantEnvelope()) || !bytes.Equal(current.GetStartGrantSha256(), next.GetStartGrantSha256()) || !proto.Equal(current.GetGrantAcceptedAt(), next.GetGrantAcceptedAt())) {
		return ErrServiceActionRejected
	}
	starting := current.GetState() == agentv1.ServiceExecutionState_SERVICE_EXECUTION_STATE_QUEUED && next.GetState() == agentv1.ServiceExecutionState_SERVICE_EXECUTION_STATE_RUNNING
	if !starting && !proto.Equal(current.GetStartedAt(), next.GetStartedAt()) {
		return ErrServiceActionRejected
	}
	return nil
}

func serviceUnstartedTerminal(state agentv1.ServiceExecutionState) bool {
	return state == agentv1.ServiceExecutionState_SERVICE_EXECUTION_STATE_EXPIRED || state == agentv1.ServiceExecutionState_SERVICE_EXECUTION_STATE_FAILED || state == agentv1.ServiceExecutionState_SERVICE_EXECUTION_STATE_SUPERSEDED
}

func (s *Store) validateServiceActions(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	usage, err := s.queries.ReadServiceActionUsage(ctx)
	if err != nil {
		return stateReadError(ctx)
	}
	totals, err := s.queries.ServiceActionTotals(ctx)
	if err != nil {
		return stateReadError(ctx)
	}
	if usage.RecordCount != totals.RecordCount || usage.RecordBytes != totals.RecordBytes || usage.RecordCount < 0 || usage.RecordCount > maximumServiceActions || usage.RecordBytes < 0 || usage.RecordBytes > maximumServiceActionTotalBytes {
		return ErrRecoveryHold
	}
	invalid, err := s.queries.InvalidServiceResourceFloorCount(ctx)
	if err != nil {
		return stateReadError(ctx)
	}
	if invalid != 0 {
		return ErrRecoveryHold
	}
	var count int64
	for cursor := ""; ; {
		row, err := s.queries.NextServiceAction(ctx, cursor)
		if errors.Is(err, sql.ErrNoRows) {
			break
		}
		if err != nil {
			return stateReadError(ctx)
		}
		if _, _, err := s.checkedServiceAction(ctx, s.queries, row); err != nil {
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
