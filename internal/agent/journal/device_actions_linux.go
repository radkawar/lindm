package journal

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"math"

	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/agent/journal/journaldb"
	"lindm/internal/protodata"
)

const maximumDeviceActions = 2048
const maximumDeviceActionBytes = 128 << 10

var (
	ErrDeviceActionNotFound = errors.New("device action not found")
	ErrDeviceActionRejected = errors.New("device action transition rejected")
	ErrDeviceActionCapacity = errors.New("device action journal is at capacity")
)

// AcceptDeviceAction reserves the entire bounded lifecycle before any effect.
// Imperative records are never evicted: action IDs and exact grants remain spent.
func (s *Store) AcceptDeviceAction(ctx context.Context, authorityRevision, trustRevision int64, record *agentv1.DeviceActionRecord) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return 0, ErrClosed
	}
	encoded, err := s.encodeDeviceAction(record)
	if err != nil {
		return 0, err
	}
	if record.GetState() != agentv1.DeviceActionState_DEVICE_ACTION_STATE_PREPARED {
		return 0, ErrDeviceActionRejected
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, deviceActionWriteError(ctx)
	}
	defer func() { _ = tx.Rollback() }()
	q := s.queries.WithTx(tx)
	if err := s.deviceActionFences(ctx, q, authorityRevision, trustRevision, record, true); err != nil {
		return 0, err
	}
	if _, err := q.ReadDeviceAction(ctx, record.GetIntent().GetActionId()); err == nil {
		return 0, ErrDeviceActionRejected
	} else if !errors.Is(err, sql.ErrNoRows) {
		return 0, stateReadError(ctx)
	}
	count, err := q.DeviceActionCount(ctx)
	if err != nil {
		return 0, stateReadError(ctx)
	}
	usage, err := q.ReadDeviceActionUsage(ctx)
	if err != nil {
		return 0, stateReadError(ctx)
	}
	if usage != count || usage < 0 || usage > maximumDeviceActions {
		return 0, ErrRecoveryHold
	}
	if count >= maximumDeviceActions {
		return 0, ErrDeviceActionCapacity
	}
	i := record.GetIntent()
	floor, err := q.DeviceActionSequenceFloor(ctx, journaldb.DeviceActionSequenceFloorParams{DeploymentID: i.GetDeploymentId(), DeviceID: i.GetDeviceId(), EnrollmentGeneration: i.GetEnrollmentGeneration()})
	if err != nil {
		return 0, stateReadError(ctx)
	}
	if i.GetActionSequence() <= uint64(floor) {
		return 0, ErrDeviceActionRejected
	}
	if err := q.InsertDeviceAction(ctx, journaldb.InsertDeviceActionParams{ActionID: i.GetActionId(), DeploymentID: i.GetDeploymentId(), DeviceID: i.GetDeviceId(), EnrollmentGeneration: i.GetEnrollmentGeneration(), ActionSequence: int64(i.GetActionSequence()), State: int64(record.GetState()), Record: encoded}); err != nil {
		return 0, deviceActionWriteError(ctx)
	}
	changed, err := q.IncrementDeviceActionUsage(ctx, count)
	if err != nil {
		return 0, deviceActionWriteError(ctx)
	}
	if changed != 1 {
		return 0, ErrRecoveryHold
	}
	if err := tx.Commit(); err != nil {
		return 0, deviceActionWriteError(ctx)
	}
	return 1, nil
}

func (s *Store) LoadDeviceAction(ctx context.Context, actionID string) (*agentv1.DeviceActionRecord, int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return nil, 0, ErrClosed
	}
	row, err := s.queries.ReadDeviceAction(ctx, actionID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, 0, ErrDeviceActionNotFound
	}
	if err != nil {
		return nil, 0, stateReadError(ctx)
	}
	record, err := s.decodeDeviceAction(row)
	return record, row.Revision, err
}

// NextUnfinishedDeviceAction is a bounded recovery cursor, never a work queue.
func (s *Store) NextUnfinishedDeviceAction(ctx context.Context, afterActionID string) (*agentv1.DeviceActionRecord, int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return nil, 0, ErrClosed
	}
	row, err := s.queries.NextUnfinishedDeviceAction(ctx, afterActionID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, 0, ErrDeviceActionNotFound
	}
	if err != nil {
		return nil, 0, stateReadError(ctx)
	}
	record, err := s.decodeDeviceAction(row)
	return record, row.Revision, err
}

// UpdateDeviceAction atomically consumes start/retirement authority before effects.
// Completion may retain evidence after revocation; it never grants another effect.
func (s *Store) UpdateDeviceAction(ctx context.Context, revision, authorityRevision, trustRevision int64, next *agentv1.DeviceActionRecord) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return 0, ErrClosed
	}
	if revision < 1 || revision == math.MaxInt64 {
		return 0, ErrConflict
	}
	encoded, err := s.encodeDeviceAction(next)
	if err != nil {
		return 0, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, deviceActionWriteError(ctx)
	}
	defer func() { _ = tx.Rollback() }()
	q := s.queries.WithTx(tx)
	admitting := next.GetState() == agentv1.DeviceActionState_DEVICE_ACTION_STATE_RUNNING
	if err := s.deviceActionFences(ctx, q, authorityRevision, trustRevision, next, admitting); err != nil {
		return 0, err
	}
	row, err := q.ReadDeviceAction(ctx, next.GetIntent().GetActionId())
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrDeviceActionNotFound
	}
	if err != nil {
		return 0, stateReadError(ctx)
	}
	current, err := s.decodeDeviceAction(row)
	if err != nil {
		return 0, err
	}
	if row.Revision != revision {
		return 0, ErrConflict
	}
	if err := rejectDeviceActionTransition(current, next); err != nil {
		return 0, err
	}
	changed, err := q.ReplaceDeviceAction(ctx, journaldb.ReplaceDeviceActionParams{ActionID: row.ActionID, Revision: revision, State: int64(next.GetState()), Record: encoded})
	if err != nil {
		return 0, deviceActionWriteError(ctx)
	}
	if changed != 1 {
		return 0, ErrConflict
	}
	if err := tx.Commit(); err != nil {
		return 0, deviceActionWriteError(ctx)
	}
	return revision + 1, nil
}

func (s *Store) deviceActionFences(ctx context.Context, q *journaldb.Queries, authorityRevision, trustRevision int64, record *agentv1.DeviceActionRecord, admitting bool) error {
	row, err := q.ReadState(ctx)
	if err != nil {
		return stateReadError(ctx)
	}
	authority, err := s.decodeAuthority(row.Revision, row.State)
	if err != nil {
		return err
	}
	trust, currentTrustRevision, err := s.loadExecutionTrust(ctx, q)
	if err != nil {
		return err
	}
	if row.Revision != authorityRevision || currentTrustRevision != trustRevision {
		return ErrConflict
	}
	i := record.GetIntent()
	if authority.GetInstallationId() != record.GetInstallationId() || authority.GetDeviceId() != i.GetDeviceId() || authority.GetEnrollmentGeneration() != i.GetEnrollmentGeneration() {
		return ErrDeviceActionRejected
	}
	if admitting && (len(authority.GetCertificatePem()) == 0 || !executionTrustConfigured(trust) || !proto.Equal(trust.GetRoot(), record.GetAcceptedRoot()) || !bytes.Equal(trust.GetDelegationEnvelope(), record.GetAcceptedDelegationEnvelope()) || trust.GetRoot().GetDeploymentId() != i.GetDeploymentId() || trust.GetRoot().GetVersion() != i.GetRootVersion() || trust.GetDelegationVersion() != i.GetDelegationVersion() || trust.GetMinimumRecoveryEpoch() > i.GetRecoveryEpoch()) {
		return ErrDeviceActionRejected
	}
	if record.GetState() == agentv1.DeviceActionState_DEVICE_ACTION_STATE_RETIRING_ESCROW && (!executionTrustConfigured(trust) || !proto.Equal(trust.GetRoot(), record.GetReceiptRoot()) || !bytes.Equal(trust.GetDelegationEnvelope(), record.GetReceiptDelegationEnvelope()) || trust.GetMinimumRecoveryEpoch() > i.GetRecoveryEpoch()) {
		return ErrDeviceActionRejected
	}
	return nil
}

func (s *Store) validateDeviceAction(record *agentv1.DeviceActionRecord) error {
	if record == nil || record.GetInstallationId() != s.installationID || proto.Size(record) > maximumDeviceActionBytes || protodata.ValidateClosed(record.ProtoReflect()) != nil || s.validator.Validate(record) != nil {
		return ErrDeviceActionRejected
	}
	i, c := record.GetIntent(), record.GetChallenge()
	for _, id := range []string{record.GetInstallationId(), i.GetDeploymentId(), i.GetDeviceId(), i.GetEnrollmentGeneration(), i.GetActionId(), i.GetActorId(), c.GetBootId(), c.GetExecutorIncarnation()} {
		if !canonicalServiceID(id) {
			return ErrDeviceActionRejected
		}
	}
	spec, err := proto.MarshalOptions{Deterministic: true}.Marshal(i.GetSpec())
	if err != nil {
		return ErrDeviceActionRejected
	}
	plan, err := proto.MarshalOptions{Deterministic: true}.Marshal(record.GetNativePlan())
	if err != nil {
		return ErrDeviceActionRejected
	}
	intentHash, specHash, planHash := sha256.Sum256(record.GetIntentEnvelope()), sha256.Sum256(spec), sha256.Sum256(plan)
	if !bytes.Equal(intentHash[:], record.GetIntentSha256()) || !bytes.Equal(specHash[:], i.GetSpecSha256()) || !proto.Equal(i.GetSpec(), record.GetNativePlan().GetSpec()) || !record.GetNativePlan().GetBefore().GetSupported() || record.GetAcceptedRoot().GetDeploymentId() != i.GetDeploymentId() || record.GetAcceptedRoot().GetVersion() != i.GetRootVersion() || serviceTimestampBefore(record.GetAcceptedAt(), i.GetNotBefore()) || !serviceTimestampBefore(record.GetAcceptedAt(), i.GetExpiresAt()) {
		return ErrDeviceActionRejected
	}
	if c == nil || c.GetDeploymentId() != i.GetDeploymentId() || c.GetDeviceId() != i.GetDeviceId() || c.GetEnrollmentGeneration() != i.GetEnrollmentGeneration() || c.GetActionId() != i.GetActionId() || c.GetActionSequence() != i.GetActionSequence() || c.GetRecoveryEpoch() != i.GetRecoveryEpoch() || !bytes.Equal(c.GetIntentSha256(), intentHash[:]) || !bytes.Equal(c.GetSpecSha256(), specHash[:]) || !bytes.Equal(c.GetNativePlanSha256(), planHash[:]) || !proto.Equal(c.GetIssuedAt(), record.GetAcceptedAt()) || serviceTimestampBefore(i.GetExpiresAt(), c.GetExpiresAt()) || record.GetChallengeBoottimeNs() < uint64(c.GetExpiresAt().AsTime().Sub(c.GetIssuedAt().AsTime())) {
		return ErrDeviceActionRejected
	}
	if !proto.Equal(c.GetNativePlan(), record.GetNativePlan()) || record.GetNativePlan().GetActionId() != i.GetActionId() {
		return ErrDeviceActionRejected
	}
	if len(record.GetStartGrantEnvelope()) != 0 {
		hash := sha256.Sum256(record.GetStartGrantEnvelope())
		if !bytes.Equal(hash[:], record.GetStartGrantSha256()) || !proto.Equal(record.GetGrantAcceptedAt(), record.GetStartedAt()) || !serviceTimestampBefore(record.GetStartedAt(), c.GetExpiresAt()) {
			return ErrDeviceActionRejected
		}
	}
	bootGrant := record.GetRecoveryBootGrantEnvelope()
	recoveryAction := i.GetSpec().GetSanitize().GetRecovery() != nil
	if recoveryAction != (len(record.GetHandoffProof()) != 0) || recoveryAction && len(record.GetStartGrantEnvelope()) != 0 {
		return ErrDeviceActionRejected
	}
	if recoveryAction && (record.GetState() == agentv1.DeviceActionState_DEVICE_ACTION_STATE_SUCCEEDED || record.GetState() == agentv1.DeviceActionState_DEVICE_ACTION_STATE_AWAITING_ESCROW || record.GetState() == agentv1.DeviceActionState_DEVICE_ACTION_STATE_RETIRING_ESCROW) {
		// An original-device BOOT grant cannot establish an erase outcome.
		return ErrDeviceActionRejected
	}
	if len(bootGrant) != 0 {
		digest := sha256.Sum256(bootGrant)
		if !recoveryAction || !bytes.Equal(digest[:], record.GetRecoveryBootGrantSha256()) || len(record.GetRecoveryCredentialEnvelope()) == 0 || !proto.Equal(record.GetGrantAcceptedAt(), record.GetStartedAt()) || !serviceTimestampBefore(record.GetStartedAt(), c.GetExpiresAt()) {
			return ErrDeviceActionRejected
		}
	} else if len(record.GetRecoveryCredentialEnvelope()) != 0 || len(record.GetRecoveryBootGrantSha256()) != 0 {
		return ErrDeviceActionRejected
	}
	started := record.GetStartedAt() != nil
	if started != (len(record.GetStartGrantEnvelope()) != 0 || len(bootGrant) != 0) {
		return ErrDeviceActionRejected
	}
	if v := record.GetVerification(); v != nil && v.GetEscrow() != nil {
		e, rotate := v.GetEscrow(), i.GetSpec().GetEscrowRotate()
		if rotate == nil || record.GetNativePlan().GetRecoveryBinding() == nil || e.GetNewKeyslot() != record.GetNativePlan().GetRecoveryBinding().GetNewKeyslot() || e.GetLuksUuid() != rotate.GetTarget().GetLuksUuid() || e.GetEscrowKeyId() != rotate.GetEscrowKeyId() || rotate.RetireKeyslot != nil && e.GetNewKeyslot() == rotate.GetRetireKeyslot() {
			return ErrDeviceActionRejected
		}
	}
	if (len(record.GetEscrowReceiptEnvelope()) != 0) != (record.GetEscrowConfirmedAt() != nil) {
		return ErrDeviceActionRejected
	}
	if (len(record.GetEscrowReceiptEnvelope()) != 0) != (record.GetReceiptRoot() != nil && len(record.GetReceiptDelegationEnvelope()) != 0) {
		return ErrDeviceActionRejected
	}
	switch record.GetState() {
	case agentv1.DeviceActionState_DEVICE_ACTION_STATE_PREPARED:
		if started || record.GetVerification() != nil {
			return ErrDeviceActionRejected
		}
	case agentv1.DeviceActionState_DEVICE_ACTION_STATE_RUNNING:
		if !started || record.GetVerification() != nil {
			return ErrDeviceActionRejected
		}
	case agentv1.DeviceActionState_DEVICE_ACTION_STATE_AWAITING_ESCROW:
		if !started || record.GetVerification().GetEscrow() == nil || len(record.GetEscrowReceiptEnvelope()) != 0 {
			return ErrDeviceActionRejected
		}
	case agentv1.DeviceActionState_DEVICE_ACTION_STATE_RETIRING_ESCROW:
		if !started || record.GetVerification().GetEscrow() == nil || len(record.GetEscrowReceiptEnvelope()) == 0 {
			return ErrDeviceActionRejected
		}
	case agentv1.DeviceActionState_DEVICE_ACTION_STATE_SUCCEEDED:
		if !started || !record.GetVerification().GetVerified() || i.GetSpec().GetEscrowRotate() != nil && len(record.GetEscrowReceiptEnvelope()) == 0 {
			return ErrDeviceActionRejected
		}
	case agentv1.DeviceActionState_DEVICE_ACTION_STATE_OUTCOME_UNKNOWN:
		if !started {
			return ErrDeviceActionRejected
		}
	case agentv1.DeviceActionState_DEVICE_ACTION_STATE_EXPIRED, agentv1.DeviceActionState_DEVICE_ACTION_STATE_FAILED:
		if started {
			return ErrDeviceActionRejected
		}
	default:
		// QUEUED is intentionally not a valid persisted imperative lifecycle.
		return ErrDeviceActionRejected
	}
	return nil
}

func (s *Store) encodeDeviceAction(record *agentv1.DeviceActionRecord) ([]byte, error) {
	if err := s.validateDeviceAction(record); err != nil {
		return nil, err
	}
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(record)
	if err != nil {
		return nil, ErrDeviceActionRejected
	}
	return encoded, nil
}

func (s *Store) decodeDeviceAction(row journaldb.DeviceAction) (*agentv1.DeviceActionRecord, error) {
	if row.Revision < 1 || len(row.Record) == 0 || len(row.Record) > maximumDeviceActionBytes {
		return nil, ErrRecoveryHold
	}
	record := new(agentv1.DeviceActionRecord)
	if proto.Unmarshal(row.Record, record) != nil || s.validateDeviceAction(record) != nil {
		return nil, ErrRecoveryHold
	}
	i := record.GetIntent()
	if row.ActionID != i.GetActionId() || row.DeploymentID != i.GetDeploymentId() || row.DeviceID != i.GetDeviceId() || row.EnrollmentGeneration != i.GetEnrollmentGeneration() || row.ActionSequence != int64(i.GetActionSequence()) || row.State != int64(record.GetState()) {
		return nil, ErrRecoveryHold
	}
	return record, nil
}

func rejectDeviceActionTransition(current, next *agentv1.DeviceActionRecord) error {
	// Compare immutable signed admission evidence without trusting mutable state.
	base := proto.CloneOf(next)
	base.State, base.Failure = current.GetState(), current.GetFailure()
	base.StartGrantEnvelope, base.StartGrantSha256 = current.GetStartGrantEnvelope(), current.GetStartGrantSha256()
	base.GrantAcceptedAt, base.StartedAt, base.CompletedAt = current.GetGrantAcceptedAt(), current.GetStartedAt(), current.GetCompletedAt()
	base.Verification = current.GetVerification()
	base.EscrowReceiptEnvelope, base.EscrowConfirmedAt = current.GetEscrowReceiptEnvelope(), current.GetEscrowConfirmedAt()
	base.ReceiptRoot, base.ReceiptDelegationEnvelope = current.GetReceiptRoot(), current.GetReceiptDelegationEnvelope()
	base.RecoveryCredentialEnvelope = current.GetRecoveryCredentialEnvelope()
	base.RecoveryBootGrantEnvelope, base.RecoveryBootGrantSha256 = current.GetRecoveryBootGrantEnvelope(), current.GetRecoveryBootGrantSha256()
	if !proto.Equal(base, current) {
		return ErrDeviceActionRejected
	}
	starting, retiring := false, false
	switch current.GetState() {
	case agentv1.DeviceActionState_DEVICE_ACTION_STATE_PREPARED:
		starting = next.GetState() == agentv1.DeviceActionState_DEVICE_ACTION_STATE_RUNNING
		if !starting && next.GetState() != agentv1.DeviceActionState_DEVICE_ACTION_STATE_EXPIRED && next.GetState() != agentv1.DeviceActionState_DEVICE_ACTION_STATE_FAILED {
			return ErrDeviceActionRejected
		}
	case agentv1.DeviceActionState_DEVICE_ACTION_STATE_RUNNING:
		if next.GetState() != agentv1.DeviceActionState_DEVICE_ACTION_STATE_AWAITING_ESCROW && next.GetState() != agentv1.DeviceActionState_DEVICE_ACTION_STATE_SUCCEEDED && next.GetState() != agentv1.DeviceActionState_DEVICE_ACTION_STATE_OUTCOME_UNKNOWN {
			return ErrDeviceActionRejected
		}
	case agentv1.DeviceActionState_DEVICE_ACTION_STATE_AWAITING_ESCROW:
		retiring = next.GetState() == agentv1.DeviceActionState_DEVICE_ACTION_STATE_RETIRING_ESCROW
		if !retiring && next.GetState() != agentv1.DeviceActionState_DEVICE_ACTION_STATE_OUTCOME_UNKNOWN || !proto.Equal(current.GetVerification(), next.GetVerification()) {
			return ErrDeviceActionRejected
		}
	case agentv1.DeviceActionState_DEVICE_ACTION_STATE_RETIRING_ESCROW:
		if next.GetState() != agentv1.DeviceActionState_DEVICE_ACTION_STATE_SUCCEEDED && next.GetState() != agentv1.DeviceActionState_DEVICE_ACTION_STATE_OUTCOME_UNKNOWN {
			return ErrDeviceActionRejected
		}
		if !proto.Equal(current.GetVerification().GetEscrow(), next.GetVerification().GetEscrow()) {
			return ErrDeviceActionRejected
		}
	default:
		return ErrDeviceActionRejected
	}
	if !starting && (!bytes.Equal(current.GetStartGrantEnvelope(), next.GetStartGrantEnvelope()) || !bytes.Equal(current.GetStartGrantSha256(), next.GetStartGrantSha256()) || !proto.Equal(current.GetGrantAcceptedAt(), next.GetGrantAcceptedAt()) || !proto.Equal(current.GetStartedAt(), next.GetStartedAt())) {
		return ErrDeviceActionRejected
	}
	if !starting && (!bytes.Equal(current.GetRecoveryCredentialEnvelope(), next.GetRecoveryCredentialEnvelope()) || !bytes.Equal(current.GetRecoveryBootGrantEnvelope(), next.GetRecoveryBootGrantEnvelope()) || !bytes.Equal(current.GetRecoveryBootGrantSha256(), next.GetRecoveryBootGrantSha256())) {
		return ErrDeviceActionRejected
	}
	if !retiring && (!bytes.Equal(current.GetEscrowReceiptEnvelope(), next.GetEscrowReceiptEnvelope()) || !proto.Equal(current.GetEscrowConfirmedAt(), next.GetEscrowConfirmedAt()) || !proto.Equal(current.GetReceiptRoot(), next.GetReceiptRoot()) || !bytes.Equal(current.GetReceiptDelegationEnvelope(), next.GetReceiptDelegationEnvelope())) {
		return ErrDeviceActionRejected
	}
	return nil
}

func (s *Store) validateDeviceActions(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	count, err := s.queries.DeviceActionCount(ctx)
	if err != nil {
		return stateReadError(ctx)
	}
	if count < 0 || count > maximumDeviceActions {
		return ErrRecoveryHold
	}
	usage, err := s.queries.ReadDeviceActionUsage(ctx)
	if err != nil {
		return stateReadError(ctx)
	}
	if usage != count {
		return ErrRecoveryHold
	}
	cursor := ""
	for {
		row, err := s.queries.NextDeviceAction(ctx, cursor)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return stateReadError(ctx)
		}
		if _, err := s.decodeDeviceAction(row); err != nil {
			return err
		}
		cursor = row.ActionID
	}
}

func deviceActionWriteError(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return errors.New("commit device action failed")
}
