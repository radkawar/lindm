//go:build linux

package executor

import (
	"bytes"
	"context"
	"errors"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/agent/actionprovider"
	"lindm/internal/agent/journal"
)

func (s *Service) StartDeviceAction(ctx context.Context, req *connect.Request[agentv1.StartDeviceActionRequest]) (*connect.Response[agentv1.StartDeviceActionResponse], error) {
	ctx, cancel := s.bounded(ctx)
	defer cancel()
	if req == nil || s.admit(req.Msg) != nil {
		return nil, mapError(errInvalid)
	}
	status, err := s.beginDeviceAction(ctx, req.Msg.GetActionId(), req.Msg.GetStartGrantEnvelope(), false)
	if err != nil {
		return nil, mapError(err)
	}
	return noStore(&agentv1.StartDeviceActionResponse{Status: status}), nil
}

func (s *Service) ConfirmDeviceActionEscrow(ctx context.Context, req *connect.Request[agentv1.ConfirmDeviceActionEscrowRequest]) (*connect.Response[agentv1.ConfirmDeviceActionEscrowResponse], error) {
	ctx, cancel := s.bounded(ctx)
	defer cancel()
	if req == nil || s.admit(req.Msg) != nil {
		return nil, mapError(errInvalid)
	}
	status, err := s.beginDeviceAction(ctx, req.Msg.GetActionId(), req.Msg.GetReceiptEnvelope(), true)
	if err != nil {
		return nil, mapError(err)
	}
	return noStore(&agentv1.ConfirmDeviceActionEscrowResponse{Status: status}), nil
}

type deviceActionAdmission struct {
	status *agentv1.DeviceActionStatus
	err    error
}

// beginDeviceAction never creates a queue. A busy provider rejects immediately.
// A single bounded native call starts now; the RPC waits until its durable effect
// gate, then disconnects from execution. Retrying only reads consumed evidence.
func (s *Service) beginDeviceAction(ctx context.Context, actionID string, envelope []byte, confirm bool) (*agentv1.DeviceActionStatus, error) {
	if err := s.lock(ctx); err != nil {
		return nil, err
	}
	if s.liveRoot != nil {
		defer s.mu.Unlock()
		if confirm || s.liveRoot.record.GetIntent().GetActionId() != actionID || !bytes.Equal(s.liveRoot.record.GetStartGrantEnvelope(), envelope) {
			return nil, errIdempotencyConflict
		}
		return s.liveRootStatus(actionID)
	}
	loaded, err := s.enrolled(ctx)
	if err != nil {
		s.mu.Unlock()
		return nil, err
	}
	record, revision, err := s.loadDeviceAction(ctx, loaded, actionID)
	if err != nil {
		s.mu.Unlock()
		return nil, err
	}
	accepted := record.GetStartGrantEnvelope()
	if confirm {
		accepted = record.GetEscrowReceiptEnvelope()
	}
	if len(accepted) != 0 {
		s.mu.Unlock()
		if !bytes.Equal(accepted, envelope) {
			return nil, errIdempotencyConflict
		}
		return deviceActionStatus(record), nil
	}
	if s.agentUpdateBusy() {
		s.mu.Unlock()
		return nil, errServiceRejected
	}
	if confirm {
		if record.GetState() != agentv1.DeviceActionState_DEVICE_ACTION_STATE_AWAITING_ESCROW {
			s.mu.Unlock()
			return nil, errServiceRejected
		}
		if err := s.authorizeDeviceActionReceipt(ctx, loaded, record, envelope); err != nil {
			s.mu.Unlock()
			return nil, err
		}
	} else {
		if err := s.expireDeviceAction(ctx, loaded, record, revision); err != nil {
			s.mu.Unlock()
			return nil, err
		}
		if record.GetState() != agentv1.DeviceActionState_DEVICE_ACTION_STATE_PREPARED {
			s.mu.Unlock()
			return nil, errServiceRejected
		}
		if _, err := s.authorizeDeviceActionStart(ctx, loaded, record, envelope); err != nil {
			s.mu.Unlock()
			return nil, err
		}
	}
	if s.actionProvider == nil || !s.actionMu.TryLock() {
		s.mu.Unlock()
		return nil, errServiceRejected
	}
	credential := s.takeActionCredential(actionID)
	s.operations.Add(1)
	work, cancel := context.WithTimeout(s.workerContext, 24*time.Hour)
	stopRequest := context.AfterFunc(ctx, cancel)
	s.mu.Unlock()
	admission := make(chan deviceActionAdmission, 1)
	go func() {
		defer s.operations.Done()
		defer s.actionMu.Unlock()
		defer releaseActionCredential(credential)
		defer cancel()
		defer stopRequest()
		consumed := false
		gate := func(gateCtx context.Context) error {
			if consumed {
				return errServiceRejected
			}
			status, err := s.consumeDeviceAction(gateCtx, record, envelope, confirm)
			if err != nil {
				return err
			}
			consumed = true
			// A canceled caller can no longer revoke a consumed native start.
			// Shutdown still cancels work and leaves durable unknown evidence.
			stopRequest()
			admission <- deviceActionAdmission{status: status}
			return nil
		}
		var result *agentv1.DeviceActionVerification
		var operationErr error
		if confirm {
			result, operationErr = s.actionProvider.ConfirmEscrow(work, record.GetNativePlan(), record.GetVerification(), credential, gate)
		} else {
			result, operationErr = s.actionProvider.Apply(work, record.GetNativePlan(), credential, gate)
		}
		s.finishDeviceAction(actionID, result, operationErr, confirm)
		if !consumed {
			if operationErr == nil {
				operationErr = errInternal
			}
			admission <- deviceActionAdmission{err: operationErr}
		}
	}()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case admitted := <-admission:
		return admitted.status, admitted.err
	}
}

func (s *Service) consumeDeviceAction(ctx context.Context, expected *agentv1.DeviceActionRecord, envelope []byte, confirm bool) (*agentv1.DeviceActionStatus, error) {
	if err := s.lock(ctx); err != nil {
		return nil, err
	}
	defer s.mu.Unlock()
	if s.agentUpdateBusy() {
		return nil, errServiceRejected
	}
	loaded, err := s.enrolled(ctx)
	if err != nil {
		return nil, err
	}
	record, revision, err := s.loadDeviceAction(ctx, loaded, expected.GetIntent().GetActionId())
	if err != nil {
		return nil, err
	}
	if !proto.Equal(record.GetNativePlan(), expected.GetNativePlan()) {
		return nil, errServiceRejected
	}
	next := proto.CloneOf(record)
	var grant *agentv1.DeviceActionStartGrant
	if confirm {
		if record.GetState() != agentv1.DeviceActionState_DEVICE_ACTION_STATE_AWAITING_ESCROW || !proto.Equal(record.GetVerification(), expected.GetVerification()) {
			return nil, errServiceRejected
		}
		if err := s.authorizeDeviceActionReceipt(ctx, loaded, record, envelope); err != nil {
			return nil, err
		}
		next.State = agentv1.DeviceActionState_DEVICE_ACTION_STATE_RETIRING_ESCROW
		next.EscrowReceiptEnvelope = bytes.Clone(envelope)
		next.EscrowConfirmedAt = protoTimestamp(s.now())
		next.ReceiptRoot = proto.CloneOf(loaded.execution.root)
		next.ReceiptDelegationEnvelope = bytes.Clone(loaded.execution.state.GetDelegationEnvelope())
	} else {
		if record.GetState() != agentv1.DeviceActionState_DEVICE_ACTION_STATE_PREPARED {
			return nil, errServiceRejected
		}
		grant, err = s.authorizeDeviceActionStart(ctx, loaded, record, envelope)
		if err != nil {
			return nil, err
		}
		next.State = agentv1.DeviceActionState_DEVICE_ACTION_STATE_RUNNING
		next.StartGrantEnvelope, next.StartGrantSha256 = bytes.Clone(envelope), digestBytes(envelope)
		next.StartedAt = protoTimestamp(s.now())
		next.GrantAcceptedAt = proto.CloneOf(next.StartedAt)
	}
	if actionprovider.LiveRootHeaderErase(next.GetIntent().GetSpec()) {
		pin := s.pinLiveRoot
		if pin == nil {
			pin = actionprovider.PinLiveRootMemory
		}
		if err := pin(); err != nil {
			return nil, err
		}
	}
	if err := s.updateDeviceAction(ctx, loaded, revision, next); err != nil {
		return nil, err
	}
	// An unusually slow FULL-synchronous commit never extends authority.
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !certUsable(loaded.cert, s.now()) {
		return nil, errIdentityExpired
	}
	if !confirm {
		if err := s.deviceActionDeadline(next); err != nil {
			return nil, err
		}
		if s.now().Before(grant.GetNotBefore().AsTime()) || !s.now().Before(grant.GetExpiresAt().AsTime()) {
			return nil, errServiceExpired
		}
	}
	if actionprovider.LiveRootHeaderErase(next.GetIntent().GetSpec()) {
		if err := s.closeLiveRootJournal(ctx, loaded, next); err != nil {
			return nil, err
		}
		// Closing/checkpointing the journal must not extend a fresh grant.
		if err := s.deviceActionDeadline(next); err != nil {
			return nil, err
		}
		if !certUsable(loaded.cert, s.now()) || !s.now().Before(grant.GetExpiresAt().AsTime()) {
			return nil, errServiceExpired
		}
		return s.liveRootStatus(next.GetIntent().GetActionId())
	}
	return deviceActionStatus(next), nil
}

func (s *Service) authorizeDeviceActionReceipt(ctx context.Context, loaded *bound, record *agentv1.DeviceActionRecord, envelope []byte) error {
	if err := s.serviceIdentitySession(loaded); err != nil {
		return err
	}
	if record.GetChallenge().GetExecutorIncarnation() != s.incarnation || loaded.execution.delegation == nil {
		return errServiceRejected
	}
	if _, err := loaded.execution.verifier.VerifyDeviceActionEscrowReceipt(ctx, loaded.execution.root, loaded.execution.delegation, envelope, record, s.now()); err != nil {
		return serviceAuthorityError(ctx, err)
	}
	return nil
}

// Completion is independent of current authorization, RPC cancellation and the
// grant deadline. Any ambiguity after consumption remains OUTCOME_UNKNOWN.
func (s *Service) finishDeviceAction(actionID string, result *agentv1.DeviceActionVerification, operationErr error, confirm bool) {
	ctx, cancel := context.WithTimeout(context.Background(), rpcTimeout)
	defer cancel()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.liveRoot != nil {
		if s.liveRoot.record.GetIntent().GetActionId() == actionID {
			s.finishLiveRoot(result, operationErr)
		}
		return
	}
	loaded, err := s.load(ctx)
	if err != nil {
		s.noteTrustDamage()
		return
	}
	record, revision, err := s.loadDeviceAction(ctx, loaded, actionID)
	if err != nil {
		s.noteTrustDamage()
		return
	}
	next := proto.CloneOf(record)
	state := record.GetState()
	if state == agentv1.DeviceActionState_DEVICE_ACTION_STATE_AWAITING_ESCROW && confirm {
		// A rejected preflight/receipt has not retired anything. Preserve both
		// slots and the exact staged ciphertext, allowing a new explicit attempt.
		return
	}
	if state == agentv1.DeviceActionState_DEVICE_ACTION_STATE_PREPARED && errors.Is(operationErr, actionprovider.ErrCredential) {
		// Missing local input is not authority consumption. A local operator may
		// supply it and explicitly retry within the unchanged live challenge.
		return
	}
	if state != agentv1.DeviceActionState_DEVICE_ACTION_STATE_PREPARED && state != agentv1.DeviceActionState_DEVICE_ACTION_STATE_RUNNING && state != agentv1.DeviceActionState_DEVICE_ACTION_STATE_RETIRING_ESCROW {
		return
	}
	if result != nil && s.admit(result) != nil {
		result, operationErr = nil, errInternal
	}
	if result != nil {
		if confirm && !proto.Equal(result.GetEscrow(), record.GetVerification().GetEscrow()) {
			result, operationErr = nil, errInternal
		} else {
			next.Verification = result
		}
	}
	next.CompletedAt = protoTimestamp(s.now())
	if state == agentv1.DeviceActionState_DEVICE_ACTION_STATE_PREPARED {
		next.State, next.Failure = agentv1.DeviceActionState_DEVICE_ACTION_STATE_FAILED, agentv1.DeviceActionFailure_DEVICE_ACTION_FAILURE_PRECONDITION
		if errors.Is(operationErr, errServiceExpired) || errors.Is(operationErr, context.Canceled) || errors.Is(operationErr, context.DeadlineExceeded) {
			next.State, next.Failure = agentv1.DeviceActionState_DEVICE_ACTION_STATE_EXPIRED, agentv1.DeviceActionFailure_DEVICE_ACTION_FAILURE_INTERRUPTED
		}
	} else if operationErr == nil && !confirm && record.GetIntent().GetSpec().GetEscrowRotate() != nil && result.GetEscrow() != nil {
		// Verification covers the newly staged key, not completion of rotation.
		// The encrypted stage is durable before any server can attest/store it.
		next.State, next.CompletedAt = agentv1.DeviceActionState_DEVICE_ACTION_STATE_AWAITING_ESCROW, nil
	} else if operationErr == nil && result.GetVerified() && (confirm || record.GetIntent().GetSpec().GetEscrowRotate() == nil) {
		next.State = agentv1.DeviceActionState_DEVICE_ACTION_STATE_SUCCEEDED
	} else {
		next.State, next.Failure = agentv1.DeviceActionState_DEVICE_ACTION_STATE_OUTCOME_UNKNOWN, agentv1.DeviceActionFailure_DEVICE_ACTION_FAILURE_OBSERVATION
		if errors.Is(operationErr, context.Canceled) || errors.Is(operationErr, context.DeadlineExceeded) {
			next.Failure = agentv1.DeviceActionFailure_DEVICE_ACTION_FAILURE_INTERRUPTED
		}
	}
	if err := s.updateDeviceAction(ctx, loaded, revision, next); err != nil {
		s.noteTrustDamage()
	}
}

// Startup never observes-and-retries imperative effects. Every consumed phase
// becomes permanently unknown; unconsumed challenges expire with incarnation.
func (s *Service) recoverDeviceActions(ctx context.Context) error {
	if s.store == nil || s.hold {
		return nil
	}
	loaded, err := s.load(ctx)
	if err != nil {
		return err
	}
	cursor := ""
	for {
		record, revision, err := s.store.NextUnfinishedDeviceAction(ctx, cursor)
		if errors.Is(err, journal.ErrDeviceActionNotFound) {
			return nil
		}
		if err != nil {
			return s.serviceStoreError(err)
		}
		if err := s.verifyDeviceActionRecord(ctx, loaded, record); err != nil {
			s.noteTrustDamage()
			return err
		}
		cursor = record.GetIntent().GetActionId()
		if record.GetStartedAt() == nil {
			record.State = agentv1.DeviceActionState_DEVICE_ACTION_STATE_EXPIRED
		} else {
			record.State = agentv1.DeviceActionState_DEVICE_ACTION_STATE_OUTCOME_UNKNOWN
		}
		record.Failure, record.CompletedAt = agentv1.DeviceActionFailure_DEVICE_ACTION_FAILURE_INTERRUPTED, protoTimestamp(s.now())
		if err := s.updateDeviceAction(ctx, loaded, revision, record); err != nil {
			return err
		}
	}
}
