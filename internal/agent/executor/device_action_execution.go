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
		return nil, errResourceRejected
	}
	if confirm {
		if record.GetState() != agentv1.DeviceActionState_DEVICE_ACTION_STATE_AWAITING_ESCROW {
			s.mu.Unlock()
			return nil, errResourceRejected
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
			return nil, errResourceRejected
		}
		if _, err := deviceAction.authorizeStart(ctx, s, loaded, record, envelope); err != nil {
			s.mu.Unlock()
			return nil, err
		}
	}
	if s.actionProvider == nil || !s.actionMu.TryLock() {
		s.mu.Unlock()
		return nil, errResourceRejected
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
				if record.GetIntent().GetSpec().GetRestart() != nil || record.GetIntent().GetSpec().GetShutdown() != nil {
					return s.recheckPowerActionStart(gateCtx, record, envelope)
				}
				return errResourceRejected
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
		var sealed *agentv1.PrivateCustodyEnvelope
		var operationErr error
		localAdmin := record.GetIntent().GetSpec().GetLocalAdminPasswordRotate() != nil
		switch {
		case confirm && localAdmin:
			result, operationErr = s.actionProvider.SetLocalAdminPassword(work, record.GetNativePlan(), record.GetVerification(), record.GetLocalAdminPassword(), gate)
		case confirm:
			result, operationErr = s.actionProvider.ConfirmEscrow(work, record.GetNativePlan(), record.GetVerification(), credential, gate)
		case localAdmin:
			result, sealed, operationErr = s.actionProvider.StageLocalAdminPassword(work, record.GetNativePlan(), gate)
		case record.GetIntent().GetSpec().GetRefreshInventory() != nil:
			result, operationErr = s.beginInventoryRefresh(work, record, gate)
		case record.GetIntent().GetSpec().GetPatchNow() != nil:
			// The runner request may not outlive the signed action.
			bounded, stop := context.WithDeadline(work, record.GetIntent().GetExpiresAt().AsTime())
			result, operationErr = s.actionProvider.Apply(bounded, record.GetNativePlan(), credential, gate)
			stop()
		default:
			result, operationErr = s.actionProvider.Apply(work, record.GetNativePlan(), credential, gate)
		}
		s.finishDeviceAction(actionID, result, sealed, operationErr, confirm)
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
		return nil, errResourceRejected
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
		return nil, errResourceRejected
	}
	next := proto.CloneOf(record)
	var grant *agentv1.DeviceActionStartGrant
	if confirm {
		if record.GetState() != agentv1.DeviceActionState_DEVICE_ACTION_STATE_AWAITING_ESCROW || !proto.Equal(record.GetVerification(), expected.GetVerification()) {
			return nil, errResourceRejected
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
			return nil, errResourceRejected
		}
		grant, err = deviceAction.authorizeStart(ctx, s, loaded, record, envelope)
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
	if confirm {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if !certUsable(loaded.cert, s.now()) {
			return nil, errIdentityExpired
		}
	} else if err := s.consumedInWindow(ctx, loaded, next.GetChallenge(), next.GetChallengeBoottimeNs(), grant); err != nil {
		return nil, err
	}
	if actionprovider.LiveRootHeaderErase(next.GetIntent().GetSpec()) {
		if err := s.closeLiveRootJournal(ctx, loaded, next); err != nil {
			return nil, err
		}
		// Closing/checkpointing the journal must not extend a fresh grant.
		if err := s.consumedInWindow(ctx, loaded, next.GetChallenge(), next.GetChallengeBoottimeNs(), grant); err != nil {
			return nil, err
		}
		return s.liveRootStatus(next.GetIntent().GetActionId())
	}
	return deviceActionStatus(next), nil
}

func (s *Service) authorizeDeviceActionReceipt(ctx context.Context, loaded *bound, record *agentv1.DeviceActionRecord, envelope []byte) error {
	if err := s.actionIdentitySession(loaded); err != nil {
		return err
	}
	if record.GetChallenge().GetExecutorIncarnation() != s.incarnation || loaded.execution.delegation == nil {
		return errResourceRejected
	}
	if _, err := loaded.execution.verifier.VerifyDeviceActionEscrowReceipt(ctx, loaded.execution.root, loaded.execution.delegation, envelope, record, s.now()); err != nil {
		return signedAuthorityError(ctx)
	}
	return nil
}

// Completion is independent of current authorization, RPC cancellation and the
// grant deadline. Any ambiguity after consumption remains OUTCOME_UNKNOWN.
// sealed is the private-custody envelope of a staged local-admin password.
func (s *Service) finishDeviceAction(actionID string, result *agentv1.DeviceActionVerification, sealed *agentv1.PrivateCustodyEnvelope, operationErr error, confirm bool) {
	if errors.Is(operationErr, errInventoryPublicationPending) {
		return
	}
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
	spec := record.GetIntent().GetSpec()
	escrowed := spec.GetEscrowRotate() != nil || spec.GetLocalAdminPasswordRotate() != nil
	// Custody of a generated password ends with the action's last phase.
	next.LocalAdminPassword = nil
	if state == agentv1.DeviceActionState_DEVICE_ACTION_STATE_PREPARED {
		next.State, next.Failure = agentv1.DeviceActionState_DEVICE_ACTION_STATE_FAILED, agentv1.DeviceActionFailure_DEVICE_ACTION_FAILURE_PRECONDITION
		if errors.Is(operationErr, errResourceExpired) || errors.Is(operationErr, context.Canceled) || errors.Is(operationErr, context.DeadlineExceeded) {
			next.State, next.Failure = agentv1.DeviceActionState_DEVICE_ACTION_STATE_EXPIRED, agentv1.DeviceActionFailure_DEVICE_ACTION_FAILURE_INTERRUPTED
		}
	} else if record.GetIntent().GetSpec().GetRestart() != nil || record.GetIntent().GetSpec().GetShutdown() != nil {
		// Native acceptance cannot establish a changed boot or powered-off host.
		// Only startup recovery may confirm restart against the signed boot ID.
		next.State, next.Failure = agentv1.DeviceActionState_DEVICE_ACTION_STATE_OUTCOME_UNKNOWN, agentv1.DeviceActionFailure_DEVICE_ACTION_FAILURE_OBSERVATION
		if next.Verification != nil {
			next.Verification.Verified = false
		}
		if record.GetIntent().GetSpec().GetShutdown() != nil {
			if next.Verification == nil {
				next.Verification = &agentv1.DeviceActionVerification{After: proto.CloneOf(record.GetNativePlan().GetBefore())}
			}
			next.Verification.Evidence = "outcome_unknown_until_contact"
		}
	} else if operationErr == nil && !confirm && escrowed && result.GetEscrow() != nil && (spec.GetLocalAdminPasswordRotate() == nil || sealed != nil) {
		// Verification covers the newly staged secret, not completion of rotation.
		// The encrypted stage is durable before any server can attest/store it.
		next.State, next.CompletedAt = agentv1.DeviceActionState_DEVICE_ACTION_STATE_AWAITING_ESCROW, nil
		if spec.GetLocalAdminPasswordRotate() != nil {
			next.LocalAdminPassword = sealed
		}
	} else if operationErr == nil && result.GetVerified() && (confirm || !escrowed) && (spec.GetPatchNow() == nil || result.GetPatchRunStarted() && result.GetEvidence() == "native_patch_run_started" && !result.GetPowerRequestAccepted()) {
		// Patch now succeeds on a started native run; installation is patch status.
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

// Startup observes restart boot evidence but never retries imperative effects.
// Other consumed phases remain unknown; unconsumed challenges expire.
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
			return s.resourceStoreError(err)
		}
		if err := s.verifyDeviceActionRecord(ctx, loaded, record); err != nil {
			s.noteTrustDamage()
			return err
		}
		cursor = record.GetIntent().GetActionId()
		wasUnknown := record.GetState() == agentv1.DeviceActionState_DEVICE_ACTION_STATE_OUTCOME_UNKNOWN
		if record.GetState() == agentv1.DeviceActionState_DEVICE_ACTION_STATE_OUTCOME_UNKNOWN && record.GetIntent().GetSpec().GetRestart() == nil {
			continue
		}
		if record.GetStartedAt() == nil {
			record.State = agentv1.DeviceActionState_DEVICE_ACTION_STATE_EXPIRED
		} else {
			record.State = agentv1.DeviceActionState_DEVICE_ACTION_STATE_OUTCOME_UNKNOWN
		}
		record.Failure, record.CompletedAt = agentv1.DeviceActionFailure_DEVICE_ACTION_FAILURE_INTERRUPTED, protoTimestamp(s.now())
		// A restart ends local custody of a staged password; the server's escrow
		// record remains the candidate for an unknown native set.
		record.LocalAdminPassword = nil
		if record.GetStartedAt() != nil && record.GetIntent().GetSpec().GetShutdown() != nil && record.GetVerification() == nil {
			record.Verification = &agentv1.DeviceActionVerification{After: proto.CloneOf(record.GetNativePlan().GetBefore()), Evidence: "outcome_unknown_until_contact"}
		}
		if record.GetStartedAt() != nil && record.GetIntent().GetSpec().GetRestart() != nil {
			boot, err := s.bootID()
			if err != nil {
				return err
			}
			if _, err := canonicalUUID(boot); err != nil {
				return err
			}
			if boot != record.GetChallenge().GetBootId() {
				record.State, record.Failure = agentv1.DeviceActionState_DEVICE_ACTION_STATE_SUCCEEDED, agentv1.DeviceActionFailure_DEVICE_ACTION_FAILURE_NONE
				record.Verification = &agentv1.DeviceActionVerification{
					Verified:             true,
					BootId:               boot,
					After:                &agentv1.DeviceActionObservation{ObservedAt: protoTimestamp(s.now()), Supported: true, BootId: boot},
					Evidence:             "restart_confirmed_boot_id_changed",
					PowerRequestAccepted: record.GetVerification().GetPowerRequestAccepted(),
				}
			} else if wasUnknown {
				continue
			}
		}
		if err := s.updateDeviceAction(ctx, loaded, revision, record); err != nil {
			return err
		}
	}
}

// Wall delivery may block after grant consumption. Power providers recheck the
// same authority immediately afterward rather than extending the start deadline.
func (s *Service) recheckPowerActionStart(ctx context.Context, expected *agentv1.DeviceActionRecord, envelope []byte) error {
	if err := s.lock(ctx); err != nil {
		return err
	}
	defer s.mu.Unlock()
	if s.agentUpdateBusy() {
		return errResourceRejected
	}
	loaded, err := s.enrolled(ctx)
	if err != nil {
		return err
	}
	record, _, err := s.loadDeviceAction(ctx, loaded, expected.GetIntent().GetActionId())
	if err != nil {
		return err
	}
	if record.GetState() != agentv1.DeviceActionState_DEVICE_ACTION_STATE_RUNNING || !bytes.Equal(record.GetStartGrantEnvelope(), envelope) || !proto.Equal(record.GetNativePlan(), expected.GetNativePlan()) {
		return errResourceRejected
	}
	_, err = deviceAction.authorizeStart(ctx, s, loaded, record, envelope)
	return err
}
