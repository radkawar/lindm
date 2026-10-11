//go:build linux

package executor

import (
	"bytes"
	"context"
	"errors"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/agent/journal"
	"lindm/internal/trust"
)

func (s *Service) PrepareDeviceAction(ctx context.Context, req *connect.Request[agentv1.PrepareDeviceActionRequest]) (*connect.Response[agentv1.PrepareDeviceActionResponse], error) {
	ctx, cancel := s.bounded(ctx)
	defer cancel()
	if req == nil || s.admit(req.Msg) != nil {
		return nil, mapError(errInvalid)
	}
	msg, err := s.prepareDeviceAction(ctx, req.Msg)
	if err != nil {
		return nil, mapError(err)
	}
	return noStore(msg), nil
}

func (s *Service) prepareDeviceAction(ctx context.Context, req *agentv1.PrepareDeviceActionRequest) (*agentv1.PrepareDeviceActionResponse, error) {
	actionID, err := deviceAction.lookup(s, req.GetIntentEnvelope())
	if err != nil {
		return nil, err
	}
	if err := s.lock(ctx); err != nil {
		return nil, err
	}
	if s.liveRoot != nil {
		defer s.mu.Unlock()
		if s.liveRoot.record.GetIntent().GetActionId() != actionID || !bytes.Equal(s.liveRoot.record.GetIntentEnvelope(), req.GetIntentEnvelope()) {
			return nil, errIdempotencyConflict
		}
		response := deviceActionPreparation(s.liveRoot.record)
		response.Status = proto.CloneOf(s.liveRoot.status)
		return response, nil
	}
	loaded, err := s.enrolled(ctx)
	if err != nil {
		s.mu.Unlock()
		return nil, err
	}
	if old, _, err := s.loadDeviceAction(ctx, loaded, actionID); err == nil {
		s.mu.Unlock()
		if !bytes.Equal(old.GetIntentEnvelope(), req.GetIntentEnvelope()) {
			return nil, errIdempotencyConflict
		}
		return deviceActionPreparation(old), nil
	} else if !errors.Is(err, journal.ErrDeviceActionNotFound) {
		s.mu.Unlock()
		return nil, err
	}
	if s.agentUpdateBusy() {
		s.mu.Unlock()
		return nil, errResourceRejected
	}
	intent, err := deviceAction.current(ctx, s, loaded, req.GetIntentEnvelope())
	if err != nil {
		s.mu.Unlock()
		return nil, err
	}
	if intent.GetSpec().GetSanitize().GetRecovery() != nil {
		s.mu.Unlock()
		return nil, errResourceRejected
	}
	if s.actionProvider == nil || !s.actionMu.TryLock() {
		s.mu.Unlock()
		return nil, errResourceRejected
	}
	s.operations.Add(1)
	ctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(s.workerContext, cancel)
	s.mu.Unlock()
	defer s.operations.Done()
	defer s.actionMu.Unlock()
	defer cancel()
	defer stop()
	observation, err := s.actionProvider.Observe(ctx, intent.GetSpec())
	if err != nil {
		return nil, err
	}
	plan, err := s.actionProvider.Plan(ctx, intent.GetSpec(), observation)
	if err != nil {
		return nil, err
	}
	if plan == nil || !proto.Equal(plan.GetSpec(), intent.GetSpec()) || !plan.GetBefore().GetSupported() {
		return nil, errResourceRejected
	}
	plan.ActionId = intent.GetActionId()
	if rotate := intent.GetSpec().GetEscrowRotate(); rotate != nil {
		binding := plan.GetRecoveryBinding()
		if binding == nil || binding.GetLuksUuid() != rotate.GetTarget().GetLuksUuid() {
			return nil, errResourceRejected
		}
		// Native planning freezes the free slot. Only root-owned identity fields
		// are filled here; changing the slot would break the signed OAEP label.
		binding.DeviceId = intent.GetDeviceId()
		binding.EnrollmentGeneration = intent.GetEnrollmentGeneration()
		binding.ActionId = intent.GetActionId()
	}
	if rotate := intent.GetSpec().GetLocalAdminPasswordRotate(); rotate != nil {
		binding := plan.GetLocalAdminBinding()
		if binding == nil || binding.GetAccountName() != rotate.GetAccountName() || binding.GetAccountUid() == 0 {
			return nil, errResourceRejected
		}
		// The provider freezes the observed account and UID; only root-owned
		// identity fields of the OAEP label and custody binding are filled here.
		binding.DeviceId = intent.GetDeviceId()
		binding.EnrollmentGeneration = intent.GetEnrollmentGeneration()
		binding.ActionId = intent.GetActionId()
	} else if plan.GetLocalAdminBinding() != nil {
		return nil, errResourceRejected
	}
	if err := s.admit(plan); err != nil {
		return nil, errInternal
	}
	if err := s.lock(ctx); err != nil {
		return nil, err
	}
	defer s.mu.Unlock()
	if s.agentUpdateBusy() {
		return nil, errResourceRejected
	}
	loaded, err = s.enrolled(ctx)
	if err != nil {
		return nil, err
	}
	intent, err = deviceAction.current(ctx, s, loaded, req.GetIntentEnvelope())
	if err != nil {
		return nil, err
	}
	record := &agentv1.DeviceActionRecord{FormatVersion: 1, InstallationId: loaded.state.GetInstallationId(), IntentEnvelope: bytes.Clone(req.GetIntentEnvelope()), IntentSha256: digestBytes(req.GetIntentEnvelope()), Intent: intent, NativePlan: plan, AcceptedRoot: loaded.execution.root, AcceptedDelegationEnvelope: bytes.Clone(loaded.execution.state.GetDelegationEnvelope()), AcceptedAt: protoTimestamp(s.now()), State: agentv1.DeviceActionState_DEVICE_ACTION_STATE_PREPARED, Failure: agentv1.DeviceActionFailure_DEVICE_ACTION_FAILURE_NONE}
	if err := s.makeDeviceActionChallenge(ctx, loaded, record); err != nil {
		return nil, err
	}
	if err := s.verifyDeviceActionRecord(ctx, loaded, record); err != nil {
		return nil, errInternal
	}
	if _, err := s.store.AcceptDeviceAction(ctx, loaded.revision, loaded.execution.revision, record); err != nil {
		return nil, s.resourceStoreError(err)
	}
	return deviceActionPreparation(record), nil
}

// deviceAction is the immutable signed-action descriptor for device actions.
var deviceAction = &signedAction[*agentv1.DeviceActionIntent, *agentv1.DeviceActionChallenge, *agentv1.DeviceActionStartGrant, *agentv1.DeviceActionRecord]{
	payloadType: trust.DeviceActionIntentType, maxIntent: 32768,
	newIntent:    func() *agentv1.DeviceActionIntent { return new(agentv1.DeviceActionIntent) },
	targetIDs:    func(*agentv1.DeviceActionIntent) []string { return nil },
	verifyIntent: (*trust.ExecutionVerifier).VerifyDeviceActionIntent,
	verifyStart:  (*trust.ExecutionVerifier).VerifyDeviceActionStart,
	verifyRecord: (*Service).verifyDeviceActionRecord,
	load:         (*journal.Store).LoadDeviceAction,
	store:        (*journal.Store).UpdateDeviceAction,
}

func deviceActionTarget(loaded *bound, intent *agentv1.DeviceActionIntent) bool {
	return signedTarget(loaded, intent)
}

// makeDeviceActionChallenge binds the exact native plan into the challenge.
// Only power plans observe a boot; others are fenced by the session boot.
func (s *Service) makeDeviceActionChallenge(ctx context.Context, loaded *bound, record *agentv1.DeviceActionRecord) error {
	planBoot := record.GetNativePlan().GetBefore().GetBootId()
	if planBoot == "" {
		planBoot = loaded.state.GetSessionBootId()
	}
	window, err := s.openChallenge(loaded, record.GetAcceptedAt().AsTime(), planBoot, record.GetIntent().GetExpiresAt().AsTime())
	if err != nil {
		return err
	}
	planDigest, err := digestMessage(record.GetNativePlan())
	if err != nil {
		return err
	}
	i := record.GetIntent()
	challenge := &agentv1.DeviceActionChallenge{DeploymentId: i.GetDeploymentId(), DeviceId: i.GetDeviceId(), EnrollmentGeneration: i.GetEnrollmentGeneration(), ActionId: i.GetActionId(), ActionSequence: i.GetActionSequence(), RecoveryEpoch: i.GetRecoveryEpoch(), IntentSha256: bytes.Clone(record.GetIntentSha256()), SpecSha256: bytes.Clone(i.GetSpecSha256()), NativePlanSha256: planDigest, Nonce: window.nonce, BootId: window.boot, ExecutorIncarnation: s.incarnation, IssuedAt: protoTimestamp(window.issued), ExpiresAt: protoTimestamp(window.expires)}
	challenge.NativePlan = proto.CloneOf(record.GetNativePlan())
	proof, err := s.authority.Sign(ctx, challenge, loaded.identityKey)
	if err != nil {
		return err
	}
	record.Challenge, record.ChallengeProof, record.ChallengeBoottimeNs = challenge, proof, window.boottime
	record.ChallengeCertificatePem = bytes.Clone(loaded.state.GetCertificatePem())
	return nil
}

func (s *Service) GetDeviceAction(ctx context.Context, req *connect.Request[agentv1.GetDeviceActionRequest]) (*connect.Response[agentv1.GetDeviceActionResponse], error) {
	ctx, cancel := s.bounded(ctx)
	defer cancel()
	if req == nil || s.admit(req.Msg) != nil {
		return nil, mapError(errInvalid)
	}
	if err := s.lock(ctx); err != nil {
		return nil, mapError(err)
	}
	defer s.mu.Unlock()
	if s.liveRoot != nil {
		status, err := s.liveRootStatus(req.Msg.GetActionId())
		if err != nil {
			return nil, mapError(err)
		}
		return noStore(&agentv1.GetDeviceActionResponse{Status: status}), nil
	}
	loaded, err := s.enrolled(ctx)
	if err != nil {
		return nil, mapError(err)
	}
	record, revision, err := s.loadDeviceAction(ctx, loaded, req.Msg.GetActionId())
	if err != nil {
		return nil, mapError(err)
	}
	if err := s.expireDeviceAction(ctx, loaded, record, revision); err != nil {
		return nil, mapError(err)
	}
	return noStore(&agentv1.GetDeviceActionResponse{Status: deviceActionStatus(record)}), nil
}

func (s *Service) expireDeviceAction(ctx context.Context, loaded *bound, record *agentv1.DeviceActionRecord, revision int64) error {
	if record.GetState() != agentv1.DeviceActionState_DEVICE_ACTION_STATE_PREPARED {
		return nil
	}
	return deviceAction.expire(ctx, s, loaded, record, revision, func(next *agentv1.DeviceActionRecord) {
		next.State, next.Failure, next.CompletedAt = agentv1.DeviceActionState_DEVICE_ACTION_STATE_EXPIRED, agentv1.DeviceActionFailure_DEVICE_ACTION_FAILURE_EXPIRED, protoTimestamp(s.now())
	})
}

func deviceActionStatus(r *agentv1.DeviceActionRecord) *agentv1.DeviceActionStatus {
	return &agentv1.DeviceActionStatus{ActionId: r.GetIntent().GetActionId(), IntentSha256: bytes.Clone(r.GetIntentSha256()), State: r.GetState(), Failure: r.GetFailure(), AcceptedAt: proto.CloneOf(r.GetAcceptedAt()), StartedAt: proto.CloneOf(r.GetStartedAt()), CompletedAt: proto.CloneOf(r.GetCompletedAt()), Before: proto.CloneOf(r.GetNativePlan().GetBefore()), Verification: proto.CloneOf(r.GetVerification()), RefreshInventory: r.GetIntent().GetSpec().GetRefreshInventory() != nil}
}

func deviceActionPreparation(r *agentv1.DeviceActionRecord) *agentv1.PrepareDeviceActionResponse {
	return &agentv1.PrepareDeviceActionResponse{Status: deviceActionStatus(r), NativePlan: proto.CloneOf(r.GetNativePlan()), ChallengeProof: bytes.Clone(r.GetChallengeProof())}
}
