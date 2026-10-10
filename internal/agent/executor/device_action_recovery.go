//go:build linux

package executor

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"path/filepath"
	"time"

	"connectrpc.com/connect"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/agent/journal"
	"lindm/internal/agent/recovery"
	"lindm/internal/trust"
)

func (s *Service) PrepareDeviceActionRecovery(ctx context.Context, req *connect.Request[agentv1.PrepareDeviceActionRecoveryRequest]) (*connect.Response[agentv1.PrepareDeviceActionRecoveryResponse], error) {
	ctx, cancel := s.bounded(ctx)
	defer cancel()
	if req == nil || s.admit(req.Msg) != nil {
		return nil, mapError(errInvalid)
	}
	response, err := s.prepareDeviceActionRecovery(ctx, req.Msg.GetIntentEnvelope())
	if err != nil {
		return nil, mapError(err)
	}
	return noStore(response), nil
}

func (s *Service) prepareDeviceActionRecovery(ctx context.Context, envelope []byte) (*agentv1.PrepareDeviceActionRecoveryResponse, error) {
	actionID, err := s.lookupDeviceActionIntent(envelope)
	if err != nil {
		return nil, err
	}
	if err := s.lock(ctx); err != nil {
		return nil, err
	}
	loaded, err := s.enrolled(ctx)
	if err != nil {
		s.mu.Unlock()
		return nil, err
	}
	if existing, _, err := s.loadDeviceAction(ctx, loaded, actionID); err == nil {
		s.mu.Unlock()
		if !bytes.Equal(existing.GetIntentEnvelope(), envelope) || len(existing.GetHandoffProof()) == 0 {
			return nil, errIdempotencyConflict
		}
		return recoveryPreparation(existing), nil
	} else if !errors.Is(err, journal.ErrDeviceActionNotFound) {
		s.mu.Unlock()
		return nil, err
	}
	if s.agentUpdateBusy() {
		s.mu.Unlock()
		return nil, errServiceRejected
	}
	intent, err := s.currentDeviceActionIntent(ctx, loaded, envelope)
	if err != nil {
		s.mu.Unlock()
		return nil, err
	}
	if s.recoveryPending != nil {
		prior, revision, err := s.loadDeviceAction(ctx, loaded, s.recoveryPending.actionID)
		if err != nil {
			s.mu.Unlock()
			return nil, err
		}
		if err := s.expireDeviceAction(ctx, loaded, prior, revision); err != nil {
			s.mu.Unlock()
			return nil, err
		}
		if prior.GetState() != agentv1.DeviceActionState_DEVICE_ACTION_STATE_EXPIRED {
			s.mu.Unlock()
			return nil, errServiceRejected
		}
		pending := s.recoveryPending
		s.recoveryPending = nil
		if err := pending.key.Close(); err != nil {
			s.mu.Unlock()
			return nil, err
		}
	}
	planner, ok := s.actionProvider.(recoveryPlanner)
	if !ok || s.recoveryConfig == nil || intent.GetSpec().GetSanitize().GetRecovery() == nil || !s.actionMu.TryLock() {
		s.mu.Unlock()
		return nil, errServiceRejected
	}
	s.operations.Add(1)
	ctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(s.workerContext, cancel)
	s.mu.Unlock()
	defer s.operations.Done()
	defer s.actionMu.Unlock()
	defer cancel()
	defer stop()
	plan, err := planner.PrepareRecovery(ctx, intent.GetSpec())
	if err != nil {
		return nil, err
	}
	if plan == nil || !proto.Equal(plan.GetSpec(), intent.GetSpec()) || !plan.GetBefore().GetSupported() {
		return nil, errServiceRejected
	}
	plan.ActionId = intent.GetActionId()
	if s.admit(plan) != nil {
		return nil, errInternal
	}
	devices, err := planner.RecoveryTargetDevices(ctx, plan)
	if err != nil {
		return nil, err
	}
	boot, err := s.bootID()
	if err != nil {
		return nil, err
	}
	stage, err := s.recoveryStageRequest(intent, boot, devices)
	if err != nil {
		return nil, err
	}
	platform := s.recoveryPlatform()
	var pending recoveryTPMPending
	retained := false
	defer func() {
		if pending != nil && !retained {
			_ = pending.Close()
		}
	}()
	if s.recoveryConfig.Custody == agentv1.RecoveryCustody_RECOVERY_CUSTODY_TPM {
		pending, err = s.generateRecoveryTPM()
		if err != nil {
			return nil, err
		}
		if pending == nil {
			return nil, errInternal
		}
		stage.TrustedTPMCustody = pending.Check
	}
	if err := platform.Preflight(ctx, stage); err != nil {
		return nil, err
	}
	var public []byte
	if pending != nil {
		public = pending.PublicKey()
	} else {
		offTarget, err := recovery.OpenJournal(stage.StateDirectory)
		if err != nil {
			return nil, err
		}
		defer func() { _ = offTarget.Close() }()
		if found, err := offTarget.Load(new(agentv1.RecoveryJournal)); err != nil {
			return nil, err
		} else if found {
			return nil, errServiceRejected
		}
		if consumed, err := offTarget.Consumed(); err != nil {
			return nil, err
		} else if consumed {
			return nil, errServiceRejected
		}
		key, err := platform.ProvisionKey(filepath.Join(stage.StateDirectory, "action.key"))
		if err != nil {
			return nil, err
		}
		if len(key) != ed25519.PrivateKeySize {
			clear(key)
			return nil, errInternal
		}
		public = bytes.Clone(key[ed25519.SeedSize:])
		clear(key)
	}
	if err := s.lock(ctx); err != nil {
		return nil, err
	}
	defer s.mu.Unlock()
	if s.agentUpdateBusy() {
		return nil, errServiceRejected
	}
	loaded, err = s.enrolled(ctx)
	if err != nil {
		return nil, err
	}
	intent, err = s.currentDeviceActionIntent(ctx, loaded, envelope)
	if err != nil {
		return nil, err
	}
	record := &agentv1.DeviceActionRecord{FormatVersion: 1, InstallationId: loaded.state.GetInstallationId(), IntentEnvelope: bytes.Clone(envelope), IntentSha256: digestBytes(envelope), Intent: intent, NativePlan: plan, AcceptedRoot: proto.CloneOf(loaded.execution.root), AcceptedDelegationEnvelope: bytes.Clone(loaded.execution.state.GetDelegationEnvelope()), AcceptedAt: protoTimestamp(s.now()), State: agentv1.DeviceActionState_DEVICE_ACTION_STATE_PREPARED, Failure: agentv1.DeviceActionFailure_DEVICE_ACTION_FAILURE_NONE}
	if err := s.makeDeviceActionChallenge(ctx, loaded, record); err != nil {
		return nil, err
	}
	if record.GetChallenge().GetBootId() != boot {
		return nil, errServiceRejected
	}
	planDigest, err := trust.RecoveryPlanDigest(plan)
	if err != nil {
		return nil, err
	}
	recoverySpec := intent.GetSpec().GetSanitize().GetRecovery()
	handoff := &agentv1.DeviceActionRecoveryHandoff{Intent: proto.CloneOf(intent), NativePlanSha256: planDigest[:], RecoveryImageSha256: bytes.Clone(recoverySpec.GetImageSha256()), MediaSha256: bytes.Clone(recoverySpec.GetMediaSha256()), RecoveryPublicKey: public, OriginalBootId: boot, ExpiresAt: proto.CloneOf(intent.GetExpiresAt()), Custody: s.recoveryConfig.Custody, IntentSha256: bytes.Clone(record.GetIntentSha256()), Challenge: proto.CloneOf(record.GetChallenge())}
	if loaded.cert.NotAfter.Before(handoff.GetExpiresAt().AsTime()) {
		handoff.ExpiresAt = protoTimestamp(loaded.cert.NotAfter)
	}
	record.HandoffProof, err = s.authority.Sign(ctx, handoff, loaded.identityKey)
	if err != nil {
		return nil, err
	}
	if err := s.verifyDeviceActionRecord(ctx, loaded, record); err != nil {
		return nil, errInternal
	}
	if _, err := s.store.AcceptDeviceAction(ctx, loaded.revision, loaded.execution.revision, record); err != nil {
		return nil, s.serviceStoreError(err)
	}
	if pending != nil {
		s.recoveryPending = &recoveryPendingAction{actionID: actionID, key: pending}
		retained = true
	}
	return recoveryPreparation(record), nil
}

func recoveryPreparation(record *agentv1.DeviceActionRecord) *agentv1.PrepareDeviceActionRecoveryResponse {
	return &agentv1.PrepareDeviceActionRecoveryResponse{HandoffProof: bytes.Clone(record.GetHandoffProof()), CertificatePem: bytes.Clone(record.GetChallengeCertificatePem()), Status: deviceActionStatus(record)}
}

func (s *Service) CommitDeviceActionRecovery(ctx context.Context, req *connect.Request[agentv1.CommitDeviceActionRecoveryRequest]) (*connect.Response[agentv1.CommitDeviceActionRecoveryResponse], error) {
	ctx, cancel := s.bounded(ctx)
	defer cancel()
	if req == nil || s.admit(req.Msg) != nil {
		return nil, mapError(errInvalid)
	}
	status, err := s.commitDeviceActionRecovery(ctx, req.Msg)
	if err != nil {
		return nil, mapError(err)
	}
	return noStore(&agentv1.CommitDeviceActionRecoveryResponse{Status: status}), nil
}

func (s *Service) commitDeviceActionRecovery(ctx context.Context, request *agentv1.CommitDeviceActionRecoveryRequest) (*agentv1.DeviceActionStatus, error) {
	if err := s.lock(ctx); err != nil {
		return nil, err
	}
	defer s.mu.Unlock()
	loaded, err := s.enrolled(ctx)
	if err != nil {
		return nil, err
	}
	record, revision, err := s.loadDeviceAction(ctx, loaded, request.GetActionId())
	if err != nil {
		return nil, err
	}
	if len(record.GetRecoveryBootGrantEnvelope()) != 0 {
		if !bytes.Equal(record.GetRecoveryBootGrantEnvelope(), request.GetBootGrantEnvelope()) || !bytes.Equal(record.GetRecoveryCredentialEnvelope(), request.GetCredentialEnvelope()) {
			return nil, errIdempotencyConflict
		}
		return deviceActionStatus(record), nil
	}
	if s.agentUpdateBusy() {
		return nil, errServiceRejected
	}
	if err := s.expireDeviceAction(ctx, loaded, record, revision); err != nil {
		return nil, err
	}
	if record.GetState() != agentv1.DeviceActionState_DEVICE_ACTION_STATE_PREPARED || s.recoveryConfig == nil {
		return nil, errServiceRejected
	}
	handoff, err := protectedRecoveryHandoff(record)
	if err != nil {
		return nil, err
	}
	grant, err := s.authorizeRecoveryBoot(ctx, loaded, record, handoff, request.GetCredentialEnvelope(), request.GetBootGrantEnvelope())
	if err != nil {
		return nil, err
	}
	// Anchor the native deadline before persistence, never extending authority by
	// journal latency. CLOCK_BOOTTIME is also checked by the final native gate.
	nativeStart := time.Now()
	ns, err := s.boottime()
	if err != nil {
		return nil, err
	}
	if ns >= record.GetChallengeBoottimeNs() {
		return nil, errServiceExpired
	}
	remaining := min(grant.GetGrant().GetExpiresAt().AsTime().Sub(s.now()), time.Duration(record.GetChallengeBoottimeNs()-ns))
	if remaining <= 0 {
		return nil, errServiceExpired
	}
	nativeDeadline := nativeStart.Add(remaining)
	if handoff.GetCustody() != s.recoveryConfig.Custody {
		return nil, errServiceRejected
	}
	var pending recoveryTPMPending
	if handoff.GetCustody() == agentv1.RecoveryCustody_RECOVERY_CUSTODY_TPM {
		if s.recoveryPending == nil || s.recoveryPending.actionID != request.GetActionId() || !bytes.Equal(s.recoveryPending.key.PublicKey(), handoff.GetRecoveryPublicKey()) {
			return nil, errServiceRejected
		}
		pending = s.recoveryPending.key
	}
	if _, ok := s.actionProvider.(recoveryPlanner); !ok || !s.actionMu.TryLock() {
		return nil, errServiceRejected
	}
	next := proto.CloneOf(record)
	next.State = agentv1.DeviceActionState_DEVICE_ACTION_STATE_RUNNING
	next.RecoveryCredentialEnvelope = bytes.Clone(request.GetCredentialEnvelope())
	next.RecoveryBootGrantEnvelope = bytes.Clone(request.GetBootGrantEnvelope())
	next.RecoveryBootGrantSha256 = digestBytes(request.GetBootGrantEnvelope())
	next.StartedAt = protoTimestamp(s.now())
	next.GrantAcceptedAt = proto.CloneOf(next.StartedAt)
	if err := s.updateDeviceAction(ctx, loaded, revision, next); err != nil {
		s.actionMu.Unlock()
		return nil, err
	}
	if pending != nil {
		s.recoveryPending = nil
	}
	s.operations.Add(1)
	work, cancel := context.WithDeadline(s.workerContext, nativeDeadline)
	go func() {
		defer s.operations.Done()
		defer s.actionMu.Unlock()
		defer cancel()
		if pending != nil {
			defer func() { _ = pending.Close() }()
		}
		if err := s.runRecoveryBoot(work, next, handoff, pending); err != nil {
			// Recovery failures occur after the commit RPC returns. Preserve the
			// nonsecret native/gate error instead of reducing it to UNKNOWN alone.
			slog.Error("device action recovery handoff failed", "action_id", next.GetIntent().GetActionId(), "error", err)
			s.finishRecoveryBoot(next.GetIntent().GetActionId())
		}
	}()
	return deviceActionStatus(next), nil
}

func (s *Service) authorizeRecoveryBoot(ctx context.Context, loaded *bound, record *agentv1.DeviceActionRecord, handoff *agentv1.DeviceActionRecoveryHandoff, credential, grant []byte) (*agentv1.DeviceActionRecoveryBootGrant, error) {
	if _, err := s.currentDeviceActionIntent(ctx, loaded, record.GetIntentEnvelope()); err != nil {
		return nil, err
	}
	if err := s.deviceActionDeadline(record); err != nil {
		return nil, err
	}
	if _, err := loaded.execution.verifier.VerifyDeviceActionRecoveryCredential(ctx, loaded.execution.root, loaded.execution.delegation, credential, handoff, s.now()); err != nil {
		return nil, serviceAuthorityError(ctx, err)
	}
	verified, err := loaded.execution.verifier.VerifyDeviceActionRecoveryBoot(ctx, loaded.execution.root, loaded.execution.delegation, grant, handoff, s.now())
	if err != nil {
		return nil, serviceAuthorityError(ctx, err)
	}
	return verified, nil
}

func (s *Service) checkRecoveryBootGate(ctx context.Context, expected *agentv1.DeviceActionRecord, handoff *agentv1.DeviceActionRecoveryHandoff) error {
	if err := s.lock(ctx); err != nil {
		return err
	}
	defer s.mu.Unlock()
	if s.agentUpdateBusy() {
		return errServiceRejected
	}
	loaded, err := s.enrolled(ctx)
	if err != nil {
		return err
	}
	record, _, err := s.loadDeviceAction(ctx, loaded, expected.GetIntent().GetActionId())
	if err != nil {
		return err
	}
	if record.GetState() != agentv1.DeviceActionState_DEVICE_ACTION_STATE_RUNNING || !bytes.Equal(record.GetRecoveryCredentialEnvelope(), expected.GetRecoveryCredentialEnvelope()) || !bytes.Equal(record.GetRecoveryBootGrantEnvelope(), expected.GetRecoveryBootGrantEnvelope()) {
		return errServiceRejected
	}
	_, err = s.authorizeRecoveryBoot(ctx, loaded, record, handoff, record.GetRecoveryCredentialEnvelope(), record.GetRecoveryBootGrantEnvelope())
	return err
}

func (s *Service) runRecoveryBoot(ctx context.Context, record *agentv1.DeviceActionRecord, handoff *agentv1.DeviceActionRecoveryHandoff, pending recoveryTPMPending) error {
	if err := s.checkRecoveryBootGate(ctx, record, handoff); err != nil {
		return err
	}
	planner, ok := s.actionProvider.(recoveryPlanner)
	if !ok {
		return errors.New("action provider does not support recovery planning")
	}
	devices, err := planner.RecoveryTargetDevices(ctx, record.GetNativePlan())
	if err != nil {
		return err
	}
	stage, err := s.recoveryStageRequest(record.GetIntent(), handoff.GetOriginalBootId(), devices)
	if err != nil {
		return err
	}
	stage.CredentialPublicKey = bytes.Clone(handoff.GetRecoveryPublicKey())
	checkpoint := &agentv1.RecoveryJournal{FormatVersion: 1, CredentialEnvelope: bytes.Clone(record.GetRecoveryCredentialEnvelope()), IntentEnvelope: bytes.Clone(record.GetIntentEnvelope()), AcceptedRoot: proto.CloneOf(record.GetAcceptedRoot()), DelegationEnvelope: bytes.Clone(record.GetAcceptedDelegationEnvelope()), Handoff: proto.CloneOf(handoff), State: agentv1.DeviceActionState_DEVICE_ACTION_STATE_PREPARED, Failure: agentv1.DeviceActionFailure_DEVICE_ACTION_FAILURE_NONE, AcceptedAt: protoTimestamp(s.now()), CredentialRoot: proto.CloneOf(record.GetAcceptedRoot()), CredentialDelegationEnvelope: bytes.Clone(record.GetAcceptedDelegationEnvelope())}
	checkpoint.TrustAcceptedAt = proto.CloneOf(checkpoint.GetAcceptedAt())
	if s.admit(checkpoint) != nil {
		return errInternal
	}
	var offTarget *recovery.Journal
	if handoff.GetCustody() == agentv1.RecoveryCustody_RECOVERY_CUSTODY_TPM {
		if pending == nil {
			return errServiceRejected
		}
		if err := s.checkRecoveryBootGate(ctx, record, handoff); err != nil {
			return err
		}
		store, err := pending.Seal(ctx, handoff, s.recoveryConfig.ExpectedPCR11SHA256, checkpoint)
		if store != nil {
			defer func() { _ = store.Close() }()
		}
		if err != nil {
			return err
		}
		if store == nil {
			return errInternal
		}
		snapshot, err := store.Snapshot()
		if err != nil {
			return err
		}
		stage.CapsulePath, stage.CapsuleSHA256, err = s.recoveryPlatform().WriteCapsule(stage.StateDirectory, record.GetIntent().GetActionId(), snapshot)
		if err != nil {
			return err
		}
		stage.TrustedTPMCustody = store.Check
	} else {
		offTarget, err = recovery.OpenJournal(stage.StateDirectory)
		if err != nil {
			return err
		}
		defer func() {
			if offTarget != nil {
				_ = offTarget.Close()
			}
		}()
		if found, err := offTarget.Load(new(agentv1.RecoveryJournal)); err != nil {
			return err
		} else if found {
			return errServiceRejected
		}
		if consumed, err := offTarget.Consumed(); err != nil {
			return err
		} else if consumed {
			return errServiceRejected
		}
		if err := offTarget.Save(checkpoint); err != nil {
			return err
		}
	}
	platform := s.recoveryPlatform()
	if err := s.checkRecoveryBootGate(ctx, record, handoff); err != nil {
		return err
	}
	staged, err := platform.Stage(ctx, stage)
	if err != nil {
		return err
	}
	if err := staged.Arm(ctx, func(gateCtx context.Context) error { return s.checkRecoveryBootGate(gateCtx, record, handoff) }); err != nil {
		return err
	}
	if err := s.checkRecoveryBootGate(ctx, record, handoff); err != nil {
		return err
	}
	if offTarget != nil {
		err := offTarget.Close()
		offTarget = nil
		if err != nil {
			return err
		}
	}
	// Both custody paths are durable before a separately fresh-authorized reboot.
	// Native reboot acceptance is never evidence that the recovery wipe ran.
	return platform.Reboot(ctx)
}

func (s *Service) finishRecoveryBoot(actionID string) {
	ctx, cancel := context.WithTimeout(context.Background(), rpcTimeout)
	defer cancel()
	s.mu.Lock()
	defer s.mu.Unlock()
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
	if record.GetState() != agentv1.DeviceActionState_DEVICE_ACTION_STATE_RUNNING {
		return
	}
	record.State = agentv1.DeviceActionState_DEVICE_ACTION_STATE_OUTCOME_UNKNOWN
	record.Failure = agentv1.DeviceActionFailure_DEVICE_ACTION_FAILURE_INTERRUPTED
	record.CompletedAt = protoTimestamp(s.now())
	if err := s.updateDeviceAction(ctx, loaded, revision, record); err != nil {
		s.noteTrustDamage()
	}
}

// protectedRecoveryHandoff decodes already authenticated journal evidence; it
// never serves as initial authorization of a caller-supplied envelope.
func protectedRecoveryHandoff(record *agentv1.DeviceActionRecord) (*agentv1.DeviceActionRecoveryHandoff, error) {
	var envelope dsse.Envelope
	if json.Unmarshal(record.GetHandoffProof(), &envelope) != nil {
		return nil, errRecoveryHold
	}
	payload, err := base64.StdEncoding.DecodeString(envelope.Payload)
	if err != nil {
		return nil, errRecoveryHold
	}
	handoff := new(agentv1.DeviceActionRecoveryHandoff)
	if proto.Unmarshal(payload, handoff) != nil {
		return nil, errRecoveryHold
	}
	return handoff, nil
}

func (s *Service) verifyRecoveryHandoff(ctx context.Context, record *agentv1.DeviceActionRecord, public ed25519.PublicKey) (*agentv1.DeviceActionRecoveryHandoff, error) {
	handoff := new(agentv1.DeviceActionRecoveryHandoff)
	if err := s.authority.Verify(ctx, record.GetHandoffProof(), handoff, 1, public); err != nil {
		return nil, historicalServiceError(ctx)
	}
	planDigest, err := trust.RecoveryPlanDigest(record.GetNativePlan())
	if err != nil || !bytes.Equal(handoff.GetNativePlanSha256(), planDigest[:]) || !proto.Equal(handoff.GetIntent(), record.GetIntent()) || !proto.Equal(handoff.GetChallenge(), record.GetChallenge()) || !bytes.Equal(handoff.GetIntentSha256(), record.GetIntentSha256()) || handoff.GetOriginalBootId() != record.GetChallenge().GetBootId() {
		return nil, errRecoveryHold
	}
	return handoff, nil
}

func (s *Service) verifyRecoveryBootHistory(ctx context.Context, loaded *bound, record *agentv1.DeviceActionRecord, delegation *agentv1.ExecutionDelegation) error {
	if len(record.GetRecoveryBootGrantEnvelope()) == 0 {
		return nil
	}
	if record.GetStartedAt() == nil || !proto.Equal(record.GetStartedAt(), record.GetGrantAcceptedAt()) || !bytes.Equal(digestBytes(record.GetRecoveryBootGrantEnvelope()), record.GetRecoveryBootGrantSha256()) {
		return errRecoveryHold
	}
	handoff, err := protectedRecoveryHandoff(record)
	if err != nil {
		return err
	}
	at := record.GetStartedAt().AsTime()
	if _, err := loaded.execution.verifier.VerifyDeviceActionRecoveryCredential(ctx, record.GetAcceptedRoot(), delegation, record.GetRecoveryCredentialEnvelope(), handoff, at); err != nil {
		return historicalServiceError(ctx)
	}
	if _, err := loaded.execution.verifier.VerifyDeviceActionRecoveryBoot(ctx, record.GetAcceptedRoot(), delegation, record.GetRecoveryBootGrantEnvelope(), handoff, at); err != nil {
		return historicalServiceError(ctx)
	}
	return nil
}
