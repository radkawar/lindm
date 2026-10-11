package device

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
	devicev1 "lindm/gen/lindm/device/v1"
	"lindm/internal/device/devicedb"
	"lindm/internal/identity"
	"lindm/internal/rpcreason"
	"lindm/internal/trust"
)

func (s *Service) recoveryApproval(ctx context.Context, action devicedb.DeviceAction) (*identity.Authorization, *identity.ApprovalConsumption, error) {
	if s.identity == nil || action.ApprovalID == nil {
		return nil, nil, approvalError(identity.ErrApprovalRequired)
	}
	authorization, err := s.identity.AuthorizeFresh(ctx, action.ActorID, identity.PermissionExecuteDestructive)
	if err != nil {
		return nil, nil, executionError(err)
	}
	if authorization.Version() != uint64(action.AuthorizationVersion) {
		return nil, nil, executionError(identity.ErrAuthorizationChanged)
	}
	request, err := actionRequest(action)
	if err != nil {
		return nil, nil, mapErr(err)
	}
	pair, err := s.identity.PrepareApprovalConsumption(ctx, action.ActorID, *action.ApprovalID, request)
	if err != nil {
		return nil, nil, approvalError(err)
	}
	return authorization, pair, nil
}
func (s *Service) recoveryApprovalScope(ctx context.Context, tx pgx.Tx, actor identity.Principal, permission identity.Permission, target uuid.UUID) error {
	if _, _, err := s.execution.CurrentInTransaction(ctx, tx); err != nil {
		return err
	}
	return s.approvalScope(ctx, tx, actor, permission, target)
}
func recoveryHumanApprovals(intent *agentv1.DeviceActionIntent, pair *identity.ApprovalConsumption) []*agentv1.DeviceActionHumanApproval {
	binding := &agentv1.DeviceActionApprovalBinding{DeviceId: intent.GetDeviceId(), EnrollmentGeneration: intent.GetEnrollmentGeneration(), SpecSha256: intent.GetSpecSha256(), ExpiresAt: intent.GetExpiresAt()}
	return []*agentv1.DeviceActionHumanApproval{
		{ActorId: pair.Requester().ActorID().String(), AuthorizationVersion: pair.Requester().Version(), Binding: binding},
		{ActorId: pair.Approver().ActorID().String(), AuthorizationVersion: pair.Approver().Version(), Binding: binding},
	}
}
func (s *Service) RegisterDeviceActionRecovery(ctx context.Context, req *connect.Request[devicev1.RegisterDeviceActionRecoveryRequest]) (*connect.Response[devicev1.RegisterDeviceActionRecoveryResponse], error) {
	ctx, cancel := bound(ctx)
	defer cancel()
	principal, ok := devicePrincipalFromContext(ctx)
	if !ok {
		return nil, rpcreason.Error(connect.CodeUnauthenticated, "unauthenticated")
	}
	if req == nil || req.Msg == nil || s.rules.Validate(req.Msg) != nil {
		return nil, invalid("invalid_recovery_handoff")
	}
	if s.identity == nil || s.signing == nil || s.execution == nil {
		return nil, rpcreason.Error(connect.CodeFailedPrecondition, "execution_signing_unconfigured")
	}
	id, _ := uuid.Parse(req.Msg.GetActionId())
	captured, err := devicedb.New(s.pool).GetDeviceAction(ctx, id)
	if err != nil {
		return nil, mapErr(err)
	}
	if captured.DeviceID != principal.DeviceID || captured.GenerationID != principal.GenerationID {
		return nil, rpcreason.Error(connect.CodePermissionDenied, "recovery_action_binding_rejected")
	}
	block, rest := pem.Decode(req.Msg.GetCertificatePem())
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, mapErr(errCertificateRejected)
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, mapErr(errCertificateRejected)
	}
	fingerprint := sha256.Sum256(certificate.Raw)
	if !bytes.Equal(fingerprint[:], principal.Fingerprint) {
		return nil, mapErr(errCertificateRejected)
	}
	handoff := new(agentv1.DeviceActionRecoveryHandoff)
	if err := s.authority.Verify(ctx, req.Msg.GetHandoffProof(), handoff, 1, principal.PublicKey); err != nil {
		return nil, rpcreason.Error(connect.CodePermissionDenied, "recovery_handoff_rejected")
	}
	intent, err := actionIntent(captured)
	if err != nil {
		return nil, mapErr(err)
	}
	digest := sha256.Sum256(captured.IntentEnvelope)
	if intent.GetSpec().GetSanitize().GetRecovery() == nil || !proto.Equal(handoff.GetIntent(), intent) || !bytes.Equal(handoff.GetIntentSha256(), digest[:]) || handoff.GetOriginalBootId() != handoff.GetChallenge().GetBootId() {
		return nil, rpcreason.Error(connect.CodePermissionDenied, "recovery_handoff_binding_rejected")
	}
	planDigest, err := trust.RecoveryPlanDigest(handoff.GetChallenge().GetNativePlan())
	if err != nil || !bytes.Equal(planDigest[:], handoff.GetNativePlanSha256()) {
		return nil, rpcreason.Error(connect.CodePermissionDenied, "recovery_plan_binding_rejected")
	}
	if err := s.admitMeasuredHandoff(ctx, handoff); err != nil {
		return nil, err
	}
	var authorization *identity.Authorization
	var pair *identity.ApprovalConsumption
	existing, lookupErr := devicedb.New(s.pool).GetDeviceActionRecovery(ctx, id)
	if errors.Is(lookupErr, pgx.ErrNoRows) {
		authorization, pair, err = s.recoveryApproval(ctx, captured)
		if err != nil {
			return nil, err
		}
	} else if lookupErr != nil {
		return nil, mapErr(lookupErr)
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, mapErr(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if pair != nil {
		if err := s.identity.LockAndConsumeApproval(ctx, tx, pair, s.recoveryApprovalScope); err != nil {
			return nil, approvalError(err)
		}
	}
	snapshot, verifier, err := s.execution.CurrentInTransaction(ctx, tx)
	if err != nil {
		return nil, executionError(err)
	}
	q := devicedb.New(tx)
	device, err := s.lockAuthority(ctx, q, principal)
	if err != nil {
		return nil, mapErr(err)
	}
	if uint64(device.generation.SessionEpoch) != req.Msg.GetSessionEpoch() {
		return nil, mapErr(errSessionFenced)
	}
	action, err := q.LockDeviceAction(ctx, id)
	if err != nil {
		return nil, mapErr(err)
	}
	now, err := dispatchClock(ctx, q)
	if err != nil {
		return nil, mapErr(err)
	}
	if !enrollmentIssuanceResumable(device.certificate, now) {
		return nil, mapErr(errCertificateRejected)
	}
	if _, err := s.authority.VerifyDeviceActionRecoveryHandoff(ctx, req.Msg.GetHandoffProof(), req.Msg.GetCertificatePem(), s.ca, intent, digest, now, trust.MaxDeviceClockSkew); err != nil {
		return nil, rpcreason.Error(connect.CodePermissionDenied, "recovery_handoff_rejected")
	}
	existing, lookupErr = q.GetDeviceActionRecovery(ctx, id)
	if lookupErr == nil {
		if !bytes.Equal(existing.HandoffProof, req.Msg.GetHandoffProof()) {
			return nil, rpcreason.Error(connect.CodeAlreadyExists, "recovery_handoff_conflict")
		}
		if err := tx.Commit(ctx); err != nil {
			return nil, mapErr(err)
		}
		return noStore(&devicev1.RegisterDeviceActionRecoveryResponse{CredentialEnvelope: existing.CredentialEnvelope, BootGrantEnvelope: existing.BootGrantEnvelope}), nil
	}
	if !errors.Is(lookupErr, pgx.ErrNoRows) {
		return nil, mapErr(lookupErr)
	}
	if err := s.requireReleaseCompatibility(ctx, q, principal.GenerationID, req.Msg.GetSessionEpoch()); err != nil {
		return nil, mapErr(err)
	}
	if action.ClosedAt.Valid || action.OutcomeUnknown || len(action.StartGrantEnvelope) > 0 || !now.Before(action.ExpiresAt.Time) || pair == nil {
		return nil, rpcreason.Error(connect.CodeFailedPrecondition, "recovery_action_unavailable")
	}
	if err := requireActionRestriction(ctx, q, principal.DeviceID, intent.GetSpec()); err != nil {
		return nil, mapErr(err)
	}
	if err := requireActionInventory(ctx, q, principal.GenerationID, intent.GetSpec(), now); err != nil {
		return nil, mapErr(err)
	}
	if _, err := verifier.VerifyDeviceActionIntent(ctx, snapshot.Root, snapshot.Delegation, action.IntentEnvelope, now); err != nil {
		return nil, executionError(err)
	}
	if snapshot.Delegation == nil {
		return nil, rpcreason.Error(connect.CodeFailedPrecondition, "execution_authority_unconfigured")
	}
	issued := handoff.GetChallenge().GetIssuedAt().AsTime()
	expires := handoff.GetChallenge().GetExpiresAt().AsTime()
	if issued.After(now.Add(trust.MaxDeviceClockSkew)) || !now.Add(-trust.MaxDeviceClockSkew).Before(expires) {
		return nil, rpcreason.Error(connect.CodeFailedPrecondition, "device_clock_skew")
	}
	for _, limit := range []time.Time{issued.Add(30 * time.Second), issued.Add(authorization.ExpiresAt().Sub(now)), handoff.GetExpiresAt().AsTime(), snapshot.Delegation.GetExpiresAt().AsTime()} {
		if limit.Before(expires) {
			expires = limit
		}
	}
	if !expires.After(issued) || !now.Before(handoff.GetExpiresAt().AsTime()) {
		return nil, rpcreason.Error(connect.CodePermissionDenied, "recovery_handoff_expired")
	}
	credential := &agentv1.DeviceActionRecoveryCredential{CredentialId: uuid.NewString(), Handoff: handoff, RootVersion: snapshot.Root.GetVersion(), DelegationVersion: snapshot.Delegation.GetVersion(), IssuedAt: timestamppb.New(now), ExpiresAt: handoff.GetExpiresAt()}
	credentialEnvelope, err := s.authority.Sign(ctx, credential, s.signing.StartKey)
	if err != nil {
		return nil, executionError(err)
	}
	if _, err := verifier.VerifyDeviceActionRecoveryCredential(ctx, snapshot.Root, snapshot.Delegation, credentialEnvelope, handoff, now); err != nil {
		return nil, executionError(err)
	}
	handoffDigest, err := trust.DeviceActionDigest(handoff)
	if err != nil {
		return nil, mapErr(err)
	}
	boot := &agentv1.DeviceActionRecoveryBootGrant{Grant: &agentv1.DeviceActionStartGrant{Challenge: handoff.GetChallenge(), ActorId: intent.GetActorId(), AuthorizationVersion: authorization.Version(), RootVersion: snapshot.Root.GetVersion(), DelegationVersion: snapshot.Delegation.GetVersion(), NotBefore: handoff.GetChallenge().GetIssuedAt(), ExpiresAt: timestamppb.New(expires), Approvals: recoveryHumanApprovals(intent, pair)}, HandoffSha256: handoffDigest[:]}
	bootEnvelope, err := s.authority.Sign(ctx, boot, s.signing.StartKey)
	if err != nil {
		return nil, executionError(err)
	}
	if _, err := verifier.VerifyDeviceActionRecoveryBoot(ctx, snapshot.Root, snapshot.Delegation, bootEnvelope, handoff, issued); err != nil {
		return nil, executionError(err)
	}
	handoffDocument, err := proto.Marshal(handoff)
	if err != nil {
		return nil, mapErr(err)
	}
	credentialDocument, err := proto.Marshal(credential)
	if err != nil {
		return nil, mapErr(err)
	}
	credentialDigest := sha256.Sum256(credentialEnvelope)
	credentialID, _ := uuid.Parse(credential.GetCredentialId())
	rootJSON, err := protojson.Marshal(snapshot.Root)
	if err != nil {
		return nil, mapErr(err)
	}
	if err := q.InsertDeviceActionRecovery(ctx, devicedb.InsertDeviceActionRecoveryParams{ActionID: id, CredentialID: credentialID, CertificateID: principal.CertificateID, SessionEpoch: int64(req.Msg.GetSessionEpoch()), PublicKey: handoff.GetRecoveryPublicKey(), HandoffProof: req.Msg.GetHandoffProof(), HandoffDocument: handoffDocument, CredentialEnvelope: credentialEnvelope, CredentialSha256: credentialDigest[:], CredentialDocument: credentialDocument, BootGrantEnvelope: bootEnvelope, RootJson: rootJSON, DelegationEnvelope: snapshot.DelegationEnvelope, ExpiresAt: timestamptz(handoff.GetExpiresAt().AsTime())}); err != nil {
		return nil, mapErr(err)
	}
	if err := q.MarkDeviceActionOutcomeUnknown(ctx, id); err != nil {
		return nil, mapErr(err)
	}
	if err := dispatchAudit(ctx, q, &action.ActorID, "device_action.recovery_handoff", id, "fresh_two_human_boot_authority"); err != nil {
		return nil, mapErr(err)
	}
	if err := s.identity.LockAndConsumeApproval(ctx, tx, pair, s.recoveryApprovalScope); err != nil {
		return nil, approvalError(err)
	}
	if err := s.identity.LockAuthorization(ctx, tx, authorization, identity.PermissionExecuteDestructive); err != nil {
		return nil, executionError(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, mapErr(err)
	}
	return noStore(&devicev1.RegisterDeviceActionRecoveryResponse{CredentialEnvelope: credentialEnvelope, BootGrantEnvelope: bootEnvelope}), nil
}
