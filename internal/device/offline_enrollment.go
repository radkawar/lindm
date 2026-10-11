package device

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
	enrollmentv1 "lindm/gen/lindm/enrollment/v1"
	"lindm/internal/device/devicedb"
	"lindm/internal/executionauthority"
	"lindm/internal/identity"
	"lindm/internal/rpcreason"
	"lindm/internal/trust"
)

func (s *Service) CreateOfflineEnrollmentAuthorization(ctx context.Context, req *connect.Request[adminv1.CreateOfflineEnrollmentAuthorizationRequest]) (*connect.Response[adminv1.CreateOfflineEnrollmentAuthorizationResponse], error) {
	ctx, cancel := bound(ctx)
	defer cancel()
	actor, err := s.requireUnrestricted(ctx, identity.PermissionManageEnrollment)
	if err != nil {
		return nil, err
	}
	if req == nil || req.Msg == nil || s.rules.Validate(req.Msg) != nil {
		return nil, invalid("invalid_offline_authorization")
	}
	if s.identity == nil || s.execution == nil || s.signing == nil {
		return nil, rpcreason.Error(connect.CodeFailedPrecondition, "execution_signing_unconfigured")
	}
	if err := s.acquire(ctx); err != nil {
		return nil, mapErr(err)
	}
	defer s.release()
	authorization, err := s.identity.AuthorizeFresh(ctx, actor.ID, identity.PermissionManageEnrollment)
	if err != nil {
		return nil, executionError(err)
	}
	if err := requireUnrestrictedPrincipal(authorization.Principal(), identity.PermissionManageEnrollment); err != nil {
		return nil, err
	}
	encoded, err := (proto.MarshalOptions{Deterministic: true}).Marshal(req.Msg)
	if err != nil {
		return nil, mapErr(err)
	}
	digest := sha256.Sum256(encoded)
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, mapErr(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := s.identity.LockAuthorization(ctx, tx, authorization, identity.PermissionManageEnrollment); err != nil {
		return nil, executionError(err)
	}
	q := devicedb.New(tx)
	requestID, _ := uuid.Parse(req.Msg.GetRequestId())
	_, owned, err := s.beginAdminRequest(ctx, q, actor.ID, "CreateOfflineEnrollmentAuthorization", requestID, digest[:])
	if err != nil {
		return nil, mapErr(err)
	}
	file := new(agentv1.OfflineEnrollmentAuthorizationFile)
	if !owned {
		previous, err := q.GetOfflineEnrollmentAuthorization(ctx, requestID)
		if err != nil {
			return nil, mapErr(err)
		}
		if previous.ActorID != actor.ID || !bytes.Equal(previous.RequestSha256, digest[:]) {
			return nil, mapErr(errIdempotencyConflict)
		}
		if err := proto.Unmarshal(previous.AuthorizationEnvelope, file); err != nil {
			return nil, mapErr(errInternalState)
		}
	} else {
		token, err := q.GetProvisioningTokenByHash(ctx, hashGrant(req.Msg.GetProvisioningToken()))
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, mapErr(errGrantInvalid)
		}
		if err != nil {
			return nil, mapErr(err)
		}
		assignment, err := provisioningAssignment(token)
		if err != nil {
			return nil, mapErr(err)
		}
		if err := provisioningAssignmentAuthority(authorization.Principal(), assignment); err != nil {
			return nil, err
		}
		now, err := dispatchClock(ctx, q)
		if err != nil {
			return nil, mapErr(err)
		}
		if err := provisioningTokenUsable(token, now); err != nil {
			return nil, mapErr(err)
		}
		if token.UsedCount >= token.MaxUses {
			return nil, rpcreason.Error(connect.CodeResourceExhausted, "provisioning_token_exhausted")
		}
		snapshot, verifier, err := s.execution.CurrentInTransaction(ctx, tx)
		if err != nil {
			return nil, executionError(err)
		}
		if snapshot.Delegation == nil {
			return nil, rpcreason.Error(connect.CodeFailedPrecondition, "execution_authority_unconfigured")
		}
		_, update, err := s.execution.ForDevice(ctx, tx, req.Msg.GetBootstrapRootVersion(), 0, 0, req.Msg.GetBootstrapRootSha256(), nil)
		if err != nil {
			return nil, executionError(err)
		}
		if update == nil {
			return nil, mapErr(errInternalState)
		}
		expires := now.Add(time.Duration(req.Msg.GetLifetimeSeconds()) * time.Second)
		for _, limit := range []time.Time{token.ExpiresAt.Time, snapshot.Delegation.GetExpiresAt().AsTime()} {
			if limit.Before(expires) {
				expires = limit
			}
		}
		value := &agentv1.OfflineEnrollmentAuthorization{DeploymentId: s.deploymentID.String(), AuthorizationId: requestID.String(), TokenId: token.ID.String(), RootVersion: snapshot.Root.GetVersion(), DelegationVersion: snapshot.Delegation.GetVersion(), NotBefore: timestamppb.New(now), ExpiresAt: timestamppb.New(expires)}
		envelope, err := s.authority.Sign(ctx, value, s.signing.PlanKey)
		if err != nil {
			return nil, executionError(err)
		}
		if _, err := verifier.VerifyOfflineAuthorization(ctx, snapshot.Root, snapshot.Delegation, envelope, now); err != nil {
			return nil, rpcreason.Error(connect.CodeFailedPrecondition, "offline_enrollment_plan_signer_not_delegated")
		}
		file.AuthorizationEnvelope, file.DelegationEnvelope, file.RootTransitions = envelope, update.GetDelegationEnvelope(), update.GetRootTransitions()
		document, err := proto.Marshal(file)
		if err != nil {
			return nil, mapErr(err)
		}
		if err := q.InsertOfflineEnrollmentAuthorization(ctx, devicedb.InsertOfflineEnrollmentAuthorizationParams{ID: requestID, TokenID: token.ID, ActorID: actor.ID, RequestSha256: digest[:], AuthorizationEnvelope: document, ExpiresAt: timestamptz(expires)}); err != nil {
			return nil, mapErr(err)
		}
		if err := insertAudit(ctx, q, &actor.ID, "enrollment.offline_authorization", requestID.String(), req.Msg.GetReason()); err != nil {
			return nil, mapErr(err)
		}
		if err := completeAdmin(ctx, q, actor.ID, "CreateOfflineEnrollmentAuthorization", requestID, requestID, uuid.Nil, expires); err != nil {
			return nil, mapErr(err)
		}
	}
	if err := s.identity.LockAuthorization(ctx, tx, authorization, identity.PermissionManageEnrollment); err != nil {
		return nil, executionError(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, mapErr(err)
	}
	return noStore(&adminv1.CreateOfflineEnrollmentAuthorizationResponse{Authorization: file}), nil
}

// verifyOfflineEnrollmentRequest checks the currently delegated signer, retained
// authorization, CSR proof of possession and device-signed immutable transaction.
// Neither file-selected roots nor unsigned DSSE payload fields confer authority.
func (s *Service) verifyOfflineEnrollmentRequest(ctx context.Context, q *devicedb.Queries, snapshot *executionauthority.Snapshot, verifier *trust.ExecutionVerifier, file *agentv1.OfflineEnrollmentRequestFile, now time.Time) (*agentv1.OfflineEnrollmentRequestProof, uuid.UUID, error) {
	denied := rpcreason.Error(connect.CodePermissionDenied, "offline_enrollment_rejected")
	authorization, err := verifier.VerifyOfflineAuthorization(ctx, snapshot.Root, snapshot.Delegation, file.GetAuthorization().GetAuthorizationEnvelope(), now)
	if err != nil {
		return nil, uuid.Nil, denied
	}
	id, _ := uuid.Parse(authorization.GetAuthorizationId())
	stored, err := q.GetOfflineEnrollmentAuthorization(ctx, id)
	if err != nil {
		return nil, uuid.Nil, denied
	}
	retained := new(agentv1.OfflineEnrollmentAuthorizationFile)
	if proto.Unmarshal(stored.AuthorizationEnvelope, retained) != nil || !proto.Equal(retained, file.GetAuthorization()) || !stored.ExpiresAt.Valid || !now.Before(stored.ExpiresAt.Time) || stored.TokenID.String() != authorization.GetTokenId() {
		return nil, uuid.Nil, denied
	}
	csr, err := parseDeviceCSR(file.GetCsrPem())
	if err != nil {
		return nil, uuid.Nil, denied
	}
	public, ok := csr.PublicKey.(ed25519.PublicKey)
	if !ok {
		return nil, uuid.Nil, denied
	}
	proof := new(agentv1.OfflineEnrollmentRequestProof)
	if err := s.authority.Verify(ctx, file.GetRequestProof(), proof, 1, public); err != nil {
		return nil, uuid.Nil, denied
	}
	authDigest, csrDigest := sha256.Sum256(retained.GetAuthorizationEnvelope()), sha256.Sum256(file.GetCsrPem())
	if proof.GetDeploymentId() != s.deploymentID.String() || !bytes.Equal(proof.GetAuthorizationSha256(), authDigest[:]) || !bytes.Equal(proof.GetCsrSha256(), csrDigest[:]) || now.Before(proof.GetNotBefore().AsTime()) || !now.Before(proof.GetExpiresAt().AsTime()) || proof.GetNotBefore().AsTime().Before(authorization.GetNotBefore().AsTime()) || proof.GetExpiresAt().AsTime().After(authorization.GetExpiresAt().AsTime()) {
		return nil, uuid.Nil, denied
	}
	return proof, stored.TokenID, nil
}

func (s *Service) ImportOfflineEnrollmentRequest(ctx context.Context, req *connect.Request[adminv1.ImportOfflineEnrollmentRequestRequest]) (*connect.Response[adminv1.ImportOfflineEnrollmentRequestResponse], error) {
	ctx, cancel := bound(ctx)
	defer cancel()
	actor, err := s.requireUnrestricted(ctx, identity.PermissionManageEnrollment)
	if err != nil {
		return nil, err
	}
	if req == nil || req.Msg == nil || s.rules.Validate(req.Msg) != nil {
		return nil, invalid("invalid_offline_request")
	}
	if s.identity == nil || s.execution == nil {
		return nil, rpcreason.Error(connect.CodeFailedPrecondition, "execution_authority_unconfigured")
	}
	if err := s.acquire(ctx); err != nil {
		return nil, mapErr(err)
	}
	defer s.release()
	authorization, err := s.identity.AuthorizeFresh(ctx, actor.ID, identity.PermissionManageEnrollment)
	if err != nil {
		return nil, executionError(err)
	}
	if err := requireUnrestrictedPrincipal(authorization.Principal(), identity.PermissionManageEnrollment); err != nil {
		return nil, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, mapErr(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	snapshot, verifier, err := s.execution.CurrentInTransaction(ctx, tx)
	if err != nil {
		return nil, executionError(err)
	}
	q := devicedb.New(tx)
	now, err := dispatchClock(ctx, q)
	if err != nil {
		return nil, mapErr(err)
	}
	proof, tokenID, err := s.verifyOfflineEnrollmentRequest(ctx, q, snapshot, verifier, req.Msg.GetRequest(), now)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, mapErr(err)
	}
	enrollment, err := s.provisionOfflineToken(ctx, tokenID, &enrollmentv1.ProvisionRequest{TransactionId: proof.GetTransactionId(), InstallationId: proof.GetInstallationId(), CsrPem: req.Msg.GetRequest().GetCsrPem()}, authorization, req.Msg.GetRequest())
	if err != nil {
		return nil, mapErr(err)
	}
	return noStore(&adminv1.ImportOfflineEnrollmentRequestResponse{Enrollment: enrollment}), nil
}

func (s *Service) ExportOfflineEnrollmentResponse(ctx context.Context, req *connect.Request[adminv1.ExportOfflineEnrollmentResponseRequest]) (*connect.Response[adminv1.ExportOfflineEnrollmentResponseResponse], error) {
	ctx, cancel := bound(ctx)
	defer cancel()
	actor, err := s.requireUnrestricted(ctx, identity.PermissionManageEnrollment)
	if err != nil {
		return nil, err
	}
	if req == nil || req.Msg == nil || s.rules.Validate(req.Msg) != nil {
		return nil, invalid("invalid_offline_request")
	}
	if s.identity == nil || s.execution == nil || s.signing == nil {
		return nil, rpcreason.Error(connect.CodeFailedPrecondition, "execution_signing_unconfigured")
	}
	if err := s.acquire(ctx); err != nil {
		return nil, mapErr(err)
	}
	defer s.release()
	authorization, err := s.identity.AuthorizeFresh(ctx, actor.ID, identity.PermissionManageEnrollment)
	if err != nil {
		return nil, executionError(err)
	}
	if err := requireUnrestrictedPrincipal(authorization.Principal(), identity.PermissionManageEnrollment); err != nil {
		return nil, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, mapErr(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := s.identity.LockAuthorization(ctx, tx, authorization, identity.PermissionManageEnrollment); err != nil {
		return nil, executionError(err)
	}
	snapshot, verifier, err := s.execution.CurrentInTransaction(ctx, tx)
	if err != nil {
		return nil, executionError(err)
	}
	q := devicedb.New(tx)
	now, err := dispatchClock(ctx, q)
	if err != nil {
		return nil, mapErr(err)
	}
	proof, tokenID, err := s.verifyOfflineEnrollmentRequest(ctx, q, snapshot, verifier, req.Msg.GetRequest(), now)
	if err != nil {
		return nil, err
	}
	token, err := q.LockProvisioningToken(ctx, tokenID)
	if err != nil {
		return nil, mapErr(err)
	}
	if err := provisioningTokenUsable(token, now); err != nil {
		return nil, mapErr(err)
	}
	id, _ := uuid.Parse(proof.GetTransactionId())
	receipt, err := q.LockProvisioningEnrollment(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, rpcreason.Error(connect.CodeNotFound, "offline_request_not_imported")
	}
	if err != nil {
		return nil, mapErr(err)
	}
	if receipt.TokenID != tokenID || receipt.InstallationID.String() != proof.GetInstallationId() || !bytes.Equal(receipt.CsrSha256, proof.GetCsrSha256()) {
		return nil, mapErr(errIdempotencyConflict)
	}
	enrollment, err := s.provisioningResponse(ctx, q, token, receipt)
	if err != nil {
		return nil, mapErr(err)
	}
	if enrollment.GetState() != "ready" {
		return nil, rpcreason.Error(connect.CodeFailedPrecondition, "enrollment_pending_approval")
	}
	expires := proof.GetExpiresAt().AsTime()
	for _, limit := range []time.Time{enrollment.GetExpiresAt().AsTime(), snapshot.Delegation.GetExpiresAt().AsTime()} {
		if limit.Before(expires) {
			expires = limit
		}
	}
	value := &agentv1.OfflineEnrollmentResponse{Request: proof, DeviceId: enrollment.GetDeviceId(), EnrollmentGeneration: enrollment.GetEnrollmentGeneration(), CertificatePem: enrollment.GetCertificatePem(), RootVersion: snapshot.Root.GetVersion(), DelegationVersion: snapshot.Delegation.GetVersion(), NotBefore: timestamppb.New(now), ExpiresAt: timestamppb.New(expires)}
	envelope, err := s.authority.Sign(ctx, value, s.signing.StartKey)
	if err != nil {
		return nil, executionError(err)
	}
	if _, err := verifier.VerifyOfflineResponse(ctx, snapshot.Root, snapshot.Delegation, envelope, now); err != nil {
		return nil, rpcreason.Error(connect.CodeFailedPrecondition, "offline_enrollment_start_signer_not_delegated")
	}
	if err := insertAudit(ctx, q, &actor.ID, "enrollment.offline_response", id.String(), req.Msg.GetReason()); err != nil {
		return nil, mapErr(err)
	}
	if err := s.identity.LockAuthorization(ctx, tx, authorization, identity.PermissionManageEnrollment); err != nil {
		return nil, executionError(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, mapErr(err)
	}
	return noStore(&adminv1.ExportOfflineEnrollmentResponseResponse{Response: &agentv1.OfflineEnrollmentResponseFile{ResponseEnvelope: envelope, DelegationEnvelope: snapshot.DelegationEnvelope, RootTransitions: req.Msg.GetRequest().GetAuthorization().GetRootTransitions()}}), nil
}

// validateProvisioningImport is called inside the shared reservation transaction
// after fresh principal locks and before metadata/token locks. The execution
// authority lock remains held through reservation commit, preventing a signer
// revocation race between file verification and consuming a bounded token use.
func (s *Service) validateProvisioningImport(ctx context.Context, tx pgx.Tx, tokenID uuid.UUID, request *enrollmentv1.ProvisionRequest, file *agentv1.OfflineEnrollmentRequestFile) (time.Time, error) {
	if s.execution == nil {
		return time.Time{}, rpcreason.Error(connect.CodeFailedPrecondition, "execution_authority_unconfigured")
	}
	snapshot, verifier, err := s.execution.CurrentInTransaction(ctx, tx)
	if err != nil {
		return time.Time{}, executionError(err)
	}
	q := devicedb.New(tx)
	now, err := dispatchClock(ctx, q)
	if err != nil {
		return time.Time{}, err
	}
	proof, verifiedToken, err := s.verifyOfflineEnrollmentRequest(ctx, q, snapshot, verifier, file, now)
	if err != nil {
		return time.Time{}, err
	}
	if verifiedToken != tokenID || proof.GetTransactionId() != request.GetTransactionId() || proof.GetInstallationId() != request.GetInstallationId() || !bytes.Equal(file.GetCsrPem(), request.GetCsrPem()) {
		return time.Time{}, errIdempotencyConflict
	}
	expires := proof.GetExpiresAt().AsTime()
	for _, limit := range []time.Time{snapshot.Root.GetExpiresAt().AsTime(), snapshot.Delegation.GetExpiresAt().AsTime()} {
		if limit.Before(expires) {
			expires = limit
		}
	}
	return expires, nil
}
