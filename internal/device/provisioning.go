package device

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
	enrollmentv1 "lindm/gen/lindm/enrollment/v1"
	"lindm/internal/device/devicedb"
	"lindm/internal/identity"
	"lindm/internal/trust"
)

func (s *Service) Provision(ctx context.Context, req *connect.Request[enrollmentv1.ProvisionRequest]) (*connect.Response[enrollmentv1.ProvisionResponse], error) {
	ctx, cancel := bound(ctx)
	defer cancel()
	if req == nil || req.Msg == nil || s.rules.Validate(req.Msg) != nil {
		return nil, invalid("invalid_provisioning_request")
	}
	if err := s.acquire(ctx); err != nil {
		return nil, mapErr(err)
	}
	defer s.release()
	response, err := s.provision(ctx, req.Msg)
	if err != nil {
		return nil, mapErr(err)
	}
	return noStore(response), nil
}

func (s *Service) provision(ctx context.Context, request *enrollmentv1.ProvisionRequest) (*enrollmentv1.ProvisionResponse, error) {
	if request == nil || request.GetProvisioningToken() == "" || s.rules.Validate(request) != nil {
		return nil, invalid("invalid_provisioning_request")
	}
	token, err := devicedb.New(s.pool).GetProvisioningTokenByHash(ctx, hashGrant(request.GetProvisioningToken()))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errGrantInvalid
	}
	if err != nil {
		return nil, err
	}
	return s.provisionToken(ctx, token.ID, request)
}

// The two adapters share the same reservation transaction. Offline requests also
// retain the current execution-authority lock through the reservation commit.
func (s *Service) provisionToken(ctx context.Context, tokenID uuid.UUID, request *enrollmentv1.ProvisionRequest) (*enrollmentv1.ProvisionResponse, error) {
	return s.reserveProvisioning(ctx, tokenID, request, nil, nil)
}

func (s *Service) provisionOfflineToken(ctx context.Context, tokenID uuid.UUID, request *enrollmentv1.ProvisionRequest, importer *identity.Authorization, file *agentv1.OfflineEnrollmentRequestFile) (*enrollmentv1.ProvisionResponse, error) {
	if importer == nil || file == nil {
		return nil, errInternalState
	}
	return s.reserveProvisioning(ctx, tokenID, request, importer, file)
}

func (s *Service) reserveProvisioning(ctx context.Context, tokenID uuid.UUID, request *enrollmentv1.ProvisionRequest, importer *identity.Authorization, offline *agentv1.OfflineEnrollmentRequestFile) (*enrollmentv1.ProvisionResponse, error) {
	if request == nil || s.rules.Validate(request) != nil {
		return nil, invalid("invalid_provisioning_request")
	}
	csr, err := parseDeviceCSR(request.GetCsrPem())
	if err != nil {
		return nil, invalid("csr_rejected")
	}
	transactionID, err := parseUUID(request.GetTransactionId())
	if err != nil {
		return nil, invalid("invalid_id")
	}
	installationID, err := parseUUID(request.GetInstallationId())
	if err != nil {
		return nil, invalid("invalid_id")
	}
	digest := sha256.Sum256(request.GetCsrPem())
	token, err := devicedb.New(s.pool).GetProvisioningToken(ctx, tokenID)
	if err != nil {
		return nil, notFoundIfMissing(err)
	}
	authorization, assignment, err := s.provisioningAuthorization(ctx, token)
	if err != nil {
		return nil, err
	}
	if importer != nil {
		if err := requireUnrestrictedPrincipal(importer.Principal(), identity.PermissionManageEnrollment); err != nil {
			return nil, err
		}
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := s.lockProvisioningPair(ctx, tx, authorization, importer); err != nil {
		return nil, err
	}
	var offlineExpiry time.Time
	if offline != nil {
		offlineExpiry, err = s.validateProvisioningImport(ctx, tx, tokenID, request, offline)
		if err != nil {
			return nil, err
		}
	}
	if err := s.validateProvisioningAssignment(ctx, tx, assignment); err != nil {
		return nil, err
	}
	q := devicedb.New(tx)
	token, err = q.LockProvisioningToken(ctx, tokenID)
	if err != nil {
		return nil, err
	}
	previous, err := q.LockProvisioningEnrollment(ctx, transactionID)
	var response *enrollmentv1.ProvisionResponse
	if err == nil {
		if previous.TokenID != tokenID || previous.InstallationID != installationID || !digestEqual(previous.CsrSha256, digest[:]) {
			return nil, errIdempotencyConflict
		}
		response, err = s.provisioningResponse(ctx, q, token, previous)
		if err != nil {
			return nil, err
		}
	} else {
		if !errors.Is(err, pgx.ErrNoRows) {
			return nil, err
		}
		now, err := dispatchClock(ctx, q)
		if err != nil {
			return nil, err
		}
		if err := provisioningTokenUsable(token, now); err != nil {
			return nil, err
		}
		if token.UsedCount >= token.MaxUses {
			return nil, rpcError(connect.CodeResourceExhausted, "provisioning_token_exhausted")
		}
		deviceID, generationID := uuid.New(), uuid.New()
		if err := q.InsertDevice(ctx, devicedb.InsertDeviceParams{ID: deviceID, EnrolledAt: timestamptz(now)}); err != nil {
			return nil, err
		}
		if err := q.InsertEnrollmentGeneration(ctx, devicedb.InsertEnrollmentGenerationParams{ID: generationID, DeviceID: deviceID, CreatedAt: timestamptz(now)}); err != nil {
			return nil, err
		}
		if err := q.SetDeviceGeneration(ctx, devicedb.SetDeviceGenerationParams{ID: deviceID, CurrentGenerationID: &generationID}); err != nil {
			return nil, err
		}
		if err := q.ReserveEnrollmentInstallation(ctx, devicedb.ReserveEnrollmentInstallationParams{GenerationID: generationID, InstallationID: installationID}); err != nil {
			return nil, err
		}
		if err := s.applyProvisioningMetadata(ctx, q, deviceID, assignment); err != nil {
			return nil, err
		}
		receipt := devicedb.ProvisioningEnrollment{TransactionID: transactionID, TokenID: tokenID, InstallationID: installationID, DeviceID: deviceID, GenerationID: generationID, CsrPem: request.GetCsrPem(), CsrSha256: digest[:], State: "pending_approval", CreatedAt: timestamptz(now), ExpiresAt: timestamptz(now.Add(time.Hour))}
		if token.ExpiresAt.Time.Before(receipt.ExpiresAt.Time) {
			receipt.ExpiresAt = token.ExpiresAt
		}
		if token.ApprovalRequired {
			payload := pendingEnrollmentPayload(token, receipt)
			id, err := s.identity.CreateEnrollmentApproval(ctx, tx, authorization, payload, s.approvalScope)
			if err != nil {
				return nil, approvalError(err)
			}
			receipt.ApprovalID = &id
		} else {
			issued, err := s.storeCertificate(ctx, q, deviceID, generationID, csr.PublicKey, now)
			if err != nil {
				return nil, err
			}
			receipt.CertificateID = &issued.ID
			receipt.State = "ready"
			if err := s.activateProvisioningProfile(ctx, tx, token, receipt, assignment); err != nil {
				return nil, err
			}
		}
		if err := q.InsertProvisioningEnrollment(ctx, devicedb.InsertProvisioningEnrollmentParams(receipt)); err != nil {
			var conflict *pgconn.PgError
			if errors.As(err, &conflict) && conflict.Code == "23505" {
				return nil, errIdempotencyConflict
			}
			return nil, err
		}
		consumed, err := q.ConsumeProvisioningToken(ctx, tokenID)
		if err != nil {
			return nil, err
		}
		if consumed != 1 {
			return nil, rpcError(connect.CodePermissionDenied, "provisioning_token_expired")
		}
		if err := insertAudit(ctx, q, &token.CreatedBy, "provisioning.reserve", deviceID.String(), token.Reason); err != nil {
			return nil, err
		}
		if importer != nil {
			actor := importer.ActorID()
			if err := insertAudit(ctx, q, &actor, "enrollment.offline_import", transactionID.String(), token.Reason); err != nil {
				return nil, err
			}
		}
		response, err = s.provisioningResponse(ctx, q, token, receipt)
		if err != nil {
			return nil, err
		}
	}
	if err := s.lockProvisioningPair(ctx, tx, authorization, importer); err != nil {
		return nil, err
	}
	if offline != nil {
		now, err := dispatchClock(ctx, q)
		if err != nil {
			return nil, err
		}
		if !now.Before(offlineExpiry) {
			return nil, rpcError(connect.CodePermissionDenied, "offline_enrollment_rejected")
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return response, nil
}

func provisioningTokenUsable(token devicedb.ProvisioningToken, now time.Time) error {
	if token.RevokedAt.Valid {
		return rpcError(connect.CodePermissionDenied, "provisioning_token_revoked")
	}
	if !token.ExpiresAt.Valid || !now.Before(token.ExpiresAt.Time) {
		return rpcError(connect.CodePermissionDenied, "provisioning_token_expired")
	}
	return nil
}

func pendingEnrollmentPayload(token devicedb.ProvisioningToken, receipt devicedb.ProvisioningEnrollment) *adminv1.ApprovePendingEnrollmentRequest {
	return &adminv1.ApprovePendingEnrollmentRequest{RequestId: receipt.TransactionID.String(), TransactionId: receipt.TransactionID.String(), DeviceId: receipt.DeviceID.String(), Reason: token.Reason}
}

func (s *Service) provisioningResponse(ctx context.Context, q *devicedb.Queries, token devicedb.ProvisioningToken, receipt devicedb.ProvisioningEnrollment) (*enrollmentv1.ProvisionResponse, error) {
	device, err := q.GetDeviceForUpdate(ctx, receipt.DeviceID)
	if err != nil {
		return nil, err
	}
	if device.State != statePending && device.State != stateActive {
		return nil, errDeviceRevoked
	}
	if device.CurrentGenerationID == nil || *device.CurrentGenerationID != receipt.GenerationID {
		return nil, errCertificateRejected
	}
	response := &enrollmentv1.ProvisionResponse{DeviceId: receipt.DeviceID.String(), EnrollmentGeneration: receipt.GenerationID.String(), State: receipt.State, ExpiresAt: timestamppb.New(receipt.ExpiresAt.Time)}
	if receipt.State == "pending_approval" {
		now, err := dispatchClock(ctx, q)
		if err != nil {
			return nil, err
		}
		if err := provisioningTokenUsable(token, now); err != nil {
			return nil, err
		}
		if !now.Before(receipt.ExpiresAt.Time) {
			return nil, approvalError(identity.ErrAuthorizationExpired)
		}
		if receipt.ApprovalID == nil {
			return nil, errInternalState
		}
		decision, err := q.ProvisioningApprovalState(ctx, *receipt.ApprovalID)
		if err != nil {
			return nil, err
		}
		if decision.State == "rejected" {
			return nil, rpcError(connect.CodePermissionDenied, "enrollment_rejected")
		}
		if !now.Before(decision.ExpiresAt.Time) {
			return nil, approvalError(identity.ErrAuthorizationExpired)
		}
		return response, nil
	}
	if receipt.State != "ready" || receipt.CertificateID == nil {
		return nil, rpcError(connect.CodePermissionDenied, "enrollment_rejected")
	}
	certificate, err := q.GetCertificateByID(ctx, *receipt.CertificateID)
	if err != nil {
		return nil, err
	}
	if certificate.DeviceID != receipt.DeviceID || certificate.GenerationID != receipt.GenerationID || !enrollmentIssuanceResumable(certificate, s.now()) {
		return nil, errCertificateRejected
	}
	response.CertificatePem = []byte(certificate.Pem)
	response.ExpiresAt = timestamppb.New(certificate.NotAfter.Time)
	return response, nil
}

func (s *Service) RetrieveProvisioningIssuance(ctx context.Context, req *connect.Request[enrollmentv1.RetrieveProvisioningIssuanceRequest]) (*connect.Response[enrollmentv1.RetrieveProvisioningIssuanceResponse], error) {
	ctx, cancel := bound(ctx)
	defer cancel()
	if req == nil || req.Msg == nil || s.rules.Validate(req.Msg) != nil {
		return nil, invalid("invalid_provisioning_proof")
	}
	if err := s.acquire(ctx); err != nil {
		return nil, mapErr(err)
	}
	defer s.release()
	denied := rpcError(connect.CodeUnauthenticated, "unauthenticated")
	var envelope dsse.Envelope
	if err := json.Unmarshal(req.Msg.GetAuthorityProof(), &envelope); err != nil || envelope.PayloadType != trust.ProvisioningRetrievalType {
		return nil, denied
	}
	payload, err := base64.StdEncoding.DecodeString(envelope.Payload)
	if err != nil {
		return nil, denied
	}
	claim := new(enrollmentv1.ProvisioningRetrieval)
	if err := proto.Unmarshal(payload, claim); err != nil || claim.GetDeploymentId() != s.deploymentID.String() {
		return nil, denied
	}
	id, err := parseUUID(claim.GetTransactionId())
	if err != nil {
		return nil, denied
	}
	q := devicedb.New(s.pool)
	receipt, err := q.GetProvisioningEnrollment(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, rpcError(connect.CodeNotFound, "enrollment_transaction_not_found")
	}
	if err != nil {
		return nil, mapErr(err)
	}
	csr, err := parseDeviceCSR(receipt.CsrPem)
	if err != nil {
		return nil, denied
	}
	public, ok := csr.PublicKey.(ed25519.PublicKey)
	if !ok {
		return nil, denied
	}
	verified := new(enrollmentv1.ProvisioningRetrieval)
	if err := s.authority.Verify(ctx, req.Msg.GetAuthorityProof(), verified, 1, public); err != nil || !proto.Equal(claim, verified) || claim.GetInstallationId() != receipt.InstallationID.String() || !digestEqual(claim.GetCsrSha256(), receipt.CsrSha256) {
		return nil, denied
	}
	var response *enrollmentv1.ProvisionResponse
	err = s.within(ctx, func(ctx context.Context, q *devicedb.Queries) error {
		token, err := q.LockProvisioningToken(ctx, receipt.TokenID)
		if err != nil {
			return err
		}
		current, err := q.LockProvisioningEnrollment(ctx, id)
		if err != nil {
			return err
		}
		response, err = s.provisioningResponse(ctx, q, token, current)
		return err
	})
	if err != nil {
		return nil, mapErr(err)
	}
	return noStore(&enrollmentv1.RetrieveProvisioningIssuanceResponse{Enrollment: response}), nil
}
