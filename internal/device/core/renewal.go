package core

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
	devicev1 "lindm/gen/lindm/device/v1"
	"lindm/internal/auditkind"
	"lindm/internal/device/devicedb"
	"lindm/internal/rpcreason"
)

func (s *Service) RenewIdentity(ctx context.Context, req *connect.Request[devicev1.RenewIdentityRequest]) (*connect.Response[devicev1.RenewIdentityResponse], error) {
	ctx, cancel := Bound(ctx)
	defer cancel()
	principal, ok := DevicePrincipalFromContext(ctx)
	if !ok {
		return nil, rpcreason.Error(connect.CodeUnauthenticated, "unauthenticated")
	}
	if req.Msg == nil || !ValidAuthorityProof(req.Msg.GetAuthorityProof()) {
		return nil, Invalid("authority_proof")
	}
	csr, err := ParseDeviceCSR(req.Msg.GetCsrPem())
	if err != nil {
		return nil, Invalid("csr_rejected")
	}
	claim := new(agentv1.RenewalIntent)
	if err := s.Authority.Verify(ctx, req.Msg.GetAuthorityProof(), claim, 1, principal.PublicKey); err != nil {
		return nil, ErrAuthorityRejected
	}
	requestID, err := ParseUUID(claim.GetIssuanceRequestId())
	csrDigest := sha256.Sum256(req.Msg.GetCsrPem())
	if err != nil || !s.AuthorityBinding(claim.GetDeploymentId(), claim.GetDeviceId(), claim.GetEnrollmentGeneration(), principal) || !ValidSessionEpoch(claim.GetSessionEpoch()) || !DigestEqual(claim.GetPresentedCertificateSha256(), principal.Fingerprint) || !DigestEqual(claim.GetCsrSha256(), csrDigest[:]) {
		return nil, ErrAuthorityRejected
	}
	// Fixed-width component hashes bind the exact proof and exact CSR bytes,
	// rather than any reserialization or merely the next public key.
	proofDigest := sha256.Sum256(req.Msg.GetAuthorityProof())
	var components [sha256.Size * 2]byte
	copy(components[:sha256.Size], proofDigest[:])
	copy(components[sha256.Size:], csrDigest[:])
	digest := sha256.Sum256(components[:])
	var pemBytes []byte
	var expires time.Time
	err = s.Within(ctx, func(ctx context.Context, q *devicedb.Queries) error {
		authority, err := s.LockAuthority(ctx, q, principal)
		if err != nil {
			return err
		}
		if uint64(authority.Generation.SessionEpoch) != claim.GetSessionEpoch() {
			return ErrSessionFenced
		}
		receipt, err := q.GetRenewalReceipt(ctx, devicedb.GetRenewalReceiptParams{GenerationID: principal.GenerationID, RequestID: requestID})
		if err == nil {
			if !DigestEqual(receipt.RequestDigest, digest[:]) || receipt.PresentedCertificateID != principal.CertificateID {
				return ErrIdempotencyConflict
			}
			issued, err := q.GetCertificateByID(ctx, receipt.IssuedCertificateID)
			if err != nil {
				return err
			}
			if issued.DeviceID != principal.DeviceID || issued.GenerationID != principal.GenerationID || !EnrollmentIssuanceResumable(issued, s.Now()) {
				return ErrCertificateRejected
			}
			expires, _ = FiniteTime(issued.NotAfter)
			pemBytes = []byte(issued.Pem)
			return nil
		}
		if err != pgx.ErrNoRows {
			return err
		}
		if authority.Certificate.Status != "active" {
			return ErrCertificateRejected
		}
		if authority.Generation.RenewalIssuanceCount >= MaxRenewalReceipts {
			return errReceiptCapacity
		}
		notAfter, _ := FiniteTime(authority.Certificate.NotAfter)
		if err := q.RetireOverlappingCertificates(ctx, devicedb.RetireOverlappingCertificatesParams{RevokedAt: Timestamptz(authority.Now), GenerationID: principal.GenerationID}); err != nil {
			return err
		}
		if err := q.BeginCertificateOverlap(ctx, devicedb.BeginCertificateOverlapParams{OverlapUntil: Timestamptz(OverlapUntil(authority.Now, notAfter)), GenerationID: principal.GenerationID}); err != nil {
			return err
		}
		issued, err := s.storeCertificate(ctx, q, principal.DeviceID, principal.GenerationID, csr.PublicKey, authority.Now)
		if err != nil {
			return err
		}
		if err := q.InsertRenewalReceipt(ctx, devicedb.InsertRenewalReceiptParams{
			GenerationID: principal.GenerationID, RequestID: requestID, RequestDigest: digest[:],
			PresentedCertificateID: principal.CertificateID, IssuedCertificateID: issued.ID, IssuedAt: Timestamptz(authority.Now),
		}); err != nil {
			return err
		}
		if err := q.CountRenewalIssuance(ctx, principal.GenerationID); err != nil {
			return err
		}
		if err := InsertDetailedAudit(ctx, q, devicedb.InsertAuditEventParams{ID: uuid.New(), Action: auditkind.DeviceRenew.String(), ResourceID: principal.DeviceID.String(), TargetDeviceID: &principal.DeviceID}, AuditDetails("certificate_sha256", hex.EncodeToString(issued.Fingerprint))); err != nil {
			return err
		}
		pemBytes, expires = issued.PEM, issued.NotAfter
		return nil
	})
	if err != nil {
		return nil, MapErr(err)
	}
	return NoStore(&devicev1.RenewIdentityResponse{CertificatePem: pemBytes, ExpiresAt: timestamppb.New(expires)}), nil
}
