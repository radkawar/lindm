package device

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"time"

	"connectrpc.com/connect"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
	devicev1 "lindm/gen/lindm/device/v1"
	"lindm/internal/device/devicedb"
	"lindm/internal/rpcreason"
)

func (s *Service) RenewIdentity(ctx context.Context, req *connect.Request[devicev1.RenewIdentityRequest]) (*connect.Response[devicev1.RenewIdentityResponse], error) {
	ctx, cancel := bound(ctx)
	defer cancel()
	principal, ok := devicePrincipalFromContext(ctx)
	if !ok {
		return nil, rpcreason.Error(connect.CodeUnauthenticated, "unauthenticated")
	}
	if req.Msg == nil || !validAuthorityProof(req.Msg.GetAuthorityProof()) {
		return nil, invalid("authority_proof")
	}
	csr, err := parseDeviceCSR(req.Msg.GetCsrPem())
	if err != nil {
		return nil, invalid("csr_rejected")
	}
	claim := new(agentv1.RenewalIntent)
	if err := s.authority.Verify(ctx, req.Msg.GetAuthorityProof(), claim, 1, principal.PublicKey); err != nil {
		return nil, errAuthorityRejected
	}
	requestID, err := parseUUID(claim.GetIssuanceRequestId())
	csrDigest := sha256.Sum256(req.Msg.GetCsrPem())
	if err != nil || !s.authorityBinding(claim.GetDeploymentId(), claim.GetDeviceId(), claim.GetEnrollmentGeneration(), principal) || !validSessionEpoch(claim.GetSessionEpoch()) || !digestEqual(claim.GetPresentedCertificateSha256(), principal.Fingerprint) || !digestEqual(claim.GetCsrSha256(), csrDigest[:]) {
		return nil, errAuthorityRejected
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
	err = s.within(ctx, func(ctx context.Context, q *devicedb.Queries) error {
		authority, err := s.lockAuthority(ctx, q, principal)
		if err != nil {
			return err
		}
		if uint64(authority.generation.SessionEpoch) != claim.GetSessionEpoch() {
			return errSessionFenced
		}
		receipt, err := q.GetRenewalReceipt(ctx, devicedb.GetRenewalReceiptParams{GenerationID: principal.GenerationID, RequestID: requestID})
		if err == nil {
			if !digestEqual(receipt.RequestDigest, digest[:]) || receipt.PresentedCertificateID != principal.CertificateID {
				return errIdempotencyConflict
			}
			issued, err := q.GetCertificateByID(ctx, receipt.IssuedCertificateID)
			if err != nil {
				return err
			}
			if issued.DeviceID != principal.DeviceID || issued.GenerationID != principal.GenerationID || !enrollmentIssuanceResumable(issued, s.now()) {
				return errCertificateRejected
			}
			expires, _ = finiteTime(issued.NotAfter)
			pemBytes = []byte(issued.Pem)
			return nil
		}
		if err != pgx.ErrNoRows {
			return err
		}
		if authority.certificate.Status != "active" {
			return errCertificateRejected
		}
		if authority.generation.RenewalIssuanceCount >= maxRenewalReceipts {
			return errReceiptCapacity
		}
		notAfter, _ := finiteTime(authority.certificate.NotAfter)
		if err := q.RetireOverlappingCertificates(ctx, devicedb.RetireOverlappingCertificatesParams{RevokedAt: timestamptz(authority.now), GenerationID: principal.GenerationID}); err != nil {
			return err
		}
		if err := q.BeginCertificateOverlap(ctx, devicedb.BeginCertificateOverlapParams{OverlapUntil: timestamptz(overlapUntil(authority.now, notAfter)), GenerationID: principal.GenerationID}); err != nil {
			return err
		}
		issued, err := s.storeCertificate(ctx, q, principal.DeviceID, principal.GenerationID, csr.PublicKey, authority.now)
		if err != nil {
			return err
		}
		if err := q.InsertRenewalReceipt(ctx, devicedb.InsertRenewalReceiptParams{
			GenerationID: principal.GenerationID, RequestID: requestID, RequestDigest: digest[:],
			PresentedCertificateID: principal.CertificateID, IssuedCertificateID: issued.ID, IssuedAt: timestamptz(authority.now),
		}); err != nil {
			return err
		}
		if err := q.CountRenewalIssuance(ctx, principal.GenerationID); err != nil {
			return err
		}
		if err := insertAudit(ctx, q, nil, actionDeviceRenew, principal.DeviceID.String(), hex.EncodeToString(issued.Fingerprint)); err != nil {
			return err
		}
		pemBytes, expires = issued.PEM, issued.NotAfter
		return nil
	})
	if err != nil {
		return nil, mapErr(err)
	}
	return noStore(&devicev1.RenewIdentityResponse{CertificatePem: pemBytes, ExpiresAt: timestamppb.New(expires)}), nil
}
