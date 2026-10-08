package device

import (
	"context"
	"crypto"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/types/known/timestamppb"

	enrollmentv1 "lindm/gen/lindm/enrollment/v1"
	"lindm/internal/device/devicedb"
)

func (s *Service) Enroll(ctx context.Context, req *connect.Request[enrollmentv1.EnrollRequest]) (*connect.Response[enrollmentv1.EnrollResponse], error) {
	ctx, cancel := bound(ctx)
	defer cancel()
	if req.Msg == nil || hasNUL(req.Msg.GetGrantSecret()) {
		return nil, invalid("invalid_text")
	}
	csr, err := parseDeviceCSR(req.Msg.GetCsrPem())
	if err != nil {
		return nil, invalid("csr_rejected")
	}
	transactionID, err := parseUUID(req.Msg.GetTransactionId())
	if err != nil {
		return nil, invalid("invalid_id")
	}
	pubHash, err := publicKeyFingerprint(csr.PublicKey)
	if err != nil {
		return nil, invalid("csr_rejected")
	}
	if err := s.acquire(ctx); err != nil {
		return nil, mapErr(err)
	}
	defer s.release()

	var (
		issued     *issuedCert
		deviceID   uuid.UUID
		generation uuid.UUID
	)
	err = s.within(ctx, func(ctx context.Context, q *devicedb.Queries) error {
		grant, err := q.GetGrantByHashForUpdate(ctx, hashGrant(req.Msg.GetGrantSecret()))
		if err != nil {
			if err == pgx.ErrNoRows {
				return errGrantInvalid
			}
			return err
		}
		if grant.ConsumedAt.Valid {
			issued, deviceID, generation, err = s.resumeEnrollment(ctx, q, grant, transactionID, pubHash)
			return err
		}
		if grant.RevokedAt.Valid {
			return errGrantRevoked
		}
		expires, ok := finiteTime(grant.ExpiresAt)
		if !ok || !expires.After(s.now()) {
			return errGrantExpired
		}
		issued, deviceID, generation, err = s.issueEnrollment(ctx, q, grant, csr.PublicKey, transactionID, pubHash)
		return err
	})
	if err != nil {
		return nil, mapErr(err)
	}
	return noStore(&enrollmentv1.EnrollResponse{
		DeviceId:             deviceID.String(),
		EnrollmentGeneration: generation.String(),
		CertificatePem:       append([]byte(nil), issued.PEM...),
		ExpiresAt:            timestamppb.New(issued.NotAfter),
	}), nil
}

func (s *Service) issueEnrollment(ctx context.Context, q *devicedb.Queries, grant devicedb.GetGrantByHashForUpdateRow, pub crypto.PublicKey, transactionID uuid.UUID, pubHash []byte) (*issuedCert, uuid.UUID, uuid.UUID, error) {
	now := s.now()
	deviceID := uuid.New()
	generation := uuid.New()
	if err := q.InsertDevice(ctx, devicedb.InsertDeviceParams{ID: deviceID, EnrolledAt: timestamptz(now)}); err != nil {
		return nil, uuid.Nil, uuid.Nil, err
	}
	if err := q.InsertEnrollmentGeneration(ctx, devicedb.InsertEnrollmentGenerationParams{
		ID:        generation,
		DeviceID:  deviceID,
		CreatedAt: timestamptz(now),
	}); err != nil {
		return nil, uuid.Nil, uuid.Nil, err
	}
	if err := q.SetDeviceGeneration(ctx, devicedb.SetDeviceGenerationParams{
		CurrentGenerationID: &generation,
		ID:                  deviceID,
	}); err != nil {
		return nil, uuid.Nil, uuid.Nil, err
	}
	issued, err := s.storeCertificate(ctx, q, deviceID, generation, pub, now)
	if err != nil {
		return nil, uuid.Nil, uuid.Nil, err
	}
	consumed, err := q.ConsumeEnrollmentGrant(ctx, devicedb.ConsumeEnrollmentGrantParams{
		ConsumedAt:           timestamptz(now),
		DeviceID:             &deviceID,
		TransactionID:        &transactionID,
		PublicKeyFingerprint: pubHash,
		CertificateID:        &issued.ID,
		ID:                   grant.ID,
	})
	if err != nil {
		return nil, uuid.Nil, uuid.Nil, err
	}
	if consumed != 1 {
		return nil, uuid.Nil, uuid.Nil, errInternalState
	}
	if err := insertAudit(ctx, q, nil, actionDeviceEnroll, deviceID.String(), grant.Reason); err != nil {
		return nil, uuid.Nil, uuid.Nil, err
	}
	return issued, deviceID, generation, nil
}

func (s *Service) resumeEnrollment(ctx context.Context, q *devicedb.Queries, grant devicedb.GetGrantByHashForUpdateRow, transactionID uuid.UUID, pubHash []byte) (*issuedCert, uuid.UUID, uuid.UUID, error) {
	if grant.DeviceID == nil || grant.TransactionID == nil || *grant.TransactionID != transactionID || !digestEqual(grant.PublicKeyFingerprint, pubHash) {
		return nil, uuid.Nil, uuid.Nil, errGrantConsumed
	}
	row, err := q.GetDeviceForUpdate(ctx, *grant.DeviceID)
	if err != nil {
		return nil, uuid.Nil, uuid.Nil, err
	}
	if row.State == stateRevoked || row.CurrentGenerationID == nil {
		return nil, uuid.Nil, uuid.Nil, errDeviceRevoked
	}
	if row.State == stateRecoveryHold {
		return nil, uuid.Nil, uuid.Nil, errRecoveryHold
	}
	if grant.CertificateID == nil {
		return nil, uuid.Nil, uuid.Nil, errCertificateRejected
	}
	cert, err := q.GetCertificateByID(ctx, *grant.CertificateID)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, uuid.Nil, uuid.Nil, errInternalState
		}
		return nil, uuid.Nil, uuid.Nil, err
	}
	if cert.DeviceID != *grant.DeviceID || !digestEqual(cert.PublicKeyFingerprint, pubHash) {
		return nil, uuid.Nil, uuid.Nil, errInternalState
	}
	if *row.CurrentGenerationID != cert.GenerationID || !enrollmentIssuanceResumable(cert, s.now()) {
		return nil, uuid.Nil, uuid.Nil, errCertificateRejected
	}
	expires, ok := finiteTime(cert.NotAfter)
	if !ok {
		return nil, uuid.Nil, uuid.Nil, errInternalState
	}
	return &issuedCert{PEM: []byte(cert.Pem), NotAfter: expires}, *grant.DeviceID, cert.GenerationID, nil
}

func enrollmentIssuanceResumable(cert devicedb.GetCertificateByIDRow, now time.Time) bool {
	notBefore, ok := finiteTime(cert.NotBefore)
	if !ok || now.Before(notBefore) {
		return false
	}
	notAfter, ok := finiteTime(cert.NotAfter)
	if !ok || !now.Before(notAfter) {
		return false
	}
	switch cert.Status {
	case "active":
		return true
	case "overlapping":
		until, ok := finiteTime(cert.OverlapUntil)
		return ok && now.Before(until)
	default:
		return false
	}
}
