package core

import (
	"context"
	"crypto"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/types/known/timestamppb"

	enrollmentv1 "lindm/gen/lindm/enrollment/v1"
	"lindm/internal/auditkind"
	"lindm/internal/device/devicedb"
)

func (s *Service) Enroll(ctx context.Context, req *connect.Request[enrollmentv1.EnrollRequest]) (*connect.Response[enrollmentv1.EnrollResponse], error) {
	ctx, cancel := Bound(ctx)
	defer cancel()
	if req.Msg == nil || HasNUL(req.Msg.GetGrantSecret()) {
		return nil, Invalid("invalid_text")
	}
	csr, err := ParseDeviceCSR(req.Msg.GetCsrPem())
	if err != nil {
		return nil, Invalid("csr_rejected")
	}
	transactionID, err := ParseUUID(req.Msg.GetTransactionId())
	if err != nil {
		return nil, Invalid("invalid_id")
	}
	pubHash, err := PublicKeyFingerprint(csr.PublicKey)
	if err != nil {
		return nil, Invalid("csr_rejected")
	}
	if err := s.Acquire(ctx); err != nil {
		return nil, MapErr(err)
	}
	defer s.Release()

	var (
		issued     *issuedCert
		deviceID   uuid.UUID
		generation uuid.UUID
	)
	err = s.Within(ctx, func(ctx context.Context, q *devicedb.Queries) error {
		grant, err := q.GetGrantByHashForUpdate(ctx, HashGrant(req.Msg.GetGrantSecret()))
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
		expires, ok := FiniteTime(grant.ExpiresAt)
		if !ok || !expires.After(s.Now()) {
			return errGrantExpired
		}
		issued, deviceID, generation, err = s.issueEnrollment(ctx, q, grant, csr.PublicKey, transactionID, pubHash)
		return err
	})
	if err != nil {
		return nil, MapErr(err)
	}
	return NoStore(&enrollmentv1.EnrollResponse{
		DeviceId:             deviceID.String(),
		EnrollmentGeneration: generation.String(),
		CertificatePem:       append([]byte(nil), issued.PEM...),
		ExpiresAt:            timestamppb.New(issued.NotAfter),
	}), nil
}

func (s *Service) issueEnrollment(ctx context.Context, q *devicedb.Queries, grant devicedb.GetGrantByHashForUpdateRow, pub crypto.PublicKey, transactionID uuid.UUID, pubHash []byte) (*issuedCert, uuid.UUID, uuid.UUID, error) {
	binding, err := q.GetRecoveryEnrollmentGrant(ctx, grant.ID)
	if err == nil {
		return s.recoverEnrollment(ctx, q, grant, binding, pub, transactionID, pubHash)
	}
	if err != pgx.ErrNoRows {
		return nil, uuid.Nil, uuid.Nil, err
	}
	now := s.Now()
	deviceID := uuid.New()
	generation := uuid.New()
	if err := q.InsertDevice(ctx, devicedb.InsertDeviceParams{ID: deviceID, EnrolledAt: Timestamptz(now)}); err != nil {
		return nil, uuid.Nil, uuid.Nil, err
	}
	if err := q.InsertEnrollmentGeneration(ctx, devicedb.InsertEnrollmentGenerationParams{
		ID:        generation,
		DeviceID:  deviceID,
		CreatedAt: Timestamptz(now),
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
		ConsumedAt:           Timestamptz(now),
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
		return nil, uuid.Nil, uuid.Nil, ErrInternalState
	}
	if err := InsertAudit(ctx, q, nil, auditkind.DeviceEnroll, deviceID.String(), grant.Reason); err != nil {
		return nil, uuid.Nil, uuid.Nil, err
	}
	return issued, deviceID, generation, nil
}

func (s *Service) resumeEnrollment(ctx context.Context, q *devicedb.Queries, grant devicedb.GetGrantByHashForUpdateRow, transactionID uuid.UUID, pubHash []byte) (*issuedCert, uuid.UUID, uuid.UUID, error) {
	if grant.DeviceID == nil || grant.TransactionID == nil || *grant.TransactionID != transactionID || !DigestEqual(grant.PublicKeyFingerprint, pubHash) {
		return nil, uuid.Nil, uuid.Nil, errGrantConsumed
	}
	row, err := q.GetDeviceForUpdate(ctx, *grant.DeviceID)
	if err != nil {
		return nil, uuid.Nil, uuid.Nil, err
	}
	if row.State == StateRevoked || row.CurrentGenerationID == nil {
		return nil, uuid.Nil, uuid.Nil, ErrDeviceRevoked
	}
	if row.State == StateRecoveryHold {
		return nil, uuid.Nil, uuid.Nil, errRecoveryHold
	}
	if grant.CertificateID == nil {
		return nil, uuid.Nil, uuid.Nil, ErrCertificateRejected
	}
	cert, err := q.GetCertificateByID(ctx, *grant.CertificateID)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, uuid.Nil, uuid.Nil, ErrInternalState
		}
		return nil, uuid.Nil, uuid.Nil, err
	}
	if cert.DeviceID != *grant.DeviceID || !DigestEqual(cert.PublicKeyFingerprint, pubHash) {
		return nil, uuid.Nil, uuid.Nil, ErrInternalState
	}
	if *row.CurrentGenerationID != cert.GenerationID || !EnrollmentIssuanceResumable(cert, s.Now()) {
		return nil, uuid.Nil, uuid.Nil, ErrCertificateRejected
	}
	expires, ok := FiniteTime(cert.NotAfter)
	if !ok {
		return nil, uuid.Nil, uuid.Nil, ErrInternalState
	}
	return &issuedCert{PEM: []byte(cert.Pem), NotAfter: expires}, *grant.DeviceID, cert.GenerationID, nil
}

func EnrollmentIssuanceResumable(cert devicedb.GetCertificateByIDRow, now time.Time) bool {
	notBefore, ok := FiniteTime(cert.NotBefore)
	if !ok || now.Before(notBefore) {
		return false
	}
	notAfter, ok := FiniteTime(cert.NotAfter)
	if !ok || !now.Before(notAfter) {
		return false
	}
	switch cert.Status {
	case "active":
		return true
	case "overlapping":
		until, ok := FiniteTime(cert.OverlapUntil)
		return ok && now.Before(until)
	default:
		return false
	}
}
