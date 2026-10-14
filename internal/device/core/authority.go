// SPDX-License-Identifier: Apache-2.0

package core

import (
	"context"
	"math"
	"time"

	"github.com/jackc/pgx/v5"

	"lindm/internal/device/devicedb"
)

const (
	maxAuthorityProofBytes = 16 << 10
	// Active-generation receipts never expire. Fixed admission ceilings bound
	// hostile durable growth without losing exact replay or predecessor fences.
	// Daily boots fit for >179 years; ten-day renewals fit for >112 years.
	MaxSessionReceipts = 65536
	MaxRenewalReceipts = 4096
)

// Device mutations hold the device row throughout authority checks and writes.
type DeviceAuthority struct {
	Device devicedb.GetDeviceForUpdateRow
	deviceCredentials
}

type deviceCredentials struct {
	Generation  devicedb.GetGenerationAuthorityRow
	Certificate devicedb.GetCertificateByIDRow
	Now         time.Time
}

func (s *Service) LockAuthority(ctx context.Context, q *devicedb.Queries, principal DevicePrincipal) (DeviceAuthority, error) {
	row, err := q.GetDeviceForUpdate(ctx, principal.DeviceID)
	if err != nil {
		return DeviceAuthority{}, err
	}
	credentials, err := s.checkAuthority(ctx, q, principal, devicedb.GetDeviceAuthorityRow{ID: row.ID, State: row.State, CurrentGenerationID: row.CurrentGenerationID})
	if err != nil {
		return DeviceAuthority{}, err
	}
	return DeviceAuthority{Device: row, deviceCredentials: credentials}, nil
}

// readAuthority requires REPEATABLE READ, READ ONLY: the device, generation and
// certificate must describe one committed state, never mixed statement snapshots.
// It authorizes public trust delivery or an empty poll, not execution or a write.
func (s *Service) ReadAuthority(ctx context.Context, q *devicedb.Queries, principal DevicePrincipal) (deviceCredentials, error) {
	row, err := q.GetDeviceAuthority(ctx, principal.DeviceID)
	if err != nil {
		return deviceCredentials{}, err
	}
	return s.checkAuthority(ctx, q, principal, row)
}

func (s *Service) checkAuthority(ctx context.Context, q *devicedb.Queries, principal DevicePrincipal, row devicedb.GetDeviceAuthorityRow) (deviceCredentials, error) {
	var authority deviceCredentials
	if row.State == StateRecoveryHold {
		return authority, errRecoveryHold
	}
	if (row.State != StatePending && row.State != StateActive) || row.CurrentGenerationID == nil || *row.CurrentGenerationID != principal.GenerationID {
		return authority, ErrDeviceRevoked
	}
	generation, err := q.GetGenerationAuthority(ctx, principal.GenerationID)
	if err != nil {
		return authority, err
	}
	if generation.DeviceID != row.ID || (generation.State != StatePending && generation.State != StateActive) {
		return authority, ErrCertificateRejected
	}
	certificate, err := q.GetCertificateByID(ctx, principal.CertificateID)
	if err != nil {
		if err == pgx.ErrNoRows {
			return authority, ErrCertificateRejected
		}
		return authority, err
	}
	now := s.Now()
	if certificate.DeviceID != row.ID || certificate.GenerationID != principal.GenerationID || !DigestEqual(certificate.Fingerprint, principal.Fingerprint) || !EnrollmentIssuanceResumable(certificate, now) {
		return authority, ErrCertificateRejected
	}
	return deviceCredentials{Generation: generation, Certificate: certificate, Now: now}, nil
}

func ValidSessionEpoch(epoch uint64) bool {
	return epoch > 0 && epoch <= math.MaxInt64
}

func ValidAuthorityProof(proof []byte) bool {
	return len(proof) > 0 && len(proof) <= maxAuthorityProofBytes
}
