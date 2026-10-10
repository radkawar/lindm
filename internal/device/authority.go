package device

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
	maxSessionReceipts = 65536
	maxRenewalReceipts = 4096
)

// Device mutations hold the device row throughout authority checks and writes.
type deviceAuthority struct {
	device devicedb.GetDeviceForUpdateRow
	deviceCredentials
}

type deviceCredentials struct {
	generation  devicedb.GetGenerationAuthorityRow
	certificate devicedb.GetCertificateByIDRow
	now         time.Time
}

func (s *Service) lockAuthority(ctx context.Context, q *devicedb.Queries, principal devicePrincipal) (deviceAuthority, error) {
	row, err := q.GetDeviceForUpdate(ctx, principal.DeviceID)
	if err != nil {
		return deviceAuthority{}, err
	}
	credentials, err := s.checkAuthority(ctx, q, principal, devicedb.GetDeviceAuthorityRow{ID: row.ID, State: row.State, CurrentGenerationID: row.CurrentGenerationID})
	if err != nil {
		return deviceAuthority{}, err
	}
	return deviceAuthority{device: row, deviceCredentials: credentials}, nil
}

// readAuthority requires REPEATABLE READ, READ ONLY: the device, generation and
// certificate must describe one committed state, never mixed statement snapshots.
// It authorizes public trust delivery or an empty poll, not execution or a write.
func (s *Service) readAuthority(ctx context.Context, q *devicedb.Queries, principal devicePrincipal) (deviceCredentials, error) {
	row, err := q.GetDeviceAuthority(ctx, principal.DeviceID)
	if err != nil {
		return deviceCredentials{}, err
	}
	return s.checkAuthority(ctx, q, principal, row)
}

func (s *Service) checkAuthority(ctx context.Context, q *devicedb.Queries, principal devicePrincipal, row devicedb.GetDeviceAuthorityRow) (deviceCredentials, error) {
	var authority deviceCredentials
	if row.State == stateRecoveryHold {
		return authority, errRecoveryHold
	}
	if (row.State != statePending && row.State != stateActive) || row.CurrentGenerationID == nil || *row.CurrentGenerationID != principal.GenerationID {
		return authority, errDeviceRevoked
	}
	generation, err := q.GetGenerationAuthority(ctx, principal.GenerationID)
	if err != nil {
		return authority, err
	}
	if generation.DeviceID != row.ID || (generation.State != statePending && generation.State != stateActive) {
		return authority, errCertificateRejected
	}
	certificate, err := q.GetCertificateByID(ctx, principal.CertificateID)
	if err != nil {
		if err == pgx.ErrNoRows {
			return authority, errCertificateRejected
		}
		return authority, err
	}
	now := s.now()
	if certificate.DeviceID != row.ID || certificate.GenerationID != principal.GenerationID || !digestEqual(certificate.Fingerprint, principal.Fingerprint) || !enrollmentIssuanceResumable(certificate, now) {
		return authority, errCertificateRejected
	}
	return deviceCredentials{generation: generation, certificate: certificate, now: now}, nil
}

func validSessionEpoch(epoch uint64) bool {
	return epoch > 0 && epoch <= math.MaxInt64
}

func validAuthorityProof(proof []byte) bool {
	return len(proof) > 0 && len(proof) <= maxAuthorityProofBytes
}
