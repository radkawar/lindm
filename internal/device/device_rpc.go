package device

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"math"
	"net/http"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/types/known/timestamppb"

	devicev1 "lindm/gen/lindm/device/v1"
	"lindm/internal/device/devicedb"
)

type devicePrincipal struct {
	DeviceID      uuid.UUID
	GenerationID  uuid.UUID
	CertificateID uuid.UUID
	Fingerprint   []byte
}

type devicePrincipalKey struct{}

func withDevicePrincipal(ctx context.Context, principal devicePrincipal) context.Context {
	return context.WithValue(ctx, devicePrincipalKey{}, principal)
}

func devicePrincipalFromContext(ctx context.Context) (devicePrincipal, bool) {
	principal, ok := ctx.Value(devicePrincipalKey{}).(devicePrincipal)
	return principal, ok
}

// presentedIdentity validates the handshake chain itself. It never reads headers.
func (s *Service) presentedIdentity(r *http.Request, now time.Time) (*x509.Certificate, uuid.UUID, uuid.UUID, error) {
	if r == nil || r.TLS == nil || !r.TLS.HandshakeComplete || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.VerifiedChains[0]) == 0 || len(r.TLS.PeerCertificates) == 0 {
		return nil, uuid.Nil, uuid.Nil, rpcError(connect.CodeUnauthenticated, "unauthenticated")
	}
	leaf := r.TLS.VerifiedChains[0][0]
	if leaf == nil || !leaf.Equal(r.TLS.PeerCertificates[0]) {
		return nil, uuid.Nil, uuid.Nil, rpcError(connect.CodeUnauthenticated, "unauthenticated")
	}
	roots := x509.NewCertPool()
	roots.AddCert(s.ca)
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:       roots,
		CurrentTime: now,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		return nil, uuid.Nil, uuid.Nil, rpcError(connect.CodeUnauthenticated, "unauthenticated")
	}
	if leaf.KeyUsage != x509.KeyUsageDigitalSignature || len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth || len(leaf.UnknownExtKeyUsage) != 0 || !leaf.BasicConstraintsValid || leaf.IsCA || len(leaf.DNSNames) != 0 || len(leaf.EmailAddresses) != 0 || len(leaf.IPAddresses) != 0 || len(leaf.URIs) != 1 {
		return nil, uuid.Nil, uuid.Nil, rpcError(connect.CodeUnauthenticated, "unauthenticated")
	}
	deployment, deviceID, generationID, err := parseIdentity(leaf.URIs[0].String())
	if err != nil || deployment != s.deploymentID {
		return nil, uuid.Nil, uuid.Nil, rpcError(connect.CodeUnauthenticated, "unauthenticated")
	}
	return leaf, deviceID, generationID, nil
}

func (s *Service) bindCertificate(ctx context.Context, leaf *x509.Certificate, deviceID, generationID uuid.UUID, now time.Time) (devicePrincipal, error) {
	sum := sha256.Sum256(leaf.Raw)
	row, err := devicedb.New(s.pool).GetCertificateByFingerprint(ctx, sum[:])
	if err != nil {
		if err == pgx.ErrNoRows {
			return devicePrincipal{}, rpcError(connect.CodeUnauthenticated, "unauthenticated")
		}
		return devicePrincipal{}, mapErr(err)
	}
	if row.DeviceID != deviceID || row.GenerationID != generationID || row.CurrentGenerationID == nil || *row.CurrentGenerationID != generationID || row.DeviceState == stateRevoked {
		return devicePrincipal{}, errCertificateRejected
	}
	notBefore, ok := finiteTime(row.NotBefore)
	if !ok || now.Before(notBefore) {
		return devicePrincipal{}, errCertificateRejected
	}
	notAfter, ok := finiteTime(row.NotAfter)
	if !ok || !now.Before(notAfter) {
		return devicePrincipal{}, errCertificateRejected
	}
	switch row.Status {
	case "active":
	case "overlapping":
		until, ok := finiteTime(row.OverlapUntil)
		if !ok || !now.Before(until) {
			return devicePrincipal{}, errCertificateRejected
		}
	default:
		return devicePrincipal{}, errCertificateRejected
	}
	return devicePrincipal{DeviceID: row.DeviceID, GenerationID: row.GenerationID, CertificateID: row.ID, Fingerprint: append([]byte(nil), sum[:]...)}, nil
}

func (s *Service) ReportInventory(ctx context.Context, req *connect.Request[devicev1.ReportInventoryRequest]) (*connect.Response[devicev1.ReportInventoryResponse], error) {
	ctx, cancel := bound(ctx)
	defer cancel()
	principal, ok := devicePrincipalFromContext(ctx)
	if !ok {
		return nil, rpcError(connect.CodeUnauthenticated, "unauthenticated")
	}
	if req.Msg == nil {
		return nil, invalid("invalid_argument")
	}
	generation, err := parseUUID(req.Msg.GetEnrollmentGeneration())
	if err != nil || generation != principal.GenerationID {
		return nil, errGenerationMismatch
	}
	bootID, err := parseUUID(req.Msg.GetBootId())
	if err != nil {
		return nil, invalid("invalid_id")
	}
	if req.Msg.GetSequence() == 0 || req.Msg.GetSequence() > uint64(math.MaxInt64) {
		return nil, invalid("sequence")
	}
	if hasNUL(req.Msg.GetHostname(), req.Msg.GetOsId(), req.Msg.GetOsVersion(), req.Msg.GetArchitecture()) {
		return nil, invalid("invalid_text")
	}
	for _, pkg := range req.Msg.GetPackages() {
		if pkg == nil || hasNUL(pkg.GetName(), pkg.GetVersion(), pkg.GetArchitecture(), pkg.GetManager()) {
			return nil, invalid("invalid_text")
		}
	}
	seq := int64(req.Msg.GetSequence())
	digest := inventoryDigest(req.Msg)
	var accepted uint64
	var serverTime time.Time
	err = s.within(ctx, func(ctx context.Context, q *devicedb.Queries) error {
		row, err := q.GetDeviceForUpdate(ctx, principal.DeviceID)
		if err != nil {
			return err
		}
		if row.State == stateRevoked || row.CurrentGenerationID == nil || *row.CurrentGenerationID != principal.GenerationID {
			return errDeviceRevoked
		}
		now := s.now()
		serverTime = now
		switch {
		case seq < row.InventorySequence:
			accepted = uint64(row.InventorySequence)
			return q.TouchDeviceLastSeen(ctx, devicedb.TouchDeviceLastSeenParams{LastSeenAt: timestamptz(now), ID: row.ID})
		case seq == row.InventorySequence:
			if !digestEqual(row.InventoryDigest, digest) {
				return errInventoryConflict
			}
			accepted = uint64(seq)
			return q.TouchDeviceLastSeen(ctx, devicedb.TouchDeviceLastSeenParams{LastSeenAt: timestamptz(now), ID: row.ID})
		}
		snapshotSeq := row.PackageSnapshotSequence
		snapshotComplete := row.PackageSnapshotComplete
		if req.Msg.GetPackagesComplete() {
			if err := replacePackages(ctx, q, row.ID, req.Msg.GetPackages()); err != nil {
				return err
			}
			snapshotSeq = seq
			snapshotComplete = true
		}
		nextState := row.State
		if row.State == statePending {
			nextState = stateActive
		}
		if err := q.UpdateDeviceInventory(ctx, devicedb.UpdateDeviceInventoryParams{
			Hostname:                req.Msg.GetHostname(),
			OsID:                    req.Msg.GetOsId(),
			OsVersion:               req.Msg.GetOsVersion(),
			Architecture:            req.Msg.GetArchitecture(),
			LastSeenAt:              timestamptz(now),
			InventorySequence:       seq,
			InventoryDigest:         digest,
			BootID:                  &bootID,
			State:                   nextState,
			PackageSnapshotSequence: snapshotSeq,
			PackageSnapshotComplete: snapshotComplete,
			ID:                      row.ID,
		}); err != nil {
			return err
		}
		if row.State == statePending {
			if err := q.ActivateGeneration(ctx, *row.CurrentGenerationID); err != nil {
				return err
			}
			if err := insertAudit(ctx, q, nil, actionDeviceActivate, row.ID.String(), "activated"); err != nil {
				return err
			}
		}
		accepted = uint64(seq)
		return nil
	})
	if err != nil {
		return nil, mapErr(err)
	}
	return connect.NewResponse(&devicev1.ReportInventoryResponse{
		AcceptedSequence: accepted,
		ServerTime:       timestamppb.New(serverTime),
	}), nil
}

func replacePackages(ctx context.Context, q *devicedb.Queries, deviceID uuid.UUID, packages []*devicev1.Package) error {
	if err := q.DeleteDevicePackages(ctx, deviceID); err != nil {
		return err
	}
	for i, pkg := range packages {
		if err := q.InsertDevicePackage(ctx, devicedb.InsertDevicePackageParams{
			DeviceID:     deviceID,
			Position:     int32(i),
			Name:         pkg.GetName(),
			Version:      pkg.GetVersion(),
			Architecture: pkg.GetArchitecture(),
			Manager:      pkg.GetManager(),
		}); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) RenewIdentity(ctx context.Context, req *connect.Request[devicev1.RenewIdentityRequest]) (*connect.Response[devicev1.RenewIdentityResponse], error) {
	ctx, cancel := bound(ctx)
	defer cancel()
	principal, ok := devicePrincipalFromContext(ctx)
	if !ok {
		return nil, rpcError(connect.CodeUnauthenticated, "unauthenticated")
	}
	if req.Msg == nil {
		return nil, invalid("invalid_argument")
	}
	csr, err := parseDeviceCSR(req.Msg.GetCsrPem())
	if err != nil {
		return nil, invalid("csr_rejected")
	}
	pubHash, err := publicKeyFingerprint(csr.PublicKey)
	if err != nil {
		return nil, invalid("csr_rejected")
	}
	var pemBytes []byte
	var expires time.Time
	err = s.within(ctx, func(ctx context.Context, q *devicedb.Queries) error {
		row, err := q.GetDeviceForUpdate(ctx, principal.DeviceID)
		if err != nil {
			return err
		}
		if row.State == stateRevoked || row.CurrentGenerationID == nil || *row.CurrentGenerationID != principal.GenerationID {
			return errDeviceRevoked
		}
		presented, err := q.GetCertificateByFingerprint(ctx, principal.Fingerprint)
		if err != nil {
			if err == pgx.ErrNoRows {
				return errCertificateRejected
			}
			return err
		}
		if presented.ID != principal.CertificateID || presented.DeviceID != principal.DeviceID || presented.GenerationID != principal.GenerationID || presented.DeviceState == stateRevoked {
			return errCertificateRejected
		}
		active, err := q.GetActiveCertificate(ctx, principal.GenerationID)
		if err != nil {
			if err == pgx.ErrNoRows {
				return errInternalState
			}
			return err
		}
		now := s.now()
		if presented.Status != "active" {
			if !renewalReplay(presented, active, pubHash, now) {
				return errCertificateRejected
			}
			notAfter, ok := finiteTime(active.NotAfter)
			if !ok {
				return errInternalState
			}
			pemBytes = []byte(active.Pem)
			expires = notAfter
			return nil
		}
		if presented.ID != active.ID {
			return errInternalState
		}
		notAfter, ok := finiteTime(active.NotAfter)
		if !ok {
			return errInternalState
		}
		if err := q.RetireOverlappingCertificates(ctx, devicedb.RetireOverlappingCertificatesParams{
			RevokedAt:    timestamptz(now),
			GenerationID: principal.GenerationID,
		}); err != nil {
			return err
		}
		if err := q.BeginCertificateOverlap(ctx, devicedb.BeginCertificateOverlapParams{
			OverlapUntil: timestamptz(overlapUntil(now, notAfter)),
			GenerationID: principal.GenerationID,
		}); err != nil {
			return err
		}
		issued, err := s.storeCertificate(ctx, q, principal.DeviceID, principal.GenerationID, csr.PublicKey, now)
		if err != nil {
			return err
		}
		if err := insertAudit(ctx, q, nil, actionDeviceRenew, principal.DeviceID.String(), hex.EncodeToString(issued.Fingerprint)); err != nil {
			return err
		}
		pemBytes = issued.PEM
		expires = issued.NotAfter
		return nil
	})
	if err != nil {
		return nil, mapErr(err)
	}
	return noStore(&devicev1.RenewIdentityResponse{
		CertificatePem: pemBytes,
		ExpiresAt:      timestamppb.New(expires),
	}), nil
}

func renewalReplay(presented devicedb.GetCertificateByFingerprintRow, active devicedb.GetActiveCertificateRow, pubHash []byte, now time.Time) bool {
	if presented.Status != "overlapping" || presented.ID == active.ID || !digestEqual(active.PublicKeyFingerprint, pubHash) {
		return false
	}
	until, ok := finiteTime(presented.OverlapUntil)
	return ok && now.Before(until)
}
