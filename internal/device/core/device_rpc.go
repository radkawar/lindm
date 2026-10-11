package core

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"net/http"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"lindm/internal/device/devicedb"
	"lindm/internal/pki"
	"lindm/internal/rpcreason"
)

type DevicePrincipal struct {
	DeviceID      uuid.UUID
	GenerationID  uuid.UUID
	CertificateID uuid.UUID
	Fingerprint   []byte
	PublicKey     ed25519.PublicKey
}

type devicePrincipalKey struct{}

func WithDevicePrincipal(ctx context.Context, principal DevicePrincipal) context.Context {
	return context.WithValue(ctx, devicePrincipalKey{}, principal)
}

func DevicePrincipalFromContext(ctx context.Context) (DevicePrincipal, bool) {
	principal, ok := ctx.Value(devicePrincipalKey{}).(DevicePrincipal)
	return principal, ok
}

// presentedIdentity validates the handshake chain itself. It never reads headers.
func (s *Service) PresentedIdentity(r *http.Request, now time.Time) (*x509.Certificate, uuid.UUID, uuid.UUID, error) {
	if r == nil || r.TLS == nil || !r.TLS.HandshakeComplete || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.VerifiedChains[0]) == 0 || len(r.TLS.PeerCertificates) == 0 {
		return nil, uuid.Nil, uuid.Nil, rpcreason.Error(connect.CodeUnauthenticated, "unauthenticated")
	}
	leaf := r.TLS.VerifiedChains[0][0]
	if leaf == nil || !leaf.Equal(r.TLS.PeerCertificates[0]) {
		return nil, uuid.Nil, uuid.Nil, rpcreason.Error(connect.CodeUnauthenticated, "unauthenticated")
	}
	roots := x509.NewCertPool()
	roots.AddCert(s.CA)
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:       roots,
		CurrentTime: now,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		return nil, uuid.Nil, uuid.Nil, rpcreason.Error(connect.CodeUnauthenticated, "unauthenticated")
	}
	if len(leaf.URIs) != 1 || leaf.URIs[0] == nil {
		return nil, uuid.Nil, uuid.Nil, rpcreason.Error(connect.CodeUnauthenticated, "unauthenticated")
	}
	deployment, deviceID, generationID, err := pki.ParseDeviceIdentity(leaf.URIs[0].String())
	if err != nil || deployment != s.DeploymentID || pki.CheckDeviceCertificate(leaf, deployment, deviceID, generationID) != nil {
		return nil, uuid.Nil, uuid.Nil, rpcreason.Error(connect.CodeUnauthenticated, "unauthenticated")
	}
	if key, ok := leaf.PublicKey.(ed25519.PublicKey); !ok || len(key) != ed25519.PublicKeySize {
		return nil, uuid.Nil, uuid.Nil, rpcreason.Error(connect.CodeUnauthenticated, "unauthenticated")
	}
	return leaf, deviceID, generationID, nil
}

func (s *Service) BindCertificate(ctx context.Context, leaf *x509.Certificate, deviceID, generationID uuid.UUID, now time.Time) (DevicePrincipal, error) {
	sum := sha256.Sum256(leaf.Raw)
	row, err := devicedb.New(s.Pool).GetCertificateByFingerprint(ctx, sum[:])
	if err != nil {
		if err == pgx.ErrNoRows {
			return DevicePrincipal{}, rpcreason.Error(connect.CodeUnauthenticated, "unauthenticated")
		}
		return DevicePrincipal{}, MapErr(err)
	}
	if row.DeviceID != deviceID || row.GenerationID != generationID || row.CurrentGenerationID == nil || *row.CurrentGenerationID != generationID || (row.DeviceState != StatePending && row.DeviceState != StateActive) {
		return DevicePrincipal{}, ErrCertificateRejected
	}
	notBefore, ok := FiniteTime(row.NotBefore)
	if !ok || now.Before(notBefore) {
		return DevicePrincipal{}, ErrCertificateRejected
	}
	notAfter, ok := FiniteTime(row.NotAfter)
	if !ok || !now.Before(notAfter) {
		return DevicePrincipal{}, ErrCertificateRejected
	}
	switch row.Status {
	case "active":
	case "overlapping":
		until, ok := FiniteTime(row.OverlapUntil)
		if !ok || !now.Before(until) {
			return DevicePrincipal{}, ErrCertificateRejected
		}
	default:
		return DevicePrincipal{}, ErrCertificateRejected
	}
	key, ok := leaf.PublicKey.(ed25519.PublicKey)
	if !ok || len(key) != ed25519.PublicKeySize {
		return DevicePrincipal{}, ErrCertificateRejected
	}
	return DevicePrincipal{DeviceID: row.DeviceID, GenerationID: row.GenerationID, CertificateID: row.ID, Fingerprint: sum[:], PublicKey: key}, nil
}
