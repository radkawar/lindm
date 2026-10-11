package device

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

type devicePrincipal struct {
	DeviceID      uuid.UUID
	GenerationID  uuid.UUID
	CertificateID uuid.UUID
	Fingerprint   []byte
	PublicKey     ed25519.PublicKey
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
		return nil, uuid.Nil, uuid.Nil, rpcreason.Error(connect.CodeUnauthenticated, "unauthenticated")
	}
	leaf := r.TLS.VerifiedChains[0][0]
	if leaf == nil || !leaf.Equal(r.TLS.PeerCertificates[0]) {
		return nil, uuid.Nil, uuid.Nil, rpcreason.Error(connect.CodeUnauthenticated, "unauthenticated")
	}
	roots := x509.NewCertPool()
	roots.AddCert(s.ca)
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
	if err != nil || deployment != s.deploymentID || pki.CheckDeviceCertificate(leaf, deployment, deviceID, generationID) != nil {
		return nil, uuid.Nil, uuid.Nil, rpcreason.Error(connect.CodeUnauthenticated, "unauthenticated")
	}
	if key, ok := leaf.PublicKey.(ed25519.PublicKey); !ok || len(key) != ed25519.PublicKeySize {
		return nil, uuid.Nil, uuid.Nil, rpcreason.Error(connect.CodeUnauthenticated, "unauthenticated")
	}
	return leaf, deviceID, generationID, nil
}

func (s *Service) bindCertificate(ctx context.Context, leaf *x509.Certificate, deviceID, generationID uuid.UUID, now time.Time) (devicePrincipal, error) {
	sum := sha256.Sum256(leaf.Raw)
	row, err := devicedb.New(s.pool).GetCertificateByFingerprint(ctx, sum[:])
	if err != nil {
		if err == pgx.ErrNoRows {
			return devicePrincipal{}, rpcreason.Error(connect.CodeUnauthenticated, "unauthenticated")
		}
		return devicePrincipal{}, mapErr(err)
	}
	if row.DeviceID != deviceID || row.GenerationID != generationID || row.CurrentGenerationID == nil || *row.CurrentGenerationID != generationID || (row.DeviceState != statePending && row.DeviceState != stateActive) {
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
	key, ok := leaf.PublicKey.(ed25519.PublicKey)
	if !ok || len(key) != ed25519.PublicKeySize {
		return devicePrincipal{}, errCertificateRejected
	}
	return devicePrincipal{DeviceID: row.DeviceID, GenerationID: row.GenerationID, CertificateID: row.ID, Fingerprint: sum[:], PublicKey: key}, nil
}
