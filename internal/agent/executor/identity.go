//go:build linux

package executor

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"io"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/pki"
	"lindm/internal/trust"
)

var (
	errKey  = errors.New("identity key binding rejected")
	errCSR  = errors.New("certificate request rejected")
	errCert = errors.New("device certificate rejected")
)

var oidSubjectAltName = asn1.ObjectIdentifier{2, 5, 29, 17}

type bound struct {
	state          *agentv1.ExecutorJournalState
	revision       int64
	bootstrap      *trust.Bootstrap
	admission      time.Time
	identityKey    ed25519.PrivateKey
	identityPublic ed25519.PublicKey
	cert           *x509.Certificate
	renewal        *boundRenewal
	prior          *boundPrior
}

type boundRenewal struct {
	id          string
	key         ed25519.PrivateKey
	public      ed25519.PublicKey
	csr         []byte
	authority   []byte
	retrieval   []byte
	epoch       uint64
	fingerprint [32]byte
}

type boundPrior struct {
	key         ed25519.PrivateKey
	public      ed25519.PublicKey
	cert        *x509.Certificate
	pem         []byte
	retain      time.Time
	fingerprint [32]byte
}

func bind(ctx context.Context, authority *trust.Authority, state *agentv1.ExecutorJournalState, now time.Time) (*bound, error) {
	if state == nil || authority == nil {
		return nil, errKey
	}
	key, public, err := consistentKey(state.GetIdentityPrivateKey())
	if err != nil {
		return nil, err
	}
	if _, err := parseCSR(state.GetEnrollmentCsrPem(), public); err != nil {
		return nil, err
	}
	admission := state.GetBootstrapVerifiedAt().AsTime()
	if admission.IsZero() || admission.After(now.Add(time.Minute)) {
		return nil, errKey
	}
	verified, err := authority.VerifyBootstrap(ctx, state.GetExecutionRootJson(), state.GetBootstrapEnvelope(), admission)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, errKey
	}
	deployment, err := canonicalUUID(verified.Root.GetDeploymentId())
	if err != nil {
		return nil, err
	}
	out := &bound{
		state:          state,
		bootstrap:      verified,
		admission:      admission,
		identityKey:    key,
		identityPublic: public,
	}
	if len(state.GetCertificatePem()) > 0 {
		device, err := canonicalUUID(state.GetDeviceId())
		if err != nil {
			return nil, err
		}
		generation, err := canonicalUUID(state.GetEnrollmentGeneration())
		if err != nil {
			return nil, err
		}
		cert, err := parsePinnedCert(state.GetCertificatePem(), public, verified.DeviceCA, deployment, device, generation)
		if err != nil {
			return nil, err
		}
		out.cert = cert
	}
	if receipt := state.GetRenewalReceipt(); receipt != nil {
		if out.cert == nil || !bytes.Equal(receipt.GetCertificateSha256(), fingerprint(out.cert)) {
			return nil, errKey
		}
		if _, err := canonicalUUID(receipt.GetIssuanceRequestId()); err != nil {
			return nil, err
		}
	}
	if receipt := state.GetSessionReceipt(); receipt != nil {
		if _, err := canonicalUUID(receipt.GetRequestId()); err != nil || receipt.GetSessionEpoch() != state.GetSessionEpoch() || state.GetSessionEpoch() == 0 {
			return nil, errKey
		}
	}
	if pending := state.GetPendingRenewal(); pending != nil {
		if out.cert == nil {
			return nil, errKey
		}
		next, nextPublic, err := consistentKey(pending.GetPrivateKey())
		if err != nil {
			return nil, err
		}
		if _, err := parseCSR(pending.GetCsrPem(), nextPublic); err != nil {
			return nil, err
		}
		if err := verifyRenewalProofs(ctx, authority, state, pending, public, nextPublic, out.cert); err != nil {
			return nil, err
		}
		out.renewal = &boundRenewal{
			id: pending.GetIssuanceRequestId(), key: next, public: nextPublic,
			csr: bytes.Clone(pending.GetCsrPem()), authority: bytes.Clone(pending.GetAuthorityProof()),
			retrieval: bytes.Clone(pending.GetRetrievalProof()), epoch: pending.GetSessionEpoch(),
			fingerprint: sha256.Sum256(out.cert.Raw),
		}
	}
	if prior := state.GetPriorCredential(); prior != nil {
		priorKey, priorPublic, err := consistentKey(prior.GetPrivateKey())
		if err != nil {
			return nil, err
		}
		device, err := canonicalUUID(state.GetDeviceId())
		if err != nil {
			return nil, err
		}
		generation, err := canonicalUUID(state.GetEnrollmentGeneration())
		if err != nil {
			return nil, err
		}
		cert, err := parsePinnedCert(prior.GetCertificatePem(), priorPublic, verified.DeviceCA, deployment, device, generation)
		if err != nil || prior.GetRetainUntil() == nil {
			return nil, errCert
		}
		out.prior = &boundPrior{
			key: priorKey, public: priorPublic, cert: cert, pem: bytes.Clone(prior.GetCertificatePem()),
			retain: prior.GetRetainUntil().AsTime(), fingerprint: sha256.Sum256(cert.Raw),
		}
	}
	if pending := state.GetPendingSession(); pending != nil {
		claim := &agentv1.SessionAcquisition{}
		if err := authority.Verify(ctx, state.GetPendingSessionProof(), claim, 1, public); err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, errKey
		}
		if !proto.Equal(claim, pending) {
			return nil, errKey
		}
	}
	return out, nil
}

func verifyRenewalProofs(ctx context.Context, authority *trust.Authority, state *agentv1.ExecutorJournalState, pending *agentv1.PendingIdentityRenewal, current, next ed25519.PublicKey, cert *x509.Certificate) error {
	intent := &agentv1.RenewalIntent{}
	if err := authority.Verify(ctx, pending.GetAuthorityProof(), intent, 1, current); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return errKey
	}
	csrHash := sha256.Sum256(pending.GetCsrPem())
	if intent.GetDeploymentId() != certDeployment(cert) || intent.GetDeviceId() != state.GetDeviceId() || intent.GetEnrollmentGeneration() != state.GetEnrollmentGeneration() || intent.GetIssuanceRequestId() != pending.GetIssuanceRequestId() || intent.GetSessionEpoch() != pending.GetSessionEpoch() || intent.GetSessionEpoch() != state.GetSessionEpoch() || !bytes.Equal(intent.GetCsrSha256(), csrHash[:]) || !bytes.Equal(intent.GetPresentedCertificateSha256(), fingerprint(cert)) {
		return errKey
	}
	retrieval := &agentv1.IssuanceRetrieval{}
	if err := authority.Verify(ctx, pending.GetRetrievalProof(), retrieval, 1, next); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return errKey
	}
	if retrieval.GetDeploymentId() != intent.GetDeploymentId() || retrieval.GetDeviceId() != intent.GetDeviceId() || retrieval.GetEnrollmentGeneration() != intent.GetEnrollmentGeneration() || retrieval.GetIssuanceRequestId() != pending.GetIssuanceRequestId() {
		return errKey
	}
	return nil
}

func certDeployment(cert *x509.Certificate) string {
	if cert == nil || len(cert.URIs) != 1 || cert.URIs[0] == nil {
		return ""
	}
	deployment, _, _, err := pki.ParseDeviceIdentity(cert.URIs[0].String())
	if err != nil {
		return ""
	}
	return deployment.String()
}

func consistentKey(raw []byte) (ed25519.PrivateKey, ed25519.PublicKey, error) {
	if len(raw) != ed25519.PrivateKeySize {
		return nil, nil, errKey
	}
	key := ed25519.PrivateKey(bytes.Clone(raw))
	if !bytes.Equal(ed25519.NewKeyFromSeed(key.Seed()), key) {
		return nil, nil, errKey
	}
	return key, ed25519.PublicKey(bytes.Clone(key[ed25519.SeedSize:])), nil
}

func newSoftwareKey(rand io.Reader) (ed25519.PrivateKey, []byte, error) {
	_, key, err := ed25519.GenerateKey(rand)
	if err != nil {
		return nil, nil, err
	}
	if _, _, err := consistentKey(key); err != nil {
		return nil, nil, err
	}
	der, err := x509.CreateCertificateRequest(rand, &x509.CertificateRequest{}, key)
	if err != nil {
		return nil, nil, err
	}
	encoded := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
	if _, err := parseCSR(encoded, ed25519.PublicKey(key[ed25519.SeedSize:])); err != nil {
		return nil, nil, err
	}
	return key, encoded, nil
}

func parseCSR(encoded []byte, expect ed25519.PublicKey) (*x509.CertificateRequest, error) {
	if len(encoded) < 64 || len(encoded) > 16384 || bytes.Contains(encoded, []byte{0}) {
		return nil, errCSR
	}
	block, rest := pem.Decode(encoded)
	if block == nil || block.Type != "CERTIFICATE REQUEST" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errCSR
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil || csr.SignatureAlgorithm != x509.PureEd25519 {
		return nil, errCSR
	}
	public, ok := csr.PublicKey.(ed25519.PublicKey)
	if !ok || !bytes.Equal(public, expect) || csr.CheckSignature() != nil || csrRequestsIdentity(csr) {
		return nil, errCSR
	}
	return csr, nil
}

func csrRequestsIdentity(csr *x509.CertificateRequest) bool {
	if len(csr.Subject.ToRDNSequence()) > 0 || len(csr.DNSNames) > 0 || len(csr.EmailAddresses) > 0 || len(csr.IPAddresses) > 0 || len(csr.URIs) > 0 {
		return true
	}
	for _, ext := range csr.Extensions {
		if ext.Id.Equal(oidSubjectAltName) {
			return true
		}
	}
	for _, ext := range csr.ExtraExtensions {
		if ext.Id.Equal(oidSubjectAltName) {
			return true
		}
	}
	return false
}

func parsePinnedCert(encoded []byte, key ed25519.PublicKey, ca *x509.Certificate, deployment, deviceID, generation uuid.UUID) (*x509.Certificate, error) {
	if len(encoded) < 64 || len(encoded) > 16384 || ca == nil {
		return nil, errCert
	}
	block, rest := pem.Decode(encoded)
	if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errCert
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, errCert
	}
	if err := pki.CheckDeviceCertificate(cert, deployment, deviceID, generation); err != nil {
		return nil, errCert
	}
	actual, ok := cert.PublicKey.(ed25519.PublicKey)
	if !ok || !bytes.Equal(actual, key) {
		return nil, errCert
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	if _, err := cert.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: cert.NotBefore, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return nil, errCert
	}
	return cert, nil
}

func canonicalUUID(text string) (uuid.UUID, error) {
	id, err := uuid.Parse(text)
	if err != nil || id == uuid.Nil || id.String() != text {
		return uuid.Nil, errCert
	}
	return id, nil
}

func fingerprint(cert *x509.Certificate) []byte {
	sum := sha256.Sum256(cert.Raw)
	return sum[:]
}

func certUsable(cert *x509.Certificate, now time.Time) bool {
	return cert != nil && !now.Before(cert.NotBefore) && now.Before(cert.NotAfter)
}

func acceptableLifetime(cert *x509.Certificate, now time.Time) error {
	if cert.NotBefore.After(now.Add(time.Minute)) || !now.Before(cert.NotAfter) {
		return errCert
	}
	if cert.NotAfter.Sub(cert.NotBefore) > 30*24*time.Hour+2*time.Minute || cert.NotAfter.Sub(now) > 30*24*time.Hour+2*time.Minute {
		return errCert
	}
	return nil
}
