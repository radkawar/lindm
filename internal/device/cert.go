package device

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"math/big"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
)

const (
	certLifetime   = 30 * 24 * time.Hour
	renewalOverlap = 15 * time.Minute
	notBeforeSkew  = time.Minute
	identityPrefix = "urn:lindm:device:"
)

var (
	errCSR          = errors.New("csr rejected")
	errCSRAlgorithm = errors.New("csr algorithm")
	errCSRSignature = errors.New("csr signature")
	errCSRIdentity  = errors.New("csr identity")
	errCAWindow     = errors.New("certificate authority window")

	oidSubjectAltName = asn1.ObjectIdentifier{2, 5, 29, 17}
)

type issuedCert struct {
	PEM                  []byte
	Serial               []byte
	Fingerprint          []byte
	PublicKeyFingerprint []byte
	NotBefore            time.Time
	NotAfter             time.Time
	ID                   uuid.UUID
}

func parseDeviceCSR(pemBytes []byte) (*x509.CertificateRequest, error) {
	if len(pemBytes) == 0 || bytesContainsNUL(pemBytes) {
		return nil, errCSR
	}
	block, rest := pem.Decode(pemBytes)
	if block == nil || block.Type != "CERTIFICATE REQUEST" || len(bytesTrimSpace(rest)) > 0 {
		return nil, errCSR
	}
	if len(block.Bytes) == 0 || len(block.Bytes) > 16*1024 {
		return nil, errCSR
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, errCSR
	}
	if err := validateCSR(csr); err != nil {
		return nil, err
	}
	return csr, nil
}

func validateCSR(csr *x509.CertificateRequest) error {
	switch csr.SignatureAlgorithm {
	case x509.ECDSAWithSHA256:
		pub, ok := csr.PublicKey.(*ecdsa.PublicKey)
		if !ok || pub == nil || pub.Curve != elliptic.P256() {
			return errCSRAlgorithm
		}
	case x509.PureEd25519:
		pub, ok := csr.PublicKey.(ed25519.PublicKey)
		if !ok || len(pub) != ed25519.PublicKeySize {
			return errCSRAlgorithm
		}
	default:
		return errCSRAlgorithm
	}
	if err := csr.CheckSignature(); err != nil {
		return errCSRSignature
	}
	if csrRequestsIdentity(csr) {
		return errCSRIdentity
	}
	return nil
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

func publicKeyFingerprint(pub crypto.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(der)
	return sum[:], nil
}

func issueCertificate(ca *x509.Certificate, caKey crypto.Signer, pub crypto.PublicKey, deployment, deviceID, generation uuid.UUID, now time.Time) (*issuedCert, error) {
	notBefore, notAfter, err := certificateWindow(now, ca)
	if err != nil {
		return nil, err
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	identity, err := deviceIdentityURL(deployment, deviceID, generation)
	if err != nil {
		return nil, err
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: deviceID.String()},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		URIs:                  []*url.URL{identity},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, pub, caKey)
	if err != nil {
		return nil, err
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	if err := issuedIdentityOK(parsed, deployment, deviceID, generation); err != nil {
		return nil, err
	}
	sum := sha256.Sum256(parsed.Raw)
	keyHash, err := publicKeyFingerprint(pub)
	if err != nil {
		return nil, err
	}
	return &issuedCert{
		PEM:                  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: parsed.Raw}),
		Serial:               append([]byte(nil), parsed.SerialNumber.Bytes()...),
		Fingerprint:          sum[:],
		PublicKeyFingerprint: keyHash,
		NotBefore:            parsed.NotBefore.UTC(),
		NotAfter:             parsed.NotAfter.UTC(),
	}, nil
}

func certificateWindow(now time.Time, ca *x509.Certificate) (time.Time, time.Time, error) {
	if ca == nil || now.Before(ca.NotBefore) {
		return time.Time{}, time.Time{}, errCAWindow
	}
	notBefore := now.Add(-notBeforeSkew).UTC().Truncate(time.Second)
	notAfter := now.Add(certLifetime).UTC().Truncate(time.Second)
	caEnd := ca.NotAfter.UTC().Truncate(time.Second)
	if caEnd.Before(notAfter) {
		notAfter = caEnd
	}
	if !notAfter.After(now.Add(time.Minute)) {
		return time.Time{}, time.Time{}, errCAWindow
	}
	return notBefore, notAfter, nil
}

func overlapUntil(now, certNotAfter time.Time) time.Time {
	until := now.Add(renewalOverlap)
	if certNotAfter.Before(until) {
		return certNotAfter
	}
	return until
}

func randomSerial() (*big.Int, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return nil, err
	}
	buf[0] &= 0x7f
	if buf[0] == 0 {
		buf[0] = 1
	}
	return new(big.Int).SetBytes(buf), nil
}

func deviceIdentityURL(deployment, deviceID, generation uuid.UUID) (*url.URL, error) {
	raw := identityPrefix + deployment.String() + ":" + deviceID.String() + ":" + generation.String()
	u, err := url.Parse(raw)
	if err != nil || u.String() != raw {
		return nil, errors.New("identity")
	}
	return u, nil
}

func parseIdentity(raw string) (uuid.UUID, uuid.UUID, uuid.UUID, error) {
	rest, ok := strings.CutPrefix(raw, identityPrefix)
	if !ok {
		return uuid.Nil, uuid.Nil, uuid.Nil, errors.New("identity")
	}
	parts := strings.Split(rest, ":")
	if len(parts) != 3 {
		return uuid.Nil, uuid.Nil, uuid.Nil, errors.New("identity")
	}
	deployment, err := uuid.Parse(parts[0])
	if err != nil {
		return uuid.Nil, uuid.Nil, uuid.Nil, err
	}
	deviceID, err := uuid.Parse(parts[1])
	if err != nil {
		return uuid.Nil, uuid.Nil, uuid.Nil, err
	}
	generation, err := uuid.Parse(parts[2])
	if err != nil || deployment == uuid.Nil || deviceID == uuid.Nil || generation == uuid.Nil {
		return uuid.Nil, uuid.Nil, uuid.Nil, errors.New("identity")
	}
	return deployment, deviceID, generation, nil
}

func issuedIdentityOK(cert *x509.Certificate, deployment, deviceID, generation uuid.UUID) error {
	if cert == nil || cert.KeyUsage != x509.KeyUsageDigitalSignature || len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth || len(cert.UnknownExtKeyUsage) != 0 || !cert.BasicConstraintsValid || cert.IsCA {
		return errors.New("issued certificate authority")
	}
	if len(cert.DNSNames) != 0 || len(cert.EmailAddresses) != 0 || len(cert.IPAddresses) != 0 || len(cert.URIs) != 1 {
		return errors.New("issued certificate name")
	}
	gotDeployment, gotDevice, gotGeneration, err := parseIdentity(cert.URIs[0].String())
	if err != nil || gotDeployment != deployment || gotDevice != deviceID || gotGeneration != generation {
		return errors.New("issued certificate identity")
	}
	if cert.Subject.CommonName != deviceID.String() || len(cert.Subject.ToRDNSequence()) != 1 {
		return errors.New("issued certificate subject")
	}
	return nil
}

func bytesContainsNUL(b []byte) bool {
	for _, c := range b {
		if c == 0 {
			return true
		}
	}
	return false
}

func bytesTrimSpace(b []byte) []byte {
	return []byte(strings.TrimSpace(string(b)))
}
