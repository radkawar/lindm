package pki

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
)

const deviceIdentityPrefix = "urn:lindm:device:"

// DeviceIdentityURL encodes the deployment-scoped identity minted by the server.
func DeviceIdentityURL(deployment, deviceID, generation uuid.UUID) (*url.URL, error) {
	if deployment == uuid.Nil || deviceID == uuid.Nil || generation == uuid.Nil {
		return nil, errors.New("zero device identity")
	}
	return url.Parse(deviceIdentityPrefix + deployment.String() + ":" + deviceID.String() + ":" + generation.String())
}

// ParseDeviceIdentity accepts only the canonical, nonzero deployment/device/
// generation URI. Alternate UUID spellings are not another certificate identity.
func ParseDeviceIdentity(raw string) (uuid.UUID, uuid.UUID, uuid.UUID, error) {
	rest, ok := strings.CutPrefix(raw, deviceIdentityPrefix)
	if !ok || len(rest) != 110 || rest[36] != ':' || rest[73] != ':' {
		return uuid.Nil, uuid.Nil, uuid.Nil, errors.New("invalid device identity URI")
	}
	var identities [3]uuid.UUID
	for index, text := range [3]string{rest[:36], rest[37:73], rest[74:]} {
		parsed, err := uuid.Parse(text)
		if err != nil || parsed == uuid.Nil || parsed.String() != text {
			return uuid.Nil, uuid.Nil, uuid.Nil, errors.New("invalid device identity UUID")
		}
		identities[index] = parsed
	}
	return identities[0], identities[1], identities[2], nil
}

// CheckDeviceCertificate checks the precise identity/authority shape. It does
// not establish chain trust or current validity; callers must verify those too.
func CheckDeviceCertificate(cert *x509.Certificate, deployment, deviceID, generation uuid.UUID) error {
	if cert == nil || cert.KeyUsage != x509.KeyUsageDigitalSignature || len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth || len(cert.UnknownExtKeyUsage) != 0 || !cert.BasicConstraintsValid || cert.IsCA {
		return errors.New("invalid device certificate authority")
	}
	if len(cert.DNSNames) != 0 || len(cert.EmailAddresses) != 0 || len(cert.IPAddresses) != 0 || len(cert.URIs) != 1 || cert.URIs[0] == nil {
		return errors.New("invalid device certificate names")
	}
	gotDeployment, gotDevice, gotGeneration, err := ParseDeviceIdentity(cert.URIs[0].String())
	if err != nil || gotDeployment != deployment || gotDevice != deviceID || gotGeneration != generation {
		return errors.New("device certificate identity mismatch")
	}
	if cert.Subject.CommonName != deviceID.String() || len(cert.Subject.ToRDNSequence()) != 1 {
		return errors.New("invalid device certificate subject")
	}
	return nil
}

// VerifyDeviceCertificatePEM binds the authenticated response to the executor's
// protected key and expected identity. Only one leaf is accepted; the trusted
// issuer is supplied by the already verified bootstrap, never by this response.
func VerifyDeviceCertificatePEM(encoded []byte, key ed25519.PublicKey, ca *x509.Certificate, deployment, deviceID, generation uuid.UUID, now time.Time) (*x509.Certificate, error) {
	if len(encoded) == 0 || len(encoded) > 16384 || len(key) != ed25519.PublicKeySize || ca == nil {
		return nil, errors.New("invalid device certificate input")
	}
	block, rest := pem.Decode(encoded)
	if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("expected one device certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, errors.New("invalid device certificate")
	}
	if err := CheckDeviceCertificate(cert, deployment, deviceID, generation); err != nil {
		return nil, err
	}
	actual, ok := cert.PublicKey.(ed25519.PublicKey)
	if !ok || !bytes.Equal(actual, key) {
		return nil, errors.New("device certificate does not bind protected key")
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	if _, err := cert.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return nil, errors.New("device certificate chain or validity rejected")
	}
	if !now.Before(cert.NotAfter) {
		return nil, errors.New("device certificate expired")
	}
	return cert, nil
}
