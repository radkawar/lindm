// SPDX-License-Identifier: Apache-2.0

package trust

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"time"

	"github.com/theupdateframework/go-tuf/v2/metadata"
	"google.golang.org/protobuf/encoding/protojson"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/pki"
)

// Bootstrap contains verified public trust material. Callers must first acquire
// rootJSON through their authenticated installation channel and persist the
// accepted bytes and version in executor-owned state.
type Bootstrap struct {
	Root           *agentv1.ExecutionRoot
	Bundle         *agentv1.BootstrapBundle
	TransportRoots *x509.CertPool
	ConsoleRoots   *x509.CertPool
	DeviceCA       *x509.Certificate
}

// VerifyBootstrap verifies a root-quorum signed bundle and its separate trust
// domains. The caller supplies the clock; exact expiration is already expired.
func (a *Authority) VerifyBootstrap(ctx context.Context, rootJSON, envelope []byte, now time.Time) (*Bootstrap, error) {
	if len(rootJSON) == 0 || len(rootJSON) > 65536 {
		return nil, errors.New("invalid execution root size")
	}
	root := new(agentv1.ExecutionRoot)
	if err := protojson.Unmarshal(rootJSON, root); err != nil {
		return nil, errors.New("invalid execution root document")
	}
	if err := a.validator.Validate(root); err != nil {
		return nil, errors.New("invalid execution root schema")
	}
	if now.Before(root.GetNotBefore().AsTime()) || !now.Before(root.GetExpiresAt().AsTime()) {
		return nil, errors.New("execution root is not currently valid")
	}
	keys := make([]ed25519.PublicKey, 0, len(root.GetKeys()))
	executionKeys := make(map[[32]byte]struct{}, len(root.GetKeys()))
	for _, key := range root.GetKeys() {
		public := ed25519.PublicKey(key.GetPublicKey())
		id, err := KeyID(public)
		if err != nil || id != key.GetKeyId() {
			return nil, errors.New("execution root key identity mismatch")
		}
		der, err := x509.MarshalPKIXPublicKey(public)
		if err != nil {
			return nil, errors.New("invalid execution root key")
		}
		executionKeys[sha256.Sum256(der)] = struct{}{}
		keys = append(keys, public)
	}
	bundle := new(agentv1.BootstrapBundle)
	if err := a.Verify(ctx, envelope, bundle, int(root.GetThreshold()), keys...); err != nil {
		return nil, err
	}
	digest := sha256.Sum256(rootJSON)
	if bundle.GetDeploymentId() != root.GetDeploymentId() || bundle.GetExecutionRootVersion() != root.GetVersion() || !bytes.Equal(bundle.GetExecutionRootSha256(), digest[:]) {
		return nil, errors.New("bootstrap execution root binding mismatch")
	}
	if now.Before(bundle.GetNotBefore().AsTime()) || !now.Before(bundle.GetExpiresAt().AsTime()) || bundle.GetNotBefore().AsTime().Before(root.GetNotBefore().AsTime()) || bundle.GetExpiresAt().AsTime().After(root.GetExpiresAt().AsTime()) {
		return nil, errors.New("bootstrap validity exceeds current root authority")
	}
	console, err := parseCAs(bundle.GetConsoleCaPem(), now, x509.ExtKeyUsageServerAuth)
	if err != nil {
		return nil, err
	}
	transport, err := parseCAs(bundle.GetTransportCaPem(), now, x509.ExtKeyUsageServerAuth)
	if err != nil {
		return nil, err
	}
	device, err := parseCAs(bundle.GetDeviceCaPem(), now, x509.ExtKeyUsageClientAuth)
	if err != nil {
		return nil, err
	}
	if len(device) != 1 {
		return nil, errors.New("bootstrap requires one device certificate authority")
	}
	tlsKeys := make(map[[32]byte]struct{}, len(transport)+len(console)+1)
	roots := x509.NewCertPool()
	for _, cert := range transport {
		roots.AddCert(cert)
		tlsKeys[sha256.Sum256(cert.RawSubjectPublicKeyInfo)] = struct{}{}
	}
	deviceKey := sha256.Sum256(device[0].RawSubjectPublicKeyInfo)
	if _, exists := tlsKeys[deviceKey]; exists {
		return nil, errors.New("device and transport trust must use distinct keys")
	}
	tlsKeys[deviceKey] = struct{}{}
	consoleRoots := x509.NewCertPool()
	for _, cert := range console {
		consoleRoots.AddCert(cert)
		key := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
		if key == deviceKey {
			return nil, errors.New("device and console trust must use distinct keys")
		}
		// Explicit shared-issuer fixtures may pin the same CA in both server
		// domains; the pools remain separately authorized by signed fields.
		tlsKeys[key] = struct{}{}
	}
	for key := range executionKeys {
		if _, exists := tlsKeys[key]; exists {
			return nil, errors.New("execution and TLS trust must use distinct keys")
		}
	}
	if err := verifyBootstrapReleaseRoot(bundle.GetReleaseRootJson(), executionKeys, tlsKeys, now); err != nil {
		return nil, err
	}
	return &Bootstrap{Root: root, Bundle: bundle, TransportRoots: roots, ConsoleRoots: consoleRoots, DeviceCA: device[0]}, nil
}

func verifyBootstrapReleaseRoot(encoded []byte, executionKeys, tlsKeys map[[32]byte]struct{}, now time.Time) error {
	release, err := metadata.Root().FromBytes(encoded)
	if err != nil {
		return errors.New("invalid TUF release root")
	}
	if release.Signed.Type != metadata.ROOT || release.Signed.Version < 1 || !now.Before(release.Signed.Expires) {
		return errors.New("TUF release root is not currently valid")
	}
	releaseKeys := make(map[string][32]byte, len(release.Signed.Keys))
	for id, key := range release.Signed.Keys {
		if key == nil {
			return errors.New("missing TUF release key")
		}
		public, err := key.ToPublicKey()
		if err != nil {
			return errors.New("invalid TUF release key")
		}
		if err := pki.ValidatePublicKey(public); err != nil {
			return err
		}
		der, err := x509.MarshalPKIXPublicKey(public)
		if err != nil {
			return errors.New("invalid TUF release key")
		}
		digest := sha256.Sum256(der)
		if _, exists := executionKeys[digest]; exists {
			return errors.New("release and execution trust must use distinct keys")
		}
		if _, exists := tlsKeys[digest]; exists {
			return errors.New("release and TLS trust must use distinct keys")
		}
		releaseKeys[id] = digest
	}
	for _, role := range []string{"root", "targets", "snapshot", "timestamp"} {
		definition, exists := release.Signed.Roles[role]
		if !exists || definition == nil || definition.Threshold < 1 {
			return errors.New("invalid TUF release role")
		}
		unique := make(map[[32]byte]struct{}, len(definition.KeyIDs))
		for _, id := range definition.KeyIDs {
			key, exists := releaseKeys[id]
			if !exists {
				return errors.New("unknown TUF release role key")
			}
			unique[key] = struct{}{}
		}
		if definition.Threshold > len(unique) {
			return errors.New("unsatisfiable TUF release role quorum")
		}
	}
	// Validate nullable role/key objects before invoking the maintained
	// verifier; malformed metadata must return an error rather than panic.
	if err := release.VerifyDelegate(metadata.ROOT, release); err != nil {
		return errors.New("invalid TUF release root signature")
	}
	return nil
}

func parseCAs(encoded []byte, now time.Time, usage x509.ExtKeyUsage) ([]*x509.Certificate, error) {
	var certificates []*x509.Certificate
	for len(bytes.TrimSpace(encoded)) != 0 {
		encoded = bytes.TrimSpace(encoded)
		if !bytes.HasPrefix(encoded, []byte("-----BEGIN CERTIFICATE-----")) {
			return nil, errors.New("invalid bootstrap CA encoding")
		}
		block, rest := pem.Decode(encoded)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return nil, errors.New("invalid bootstrap CA encoding")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil || !cert.IsCA || !cert.BasicConstraintsValid || cert.KeyUsage&x509.KeyUsageCertSign == 0 || now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) {
			return nil, errors.New("invalid bootstrap certificate authority")
		}
		if !pki.PermitsUsage(cert, usage) {
			return nil, errors.New("bootstrap CA does not permit its intended usage")
		}
		if err := pki.ValidatePublicKey(cert.PublicKey); err != nil {
			return nil, err
		}
		// X.509 verifies signatures and EKU, while the authenticated bootstrap
		// payload establishes which public roots are initially trusted.
		roots := x509.NewCertPool()
		roots.AddCert(cert)
		if _, err := cert.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{usage}}); err != nil {
			return nil, errors.New("bootstrap CA does not permit its intended usage")
		}
		certificates = append(certificates, cert)
		if len(certificates) > 16 {
			return nil, errors.New("too many bootstrap certificate authorities")
		}
		encoded = rest
	}
	if len(certificates) == 0 {
		return nil, errors.New("missing bootstrap certificate authority")
	}
	return certificates, nil
}
