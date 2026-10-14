// SPDX-License-Identifier: Apache-2.0

package devlab

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/config"
)

// ConnectivityProbeAuthority is the public material a disposable lab device
// and its dedicated probe peer are root-provisioned with. The peer key pair is
// a fresh server leaf; no shared CA key leaves the development fixture.
type ConnectivityProbeAuthority struct {
	DeploymentID string
	// ConfirmationPublicKey verifies the server's DSSE connectivity
	// confirmation; it is the configured execution start key's public half.
	ConfirmationPublicKey ed25519.PublicKey
	// The peer leaf is issued by the shared transport CA for exactly one IP.
	PeerCertificatePEM, PeerKeyPEM, DeviceCAPEM []byte
}

// ConfigureConnectivityProbes pins the exact probe targets into the private
// server configured by ConfigureServiceDispatch and restarts it. Targets must
// byte-equal the device guard and peer configuration; the server validates
// count, signing and peer roles when it loads the configuration.
func (f *AuthorityFixture) ConfigureConnectivityProbes(ctx context.Context, targets []*agentv1.ConnectivityProbeTarget, peer netip.Addr) (*ConnectivityProbeAuthority, error) {
	if f.closed || !peer.IsValid() || peer.Zone() != "" {
		return nil, errors.New("connectivity probes require an open fixture and one peer address")
	}
	document, err := config.Load(f.configPath())
	if err != nil {
		return nil, err
	}
	signing := document.Proto.GetExecutionSigning()
	if signing == nil || len(document.Proto.GetConnectivityProbes()) != 0 {
		return nil, errors.New("connectivity probes require configured execution signing and no prior targets")
	}
	start, err := os.ReadFile(filepath.Join(f.directory, signing.GetStartKeyFile()))
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(start)
	clear(start)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, errors.New("execution start key is not one PKCS8 PEM")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	clear(block.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("execution start key is not Ed25519")
	}
	// An Ed25519 private key is seed||public key.
	authority := &ConnectivityProbeAuthority{DeploymentID: document.Proto.GetDeploymentId(), ConfirmationPublicKey: append(ed25519.PublicKey(nil), key[ed25519.SeedSize:]...)}
	clear(key)
	shared := FixturePath(f.repository)
	authority.DeviceCAPEM, err = os.ReadFile(filepath.Join(shared, "device-ca.crt"))
	if err != nil {
		return nil, err
	}
	authority.PeerCertificatePEM, authority.PeerKeyPEM, err = issueProbePeerLeaf(shared, peer)
	if err != nil {
		return nil, err
	}
	document.Proto.ConnectivityProbes = make([]*agentv1.ConnectivityProbeTarget, len(targets))
	for i, target := range targets {
		document.Proto.ConnectivityProbes[i] = proto.CloneOf(target)
	}
	encoded, err := protojson.Marshal(document.Proto)
	if err != nil {
		return nil, err
	}
	if err := f.writeConfig(encoded); err != nil {
		return nil, err
	}
	if _, err := config.Load(f.configPath()); err != nil {
		return nil, err
	}
	if err := f.Restart(ctx); err != nil {
		return nil, err
	}
	return authority, nil
}

// issueProbePeerLeaf signs a short-lived ServerAuth leaf for one IP literal
// origin with the shared transport CA, which enrolled devices already trust.
func issueProbePeerLeaf(shared string, peer netip.Addr) (certificatePEM, keyPEM []byte, err error) {
	ca, err := tls.LoadX509KeyPair(filepath.Join(shared, "transport-ca.crt"), filepath.Join(shared, "transport-ca.key"))
	if err != nil {
		return nil, nil, err
	}
	signer, ok := ca.PrivateKey.(crypto.Signer)
	if !ok || ca.Leaf == nil || !ca.Leaf.IsCA {
		return nil, nil, errors.New("shared transport CA is unusable")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: "lindm lab connectivity probe peer"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{peer.AsSlice()}, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.Leaf, &key.PublicKey, signer)
	if err != nil {
		return nil, nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	defer clear(keyDER)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), nil
}
