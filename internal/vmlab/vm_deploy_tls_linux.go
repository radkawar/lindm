// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"lindm/internal/deploylab"
)

// VMDeployTLSEvidence describes public certificates, never private authority.
// The CA is retrieved through the pinned guest SSH channel, not first-use HTTPS.
type VMDeployTLSEvidence struct {
	Phase         string                      `json:"phase"`
	TrustSource   string                      `json:"trust_source"`
	ConsoleCA     VMDeployCertificateEvidence `json:"console_ca"`
	ConsoleServer VMDeployCertificateEvidence `json:"console_server"`
	DeviceCA      VMDeployCertificateEvidence `json:"device_transport_ca"`
	DeviceServer  VMDeployCertificateEvidence `json:"device_transport_server"`
	HTTPSVerified bool                        `json:"https_verified"`
}

type VMDeployCertificateEvidence struct {
	SHA256             string `json:"sha256"`
	SPKISHA256         string `json:"spki_sha256"`
	PublicKeyAlgorithm string `json:"public_key_algorithm"`
	Curve              string `json:"curve,omitempty"`
	SignatureAlgorithm string `json:"signature_algorithm"`
}

func deployCertificateEvidence(cert *x509.Certificate) VMDeployCertificateEvidence {
	digest, spki := sha256.Sum256(cert.Raw), sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	evidence := VMDeployCertificateEvidence{SHA256: hex.EncodeToString(digest[:]), SPKISHA256: hex.EncodeToString(spki[:]), PublicKeyAlgorithm: cert.PublicKeyAlgorithm.String(), SignatureAlgorithm: cert.SignatureAlgorithm.String()}
	if key, ok := cert.PublicKey.(*ecdsa.PublicKey); ok {
		evidence.Curve = key.Curve.Params().Name
	}
	return evidence
}

func parseDeployCertificate(data []byte) (*x509.Certificate, error) {
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("native generated TLS requires exactly one public PEM certificate")
	}
	return x509.ParseCertificate(block.Bytes)
}

func validateDeployTLS(ca, leaf *x509.Certificate, origin string) error {
	for _, cert := range []*x509.Certificate{ca, leaf} {
		key, ok := cert.PublicKey.(*ecdsa.PublicKey)
		if !ok || key.Curve != elliptic.P256() || cert.SignatureAlgorithm != x509.ECDSAWithSHA256 {
			return errors.New("native generated console TLS requires ECDSA P-256 and ECDSA-SHA256, not Ed25519")
		}
	}
	return validateDeployTLSChain(ca, leaf, origin)
}

// Device transport remains Ed25519; browser compatibility is an admin-only gate.
func validateDeployTLSChain(ca, leaf *x509.Certificate, origin string) error {
	if !ca.IsCA || leaf.IsCA {
		return errors.New("native generated TLS CA and leaf roles rejected")
	}
	if err := ca.CheckSignatureFrom(ca); err != nil {
		return fmt.Errorf("verify generated transport CA: %w", err)
	}
	u, err := url.Parse(origin)
	if err != nil {
		return err
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	_, err = leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: u.Hostname(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
	return err
}

// observeDeployTLS runs before any browser qualification and after each cutover.
// It retains algorithms even when qualification rejects a signed old product.
func observeDeployTLS(ctx context.Context, guest *guestVM, request *deploylab.BrowserRequest, phase string, expected *VMDeployTLSEvidence, evidence *[]*VMDeployTLSEvidence) error {
	observed := &VMDeployTLSEvidence{Phase: phase, TrustSource: "pinned-guest-ssh:/etc/lindm/console-ca.crt"}
	*evidence = append(*evidence, observed)
	certificates := make([]*x509.Certificate, 0, 4)
	for _, name := range []string{"console-ca.crt", "admin.crt", "transport-ca.crt", "server.crt"} {
		path := "/etc/lindm/" + name
		data, err := serverGuestCommand(ctx, guest, "retrieve installed public TLS certificate", "test -f "+nativeQuote(path)+"; test ! -L "+nativeQuote(path)+"; test \"$(stat -c %s "+nativeQuote(path)+")\" -le 65536; cat "+nativeQuote(path), nil)
		if err != nil {
			return err
		}
		var expectedCA string
		if expected != nil {
			switch name {
			case "console-ca.crt":
				expectedCA = expected.ConsoleCA.SHA256
			case "transport-ca.crt":
				expectedCA = expected.DeviceCA.SHA256
			}
		}
		cert, err := retainDeployTLSCertificate(request, observed, name, data, expectedCA)
		if err != nil {
			return err
		}
		certificates = append(certificates, cert)
	}
	if err := validateDeployTLS(certificates[0], certificates[1], request.Origin); err != nil {
		return err
	}
	if err := validateDeployTLSChain(certificates[2], certificates[3], request.Origin); err != nil {
		return fmt.Errorf("verify native device transport certificate: %w", err)
	}
	u, err := url.Parse(request.Origin)
	if err != nil {
		return err
	}
	roots := x509.NewCertPool()
	roots.AddCert(certificates[0])
	probe, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	trust := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: u.Hostname()}
	if err := waitDeployReadiness(probe, request.Origin, trust); err != nil {
		return err
	}
	dialer := &tls.Dialer{Config: trust}
	connection, err := dialer.DialContext(probe, "tcp", u.Host)
	if err != nil {
		return fmt.Errorf("verify native console TLS: %w", err)
	}
	defer func() { _ = connection.Close() }()
	tlsConnection, ok := connection.(*tls.Conn)
	if !ok {
		return errors.New("native console probe did not establish TLS")
	}
	peers := tlsConnection.ConnectionState().PeerCertificates
	if len(peers) == 0 || !bytes.Equal(peers[0].Raw, certificates[1].Raw) {
		return errors.New("native console did not serve the installed generated certificate")
	}
	observed.HTTPSVerified = true
	return nil
}

func retainDeployTLSCertificate(request *deploylab.BrowserRequest, observed *VMDeployTLSEvidence, name string, data []byte, expectedCA string) (*x509.Certificate, error) {
	cert, err := parseDeployCertificate(data)
	if err != nil {
		return nil, err
	}
	public := deployCertificateEvidence(cert)
	switch name {
	case "console-ca.crt", "transport-ca.crt":
		if name == "console-ca.crt" {
			observed.ConsoleCA = public
		} else {
			observed.DeviceCA = public
		}
		if expectedCA != "" && public.SHA256 != expectedCA {
			return nil, errors.New("native cutover replaced an original generated TLS CA")
		}
		path := filepath.Join(request.PrivateDirectory, name)
		if name == "console-ca.crt" {
			// Only this exact authenticated admin CA enters private browser NSS.
			path = request.CAFile
		}
		if err := os.WriteFile(path, data, 0600); err != nil {
			return nil, err
		}
	case "admin.crt":
		observed.ConsoleServer = public
	case "server.crt":
		observed.DeviceServer = public
	}
	if err := os.WriteFile(filepath.Join(request.EvidenceDirectory, observed.Phase+"-"+name), data, 0600); err != nil {
		return nil, err
	}
	return cert, nil
}
