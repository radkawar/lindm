// SPDX-License-Identifier: Apache-2.0

//go:build linux

package install

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
	"net/url"
	"time"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/pki"
)

// Go's maintained x509 implementation issues the certificates. Offline CA keys
// exist only in locked process memory and their custodian-encrypted artifact.
func certificates(ctx context.Context, o Options, deployment string, uid, gid, pguid, pggid int, custody *authorityCustody) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	device, deviceKey, err := newCertificateAuthority("Lindm device CA " + deployment)
	if err != nil {
		return err
	}
	defer clear(deviceKey)
	sealed := &agentv1.ServerRecoveryPKIExport{DeploymentId: deployment, PublicUrl: o.Origin, DevicePublicUrl: o.DeviceOrigin}
	if o.TLSCertificate != "" {
		cert, err := protected(o.TLSCertificate, false)
		if err != nil {
			return err
		}
		key, err := protected(o.TLSKey, true)
		if err != nil {
			return err
		}
		defer clear(key)
		ca, err := protected(o.TLSCA, false)
		if err != nil {
			return err
		}
		if err := validateBringOwnConsoleTLS(cert, key, ca, o.Origin); err != nil {
			return err
		}
		if err := newFile("/etc/lindm/admin.crt", cert, uid, gid, 0600); err != nil {
			return err
		}
		if err := newFile("/etc/lindm/admin.key", key, uid, gid, 0600); err != nil {
			return err
		}
		if err := newFile("/etc/lindm/console-ca.crt", ca, uid, gid, 0600); err != nil {
			return err
		}
		sealed.ConsoleCaPem = ca
	} else {
		ca, key, err := newTLSCertificateAuthority("Lindm console CA " + deployment)
		if err != nil {
			return err
		}
		if err := writeCertificate("/etc/lindm/console-ca.crt", ca, uid, gid); err != nil {
			return err
		}
		sealed.ConsoleCaPem = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw})
		sealed.ConsolePrivateKeyPem, err = privateKeyPEM(key)
		if err != nil {
			return err
		}
		defer clear(sealed.ConsolePrivateKeyPem)
		u, _ := url.Parse(o.Origin)
		if err := issueAdminServerCertificate("/etc/lindm/admin", "Lindm console", []string{u.Hostname()}, ca, key, uid, gid); err != nil {
			return err
		}
	}
	if err := writeCertificate("/etc/lindm/device-ca.crt", device, uid, gid); err != nil {
		return err
	}
	if err := writeKey("/etc/lindm/device-ca.key", deviceKey, uid, gid); err != nil {
		return err
	}
	transport, transportKey, err := newCertificateAuthority("Lindm transport CA " + deployment)
	if err != nil {
		return err
	}
	defer clear(transportKey)
	if err := writeCertificate("/etc/lindm/transport-ca.crt", transport, uid, gid); err != nil {
		return err
	}
	sealed.TransportCaPem = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: transport.Raw})
	sealed.TransportPrivateKeyPem, err = privateKeyPEM(transportKey)
	if err != nil {
		return err
	}
	defer clear(sealed.TransportPrivateKeyPem)
	deviceOrigin, _ := url.Parse(o.DeviceOrigin)
	if err := issueServerCertificate("/etc/lindm/server", "Lindm device server", []string{deviceOrigin.Hostname()}, transport, transportKey, uid, gid); err != nil {
		return err
	}
	if pguid != 0 {
		ca, key, err := newDatabaseCertificateAuthority("Lindm database CA " + deployment)
		if err != nil {
			return err
		}
		if err := writeCertificate("/etc/lindm/database-ca.crt", ca, uid, gid); err != nil {
			return err
		}
		sealed.DatabaseCaPem = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw})
		sealed.DatabasePrivateKeyPem, err = privateKeyPEM(key)
		if err != nil {
			return err
		}
		defer clear(sealed.DatabasePrivateKeyPem)
		if err := issueAdminServerCertificate("/etc/lindm/postgresql/server", "Lindm PostgreSQL", []string{"localhost", "127.0.0.1", "::1"}, ca, key, pguid, pggid); err != nil {
			return err
		}
	}
	return custody.sealPKI(sealed)
}

// Verify all imported browser-facing inputs before publishing any TLS files.
func validateBringOwnConsoleTLS(cert, key, ca []byte, origin string) error {
	pair, err := tls.X509KeyPair(cert, key)
	if err != nil {
		return errors.New("bring-own TLS key pair rejected")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return err
	}
	if err := validateConsoleTLSLeaf(leaf); err != nil {
		return err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return errors.New("bring-own TLS approved roots rejected")
	}
	intermediates := x509.NewCertPool()
	for _, der := range pair.Certificate[1:] {
		certificate, err := x509.ParseCertificate(der)
		if err != nil {
			return err
		}
		intermediates.AddCert(certificate)
	}
	u, _ := url.Parse(origin)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, DNSName: u.Hostname(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		return errors.New("bring-own TLS chain, names or validity rejected")
	}
	return nil
}

func validateConsoleTLSLeaf(leaf *x509.Certificate) error {
	if leaf.PublicKeyAlgorithm == x509.Ed25519 || leaf.SignatureAlgorithm == x509.PureEd25519 {
		return errors.New("bring-own console TLS requires browser-compatible certificate and issuer algorithms; Ed25519 is unsupported")
	}
	return pki.ValidatePublicKey(leaf.PublicKey)
}

func newCertificateAuthority(name string) (*x509.Certificate, ed25519.PrivateKey, error) {
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	cert, err := createCertificateAuthority(name, public, key)
	if err != nil {
		clear(key)
		return nil, nil, err
	}
	return cert, key, nil
}

// Browser-facing TLS requires P-256 and hash-defined signatures.
// Go owns the ECDSA key internals; the installer's whole-process locked,
// non-dumpable memory gate protects them. Explicit PKCS8/PEM buffers are cleared.
func newTLSCertificateAuthority(name string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	cert, err := createCertificateAuthority(name, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	return cert, key, nil
}

// PostgreSQL SCRAM-PLUS also requires a hash-defined issuer signature.
func newDatabaseCertificateAuthority(name string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	return newTLSCertificateAuthority(name)
}

func createCertificateAuthority(name string, public crypto.PublicKey, key crypto.Signer) (*x509.Certificate, error) {
	serial, err := certificateSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: name}, NotBefore: now.Add(-time.Minute), NotAfter: now.AddDate(10, 0, 0), BasicConstraintsValid: true, IsCA: true, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, key)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

func certificateSerial() (*big.Int, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	if serial.Sign() == 0 {
		return nil, errors.New("certificate serial entropy invalid")
	}
	return serial, nil
}

func writeCertificate(path string, cert *x509.Certificate, uid, gid int) error {
	return newFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}), uid, gid, 0600)
}

func privateKeyPEM(key crypto.Signer) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	defer clear(der)
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

func issueAdminServerCertificate(path, name string, hosts []string, ca *x509.Certificate, caKey crypto.Signer, uid, gid int) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	return writeServerCertificate(path, name, hosts, ca, caKey, &key.PublicKey, key, uid, gid)
}

func issueServerCertificate(path, name string, hosts []string, ca *x509.Certificate, caKey crypto.Signer, uid, gid int) error {
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	defer clear(key)
	return writeServerCertificate(path, name, hosts, ca, caKey, public, key, uid, gid)
}

func writeServerCertificate(path, name string, hosts []string, ca *x509.Certificate, caKey crypto.Signer, public crypto.PublicKey, key crypto.Signer, uid, gid int) error {
	serial, err := certificateSerial()
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: name}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(397 * 24 * time.Hour), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	for _, host := range hosts {
		if ip := net.ParseIP(host); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, host)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, public, caKey)
	if err != nil {
		return err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return err
	}
	if err := writeCertificate(path+".crt", cert, uid, gid); err != nil {
		return err
	}
	return writeKey(path+".key", key, uid, gid)
}
