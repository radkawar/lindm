// SPDX-License-Identifier: Apache-2.0

package config

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"time"

	"lindm/internal/pki"
)

func (d *Document) resolveListenerTLS(resources *Resources) error {
	cfg := d.Proto
	if (cfg.GetAdminTls() != nil) != (cfg.AdminCaFile != nil) {
		return errors.New("admin_tls and admin_ca_file must be configured together")
	}
	deviceOrigin := cfg.GetDevicePublicUrl()
	if deviceOrigin == "" {
		deviceOrigin = cfg.GetPublicUrl()
	}
	deviceURL, err := url.Parse(deviceOrigin)
	if err != nil {
		return fmt.Errorf("parse device TLS origin: %w", err)
	}
	if err := resources.ServerCertificate.Leaf.VerifyHostname(deviceURL.Hostname()); err != nil {
		return fmt.Errorf("tls certificate does not cover device origin: %w", err)
	}
	if !pki.PermitsUsage(resources.ServerCertificate.Leaf, x509.ExtKeyUsageServerAuth) {
		return errors.New("tls certificate must permit server authentication")
	}
	resources.AdminServerCertificate = resources.ServerCertificate
	publicURL, err := url.Parse(cfg.GetPublicUrl())
	if err != nil {
		return fmt.Errorf("parse public_url: %w", err)
	}
	admin := cfg.GetAdminTls()
	if admin == nil {
		if err := resources.AdminServerCertificate.Leaf.VerifyHostname(publicURL.Hostname()); err != nil {
			return fmt.Errorf("shared tls certificate does not cover public_url: %w", err)
		}
		return validateAdminTLS(resources.AdminServerCertificate.Leaf)
	}
	pair, err := keyPair(d.base, admin.GetCertificateFile(), admin.GetPrivateKeyFile())
	if err != nil {
		return fmt.Errorf("load admin_tls certificate: %w", err)
	}
	encoded, err := readFile(reference(d.base, cfg.GetAdminCaFile()), false)
	if err != nil {
		return fmt.Errorf("read admin_ca_file: %w", err)
	}
	block, rest := pem.Decode(encoded)
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		return errors.New("admin_ca_file must contain exactly one PEM CA certificate")
	}
	ca, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("parse admin_ca_file: %w", err)
	}
	if !ca.IsCA || !ca.BasicConstraintsValid || ca.KeyUsage&x509.KeyUsageCertSign == 0 {
		return errors.New("admin_ca_file must be a certificate-signing CA")
	}
	if err := pki.ValidatePublicKey(ca.PublicKey); err != nil {
		return fmt.Errorf("admin_ca_file public key: %w", err)
	}
	now := time.Now()
	if now.Before(ca.NotBefore) || !now.Before(ca.NotAfter) {
		return errors.New("admin_ca_file certificate is not currently valid")
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	intermediates := x509.NewCertPool()
	for _, der := range pair.Certificate[1:] {
		certificate, err := x509.ParseCertificate(der)
		if err != nil {
			return fmt.Errorf("parse admin_tls intermediate: %w", err)
		}
		intermediates.AddCert(certificate)
	}
	if _, err := pair.Leaf.Verify(x509.VerifyOptions{
		Roots: roots, Intermediates: intermediates, DNSName: publicURL.Hostname(),
		CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		return fmt.Errorf("admin_tls does not satisfy public_url and admin_ca_file: %w", err)
	}
	if !pki.PermitsUsage(pair.Leaf, x509.ExtKeyUsageServerAuth) {
		return errors.New("admin_tls certificate must permit server authentication")
	}
	resources.AdminServerCertificate = pair
	resources.AdminCACertificate = ca
	return validateAdminTLS(resources.AdminServerCertificate.Leaf)
}

// Browser compatibility applies to the final console identity, including an
// intentionally shared identity. Device TLS independently permits Ed25519.
func validateAdminTLS(certificate *x509.Certificate) error {
	if certificate.PublicKeyAlgorithm == x509.Ed25519 || certificate.SignatureAlgorithm == x509.PureEd25519 {
		return errors.New("admin_tls certificate is not browser-compatible: Ed25519 public keys and issuer signatures are unsupported; use ECDSA or RSA")
	}
	return nil
}
