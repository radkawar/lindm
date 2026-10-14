// SPDX-License-Identifier: Apache-2.0

package config

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"net/url"
)

// resolveEnrollmentTLS projects the approved HTTPS issuer for native package
// downloads from public_url. This is console-origin download trust, not the
// device transport pin. Failure disables native enrollment instructions, not
// air-gap use; unrelated outbound or device-client CAs never authorize it.
func (d *Document) resolveEnrollmentTLS(resources *Resources) error {
	pair := resources.AdminServerCertificate
	if d.Proto.GetAdminTls() == nil && len(pair.Certificate) == 0 {
		pair = resources.ServerCertificate
	}
	leaf := pair.Leaf
	intermediates := x509.NewCertPool()
	var candidates []*x509.Certificate
	signed := resources.ExecutionBootstrap != nil
	if !signed && resources.AdminCACertificate != nil {
		candidates = append(candidates, resources.AdminCACertificate)
	}
	for _, der := range pair.Certificate[1:] {
		certificate, err := x509.ParseCertificate(der)
		if err != nil {
			return err
		}
		intermediates.AddCert(certificate)
		if !signed {
			candidates = append(candidates, certificate)
		}
	}
	var bundles [][]byte
	if resources.ExecutionBootstrap != nil {
		bundles = append(bundles, resources.ExecutionBootstrap.ConsoleCAPEM)
	}
	if name := d.Proto.GetTrustedCaFile(); !signed && name != "" {
		encoded, err := readFile(reference(d.base, name), false)
		if err != nil {
			return err
		}
		bundles = append(bundles, encoded)
	}
	for _, encoded := range bundles {
		for len(encoded) != 0 {
			block, rest := pem.Decode(encoded)
			if block == nil {
				break
			}
			encoded = rest
			if block.Type != "CERTIFICATE" {
				continue
			}
			certificate, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return err
			}
			candidates = append(candidates, certificate)
			intermediates.AddCert(certificate)
		}
	}
	endpoint, err := url.Parse(d.Proto.GetPublicUrl())
	if err != nil {
		return err
	}
	options := x509.VerifyOptions{DNSName: endpoint.Hostname(), Intermediates: intermediates, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	// Prefer an explicit deployment CA even when the server OS also trusts it:
	// a bare enrolling machine need not share the server's local trust store.
	for _, candidate := range candidates {
		if !candidate.IsCA || (candidate != resources.AdminCACertificate && candidate.CheckSignatureFrom(candidate) != nil) {
			continue
		}
		roots := x509.NewCertPool()
		roots.AddCert(candidate)
		options.Roots = roots
		if _, err := leaf.Verify(options); err != nil {
			continue
		}
		resources.EnrollmentTLSCAPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: candidate.Raw}))
		digest := sha256.Sum256(candidate.Raw)
		resources.EnrollmentTLSCASHA256 = hex.EncodeToString(digest[:])
		return nil
	}
	if !signed {
		options.Roots = nil
		if _, err := leaf.Verify(options); err == nil {
			return nil
		}
	}
	resources.EnrollmentTLSUnavailable = true
	return nil
}
