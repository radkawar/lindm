// SPDX-License-Identifier: Apache-2.0

package config

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"net/url"
)

// resolveEnrollmentTLS selects only a CA which actually verifies the configured
// administrative TLS certificate and both advertised hostnames. Outbound trust
// material is a candidate pool, never proof that an unrelated device CA is the
// HTTPS issuer. Failure disables native enrollment instructions, not air-gap use.
func (d *Document) resolveEnrollmentTLS(resources *Resources) error {
	leaf := resources.ServerCertificate.Leaf
	intermediates := x509.NewCertPool()
	var candidates []*x509.Certificate
	for _, der := range resources.ServerCertificate.Certificate[1:] {
		certificate, err := x509.ParseCertificate(der)
		if err != nil {
			return err
		}
		intermediates.AddCert(certificate)
		candidates = append(candidates, certificate)
	}
	var bundles [][]byte
	if resources.ExecutionBootstrap != nil {
		bundles = append(bundles, resources.ExecutionBootstrap.TransportCAPEM)
	}
	if name := d.Proto.GetTrustedCaFile(); name != "" {
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
	public, err := url.Parse(d.Proto.GetPublicUrl())
	if err != nil {
		return err
	}
	options := x509.VerifyOptions{DNSName: public.Hostname(), Intermediates: intermediates, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	if device := d.Proto.GetDevicePublicUrl(); device != "" {
		origin, err := url.Parse(device)
		if err != nil {
			return err
		}
		if err := leaf.VerifyHostname(origin.Hostname()); err != nil {
			resources.EnrollmentTLSUnavailable = true
			return nil
		}
	}
	// Prefer an explicit deployment CA even when the server OS also trusts it:
	// a bare enrolling machine need not share the server's local trust store.
	for _, candidate := range candidates {
		if !candidate.IsCA || candidate.CheckSignatureFrom(candidate) != nil {
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
	options.Roots = nil
	if _, err := leaf.Verify(options); err == nil {
		return nil
	}
	resources.EnrollmentTLSUnavailable = true
	return nil
}
