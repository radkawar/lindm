// SPDX-License-Identifier: Apache-2.0

package pki

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
)

// IsReleaseCAAnchor admits explicit CA certificates and legacy self-signed
// roots without basic constraints. An explicit CA:false always refuses, even
// for a self-signed certificate. This is anchor selection, not chain validation.
func IsReleaseCAAnchor(certificate *x509.Certificate) bool {
	if certificate == nil {
		return false
	}
	if certificate.BasicConstraintsValid {
		return certificate.IsCA
	}
	return bytes.Equal(certificate.RawSubject, certificate.RawIssuer) && certificate.CheckSignature(certificate.SignatureAlgorithm, certificate.RawTBSCertificate, certificate.Signature) == nil
}

// SelectReleaseCARoots removes non-CA entries from explicitly selected public
// trust material. It returns skipped certificates for operator-visible warnings;
// only accepted certificate bytes are exported and independently pinned. Invalid
// PEM/X.509 is rejected, and a bundle without usable anchors fails closed.
func SelectReleaseCARoots(data []byte) (selected []byte, skipped []*x509.Certificate, err error) {
	if len(data) == 0 || len(data) > 4<<20 {
		return nil, nil, errors.New("release CA source must contain 1..4194304 bytes")
	}
	remaining := bytes.TrimSpace(data)
	count := 0
	for len(remaining) > 0 {
		if !bytes.HasPrefix(remaining, []byte("-----BEGIN CERTIFICATE-----")) {
			return nil, nil, errors.New("release CA source must contain only certificate PEM blocks")
		}
		block, rest := pem.Decode(remaining)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return nil, nil, errors.New("invalid release CA certificate PEM")
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, nil, err
		}
		count++
		if count > 1024 {
			return nil, nil, errors.New("release CA source has more than 1024 certificates")
		}
		if IsReleaseCAAnchor(certificate) {
			selected = append(selected, pem.EncodeToMemory(block)...)
		} else {
			skipped = append(skipped, certificate)
		}
		remaining = bytes.TrimSpace(rest)
	}
	if len(selected) == 0 {
		return nil, skipped, errors.New("release CA source contains no usable CA certificates")
	}
	return selected, skipped, nil
}
