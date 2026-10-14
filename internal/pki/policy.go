// SPDX-License-Identifier: Apache-2.0

// Package pki holds certificate policy shared by server resources and agent trust.
package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"errors"
)

// PermitsUsage rejects unknown-only EKUs rather than interpreting them as an
// unrestricted certificate. Absence of all EKUs and explicit Any permit use.
func PermitsUsage(cert *x509.Certificate, required x509.ExtKeyUsage) bool {
	if cert == nil {
		return false
	}
	if len(cert.ExtKeyUsage) == 0 && len(cert.UnknownExtKeyUsage) == 0 {
		return true
	}
	for _, usage := range cert.ExtKeyUsage {
		if usage == x509.ExtKeyUsageAny || usage == required {
			return true
		}
	}
	return false
}

// ValidatePublicKey applies the minimum algorithm/strength policy to parsed keys.
func ValidatePublicKey(key crypto.PublicKey) error {
	switch key := key.(type) {
	case *ecdsa.PublicKey:
		if key != nil && key.Curve != nil && key.Curve.Params().BitSize >= 256 {
			return nil
		}
	case ed25519.PublicKey:
		if len(key) == ed25519.PublicKeySize {
			return nil
		}
	case *rsa.PublicKey:
		if key != nil && key.N != nil && key.N.BitLen() >= 3072 {
			return nil
		}
	}
	return errors.New("key must be Ed25519, ECDSA with at least 256 bits, or RSA with at least 3072 bits")
}
