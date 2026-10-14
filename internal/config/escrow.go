// SPDX-License-Identifier: Apache-2.0

package config

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"

	"lindm/internal/escrow"
)

func (d *Document) escrowCustody() (*escrow.Custody, error) {
	cfg := d.Proto.GetEscrow()
	if cfg == nil {
		return nil, nil
	}
	transportPath := reference(d.base, cfg.GetTransportKeyFile())
	wrappingPath := reference(d.base, cfg.GetWrappingKeyFile())
	if transportPath == wrappingPath {
		return nil, errors.New("escrow keys require separate files")
	}
	encoded, err := readFile(transportPath, true)
	if err != nil {
		return nil, fmt.Errorf("read escrow.transport_key_file: %w", err)
	}
	defer clear(encoded)
	trimmed := bytes.TrimSpace(encoded)
	if !bytes.HasPrefix(trimmed, []byte("-----BEGIN PRIVATE KEY-----")) || bytes.Count(trimmed, []byte("-----BEGIN ")) != 1 || bytes.Count(trimmed, []byte("-----END ")) != 1 {
		return nil, errors.New("escrow transport key must be one unencrypted PKCS#8 RSA PRIVATE KEY")
	}
	block, rest := pem.Decode(trimmed)
	if block == nil || block.Type != "PRIVATE KEY" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("escrow transport key must be one unencrypted PKCS#8 RSA PRIVATE KEY")
	}
	defer clear(block.Bytes)
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("escrow transport key is not valid PKCS#8")
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("escrow transport key must be RSA")
	}
	wrapping, err := readFile(wrappingPath, true)
	if err != nil {
		return nil, fmt.Errorf("read escrow.wrapping_key_file: %w", err)
	}
	defer clear(wrapping)
	return escrow.New(key, wrapping)
}
