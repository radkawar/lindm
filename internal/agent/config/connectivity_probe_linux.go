// SPDX-License-Identifier: Apache-2.0

//go:build linux

package config

import (
	"bytes"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/pki"
)

func resolveConnectivityProbe(base string, configuration *agentv1.ConnectivityProbeServerConfig) error {
	if configuration == nil {
		return nil
	}
	for _, path := range []*string{&configuration.TlsCertificateFile, &configuration.TlsPrivateKeyFile, &configuration.DeviceCaFile, &configuration.ProofKeyFile} {
		*path = resolve(base, *path)
		if !filepath.IsAbs(*path) || filepath.Clean(*path) != *path {
			return errors.New("connectivity probe credential path must be canonical")
		}
	}
	return nil
}

// ConnectivityProbeTLS opens only provisioned root-owned file descriptors. It
// never puts keys in argv, environment, public evidence, or the device process.
// The caller must clear the returned private proof key after server construction.
func (d *Document) ConnectivityProbeTLS() (configuration *tls.Config, proofKey ed25519.PrivateKey, err error) {
	if d == nil || d.Proto.GetConnectivityProbe() == nil || os.Geteuid() != 0 {
		return nil, nil, errors.New("connectivity probe requires root provisioning")
	}
	cfg := d.Proto.GetConnectivityProbe()
	certificate, err := readProbeCredential(cfg.GetTlsCertificateFile(), false)
	if err != nil {
		return nil, nil, err
	}
	private, err := readProbeCredential(cfg.GetTlsPrivateKeyFile(), true)
	if err != nil {
		return nil, nil, err
	}
	defer clear(private)
	pair, err := tls.X509KeyPair(certificate, private)
	if err != nil {
		return nil, nil, err
	}
	if pair.Leaf == nil {
		pair.Leaf, err = x509.ParseCertificate(pair.Certificate[0])
		if err != nil {
			return nil, nil, err
		}
	}
	origin, err := url.Parse(cfg.GetOrigin())
	if err != nil {
		return nil, nil, err
	}
	now := time.Now()
	if origin.Scheme != "https" || origin.Hostname() == "" || origin.User != nil || origin.RawQuery != "" || origin.Fragment != "" || (origin.Path != "" && origin.Path != "/") || now.Before(pair.Leaf.NotBefore) || !now.Before(pair.Leaf.NotAfter) || !pki.PermitsUsage(pair.Leaf, x509.ExtKeyUsageServerAuth) {
		return nil, nil, errors.New("invalid connectivity probe TLS server identity")
	}
	if err := pair.Leaf.VerifyHostname(origin.Hostname()); err != nil {
		return nil, nil, err
	}
	caPEM, err := readProbeCredential(cfg.GetDeviceCaFile(), false)
	if err != nil {
		return nil, nil, err
	}
	roots := x509.NewCertPool()
	count := 0
	for len(bytes.TrimSpace(caPEM)) != 0 {
		block, rest := pem.Decode(caPEM)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return nil, nil, errors.New("invalid connectivity probe device CA PEM")
		}
		ca, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, nil, err
		}
		if !ca.IsCA || !ca.BasicConstraintsValid || ca.KeyUsage&x509.KeyUsageCertSign == 0 || !pki.PermitsUsage(ca, x509.ExtKeyUsageClientAuth) {
			return nil, nil, errors.New("connectivity probe CA does not authorize device TLS")
		}
		roots.AddCert(ca)
		count++
		if count > 16 {
			return nil, nil, errors.New("connectivity probe CA chain exceeds bound")
		}
		caPEM = rest
	}
	if count == 0 {
		return nil, nil, errors.New("missing connectivity probe device CA")
	}
	proof, err := readProbeCredential(cfg.GetProofKeyFile(), true)
	if err != nil {
		return nil, nil, err
	}
	defer clear(proof)
	block, rest := pem.Decode(proof)
	if block == nil || block.Type != "PRIVATE KEY" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, nil, errors.New("connectivity probe proof key must be one PKCS8 PEM")
	}
	defer clear(block.Bytes)
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, nil, err
	}
	key, ok := parsed.(ed25519.PrivateKey)
	if !ok || len(key) != ed25519.PrivateKeySize {
		return nil, nil, errors.New("connectivity probe proof key must be Ed25519")
	}
	return &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, Certificates: []tls.Certificate{pair}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots, SessionTicketsDisabled: true, NextProtos: []string{"http/1.1"}}, key, nil
}
func readProbeCredential(path string, secret bool) (data []byte, err error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("connectivity probe credential path is not resolved")
	}
	fd, err := openConfig(path, true)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "connectivity-probe-credential")
	defer func() { err = errors.Join(err, file.Close()) }()
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return nil, err
	}
	if stat.Uid != 0 || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 || stat.Mode&0022 != 0 || (secret && stat.Mode&0077 != 0) || stat.Size > 65536 {
		return nil, errors.New("unsafe connectivity probe credential custody")
	}
	data, err = io.ReadAll(io.LimitReader(file, 65537))
	if err != nil {
		return nil, err
	}
	if len(data) == 0 || len(data) > 65536 {
		clear(data)
		return nil, errors.New("invalid connectivity probe credential size")
	}
	return data, nil
}
