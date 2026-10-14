// SPDX-License-Identifier: Apache-2.0

// Package transport runs the unprivileged agent network process. Identity keys,
// signing authority, session epochs and rotation intent stay in the executor.
package transport

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net"
	"net/http"
	"net/url"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/gen/lindm/agent/v1/agentv1connect"
	"lindm/gen/lindm/device/v1/devicev1connect"
	"lindm/gen/lindm/enrollment/v1/enrollmentv1connect"
	"lindm/internal/agent/localrpc"
	"lindm/internal/pki"
	"lindm/internal/trust"
)

const requestTimeout = 15 * time.Second

type connections struct {
	device          devicev1connect.DeviceServiceClient
	enrollment      enrollmentv1connect.EnrollmentServiceClient
	deviceTransport *http.Transport
	publicTransport *http.Transport
}

func connectServers(executor agentv1connect.ExecutorServiceClient, connection *agentv1.GetConnectionResponse) (*connections, error) {
	if connection == nil {
		return nil, errors.New("missing executor connection state")
	}
	if err := checkOrigin(connection.GetEnrollmentOrigin()); err != nil {
		return nil, err
	}
	if err := checkOrigin(connection.GetDeviceOrigin()); err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	if len(connection.GetTransportCaPem()) == 0 || len(connection.GetTransportCaPem()) > 65536 || !roots.AppendCertsFromPEM(connection.GetTransportCaPem()) {
		return nil, errors.New("invalid pinned transport trust")
	}
	publicTransport := newHTTPTransport(&tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13})
	result := &connections{publicTransport: publicTransport}
	result.enrollment = enrollmentv1connect.NewEnrollmentServiceClient(newHTTPClient(publicTransport), connection.GetEnrollmentOrigin(), connect.WithReadMaxBytes(1<<20))
	if len(connection.GetCertificatePem()) == 0 {
		return result, nil
	}
	leaf, err := connectionCertificate(connection)
	if err != nil {
		result.Close()
		return nil, err
	}
	result.deviceTransport = newHTTPTransport(&tls.Config{
		RootCAs: roots, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		GetClientCertificate: func(handshake *tls.CertificateRequestInfo) (*tls.Certificate, error) {
			signer, err := localrpc.NewTLSSigner(handshake.Context(), executor, leaf)
			if err != nil {
				return nil, err
			}
			return &tls.Certificate{Certificate: [][]byte{leaf.Raw}, Leaf: leaf, PrivateKey: signer}, nil
		},
	})
	result.device = devicev1connect.NewDeviceServiceClient(newHTTPClient(result.deviceTransport), connection.GetDeviceOrigin(), connect.WithReadMaxBytes(1<<20))
	return result, nil
}

func newHTTPTransport(tlsConfig *tls.Config) *http.Transport {
	return &http.Transport{
		TLSClientConfig:   tlsConfig,
		DialContext:       (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2: true, MaxConnsPerHost: 2, MaxIdleConns: 2, MaxIdleConnsPerHost: 2,
		IdleConnTimeout: time.Minute, TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: requestTimeout,
	}
}

func newHTTPClient(transport *http.Transport) *http.Client {
	return &http.Client{Transport: transport, Timeout: requestTimeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func checkOrigin(raw string) error {
	origin, err := url.Parse(raw)
	if err != nil || origin.Scheme != "https" || origin.Host == "" || origin.User != nil || origin.RawQuery != "" || origin.Fragment != "" || (origin.Path != "" && origin.Path != "/") {
		return errors.New("executor supplied an invalid HTTPS origin")
	}
	return nil
}

func connectionCertificate(connection *agentv1.GetConnectionResponse) (*x509.Certificate, error) {
	if connection.GetCredentialKind() != agentv1.TLSCredentialKind_TLS_CREDENTIAL_KIND_ED25519 || len(connection.GetCertificatePem()) > 16384 {
		return nil, errors.New("executor did not supply an eligible Ed25519 credential")
	}
	block, rest := pem.Decode(connection.GetCertificatePem())
	if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("executor returned an invalid device certificate")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, errors.New("executor returned an invalid device certificate")
	}
	deployment, err := uuid.Parse(connection.GetDeploymentId())
	if err != nil {
		return nil, errors.New("invalid executor deployment identity")
	}
	device, err := uuid.Parse(connection.GetDeviceId())
	if err != nil {
		return nil, errors.New("invalid executor device identity")
	}
	generation, err := uuid.Parse(connection.GetEnrollmentGeneration())
	if err != nil {
		return nil, errors.New("invalid executor enrollment generation")
	}
	if err := pki.CheckDeviceCertificate(leaf, deployment, device, generation); err != nil {
		return nil, err
	}
	fingerprint := sha256.Sum256(leaf.Raw)
	if !bytes.Equal(fingerprint[:], connection.GetCertificateSha256()) {
		return nil, errors.New("executor certificate fingerprint mismatch")
	}
	public, ok := leaf.PublicKey.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("executor device key is not Ed25519")
	}
	keyID, err := trust.KeyID(public)
	if err != nil || keyID != connection.GetKeyId() {
		return nil, errors.New("executor device key identifier mismatch")
	}
	return leaf, nil
}

func (c *connections) Close() {
	if c.deviceTransport != nil {
		c.deviceTransport.CloseIdleConnections()
	}
	if c.publicTransport != nil {
		c.publicTransport.CloseIdleConnections()
	}
}
